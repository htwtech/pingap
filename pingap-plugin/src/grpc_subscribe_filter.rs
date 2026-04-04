// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{Error, get_hash_key, get_plugin_factory};
use async_trait::async_trait;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult, get_client_ip,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use toml::Value;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

// gRPC Subscribe path for Yellowstone/Geyser
const SUBSCRIBE_PATH: &str = "/geyser.Geyser/Subscribe";
const DEFAULT_RELOAD_SECS: u64 = 30;

// ──────────────────────────────────────────────────────────────
// TOML sub-table helpers
// ──────────────────────────────────────────────────────────────

type TomlTable = toml::map::Map<String, Value>;

fn get_sub_table<'a>(conf: &'a TomlTable, key: &str) -> Option<&'a TomlTable> {
    conf.get(key).and_then(|v| v.as_table())
}

fn sub_int(table: Option<&TomlTable>, key: &str, default: i64) -> i64 {
    table
        .and_then(|t| t.get(key))
        .and_then(|v| v.as_integer())
        .unwrap_or(default)
}

fn sub_bool(table: Option<&TomlTable>, key: &str, default: bool) -> bool {
    table
        .and_then(|t| t.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

fn sub_str_slice(table: Option<&TomlTable>, key: &str) -> HashSet<String> {
    table
        .and_then(|t| t.get(key))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

// ──────────────────────────────────────────────────────────────
// Filter rules (per-IP or default)
// ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AccountsLimits {
    account_max: i64,
    owner_max: i64,
    data_slice_max: i64,
    account_reject: HashSet<String>,
    owner_reject: HashSet<String>,
}

#[derive(Debug, Clone)]
struct TransactionsLimits {
    account_include_max: i64,
    account_exclude_max: i64,
    account_required_max: i64,
    account_include_reject: HashSet<String>,
}

#[derive(Debug, Clone)]
struct BlocksLimits {
    account_include_max: i64,
    include_accounts: bool,
    include_entries: bool,
    include_transactions: bool,
    account_include_reject: HashSet<String>,
}

/// A complete set of filter rules for one client (or default)
#[derive(Debug, Clone)]
struct FilterRules {
    accounts: AccountsLimits,
    transactions: TransactionsLimits,
    blocks: BlocksLimits,
    transactions_status: TransactionsLimits,
}

impl FilterRules {
    fn from_toml(conf: &TomlTable) -> Self {
        let acc = get_sub_table(conf, "accounts");
        let tx = get_sub_table(conf, "transactions");
        let blk = get_sub_table(conf, "blocks");
        let tx_st = get_sub_table(conf, "transactions_status");

        Self {
            accounts: AccountsLimits {
                account_max: sub_int(acc, "account_max", 100),
                owner_max: sub_int(acc, "owner_max", 20),
                data_slice_max: sub_int(acc, "data_slice_max", 2),
                account_reject: sub_str_slice(acc, "account_reject"),
                owner_reject: sub_str_slice(acc, "owner_reject"),
            },
            transactions: TransactionsLimits {
                account_include_max: sub_int(tx, "account_include_max", 100),
                account_exclude_max: sub_int(tx, "account_exclude_max", 100),
                account_required_max: sub_int(tx, "account_required_max", 100),
                account_include_reject: sub_str_slice(tx, "account_include_reject"),
            },
            blocks: BlocksLimits {
                account_include_max: sub_int(blk, "account_include_max", 20),
                include_accounts: sub_bool(blk, "include_accounts", false),
                include_entries: sub_bool(blk, "include_entries", false),
                include_transactions: sub_bool(blk, "include_transactions", true),
                account_include_reject: sub_str_slice(blk, "account_include_reject"),
            },
            transactions_status: TransactionsLimits {
                account_include_max: sub_int(tx_st, "account_include_max", 20),
                account_exclude_max: sub_int(tx_st, "account_exclude_max", 20),
                account_required_max: sub_int(tx_st, "account_required_max", 20),
                account_include_reject: sub_str_slice(tx_st, "account_include_reject"),
            },
        }
    }

    fn defaults() -> Self {
        let empty = TomlTable::new();
        Self::from_toml(&empty)
    }
}

// ──────────────────────────────────────────────────────────────
// Per-IP rules loader
// ──────────────────────────────────────────────────────────────

/// Load all .toml files from a directory into a HashMap<IP, FilterRules>
fn load_rules_from_dir(
    dir: &std::path::Path,
) -> std::result::Result<(FilterRules, HashMap<String, FilterRules>), String> {
    let mut ip_rules = HashMap::new();
    let mut default_rules = None;

    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read rules_dir {}: {e}", dir.display()))?;

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        let content = std::fs::read_to_string(&path).map_err(|e| {
            format!("failed to read {}: {e}", path.display())
        })?;

        let table: TomlTable = toml::from_str(&content).map_err(|e| {
            format!("failed to parse {}: {e}", path.display())
        })?;

        let rules = FilterRules::from_toml(&table);

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        if stem == "default" {
            default_rules = Some(rules);
        } else {
            ip_rules.insert(stem, rules);
        }
    }

    let default = default_rules.unwrap_or_else(FilterRules::defaults);
    Ok((default, ip_rules))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ──────────────────────────────────────────────────────────────
// Plugin struct
// ──────────────────────────────────────────────────────────────

pub struct GrpcSubscribeFilter {
    hash_value: String,
    /// Default rules (used when no per-IP match)
    default_rules: RwLock<FilterRules>,
    /// Per-IP rules: IP string -> FilterRules
    ip_rules: RwLock<HashMap<String, FilterRules>>,
    /// Directory containing per-IP .toml files
    rules_dir: Option<PathBuf>,
    /// How often to reload rules from disk
    reload_interval: Duration,
    /// Timestamp of last reload (unix seconds)
    last_reload: AtomicU64,
}

impl GrpcSubscribeFilter {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new grpc_subscribe_filter plugin");
        Self::try_from(params)
    }

    /// Reload rules from disk if enough time has passed
    fn maybe_reload(&self) {
        let Some(dir) = &self.rules_dir else {
            return;
        };

        let now = now_secs();
        let last = self.last_reload.load(Ordering::Relaxed);
        if now.saturating_sub(last) < self.reload_interval.as_secs() {
            return;
        }

        // Try to be the one thread that reloads
        if self
            .last_reload
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread is already reloading
        }

        match load_rules_from_dir(dir) {
            Ok((default, ip_map)) => {
                if let Ok(mut d) = self.default_rules.write() {
                    *d = default;
                }
                if let Ok(mut m) = self.ip_rules.write() {
                    *m = ip_map;
                }
                debug!(
                    dir = dir.to_str().unwrap_or(""),
                    "reloaded grpc filter rules"
                );
            },
            Err(e) => {
                tracing::error!(error = e.as_str(), "failed to reload grpc filter rules");
            },
        }
    }

    /// Get the rules for a specific client IP
    fn get_rules_for_ip(&self, ip: &str) -> FilterRules {
        if let Ok(map) = self.ip_rules.read() {
            if let Some(rules) = map.get(ip) {
                return rules.clone();
            }
        }
        if let Ok(d) = self.default_rules.read() {
            return d.clone();
        }
        FilterRules::defaults()
    }
}

impl TryFrom<&PluginConf> for GrpcSubscribeFilter {
    type Error = Error;
    fn try_from(conf: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(conf);

        let rules_dir_str = conf
            .get("rules_dir")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let reload_secs = conf
            .get("reload_interval")
            .and_then(|v| v.as_str())
            .and_then(|s| humantime::parse_duration(s).ok())
            .unwrap_or(Duration::from_secs(DEFAULT_RELOAD_SECS));

        let (default_rules, ip_rules, rules_dir) = if !rules_dir_str.is_empty() {
            let dir = PathBuf::from(rules_dir_str);
            match load_rules_from_dir(&dir) {
                Ok((default, ip_map)) => {
                    debug!(
                        dir = rules_dir_str,
                        count = ip_map.len(),
                        "loaded per-IP grpc filter rules"
                    );
                    (default, ip_map, Some(dir))
                },
                Err(e) => {
                    tracing::error!(
                        error = e.as_str(),
                        "failed to load rules_dir, using inline/defaults"
                    );
                    (FilterRules::from_toml(conf), HashMap::new(), None)
                },
            }
        } else {
            // No rules_dir — use inline config (backward compatible)
            (FilterRules::from_toml(conf), HashMap::new(), None)
        };

        Ok(Self {
            hash_value,
            default_rules: RwLock::new(default_rules),
            ip_rules: RwLock::new(ip_rules),
            rules_dir,
            reload_interval: reload_secs,
            last_reload: AtomicU64::new(now_secs()),
        })
    }
}

// ──────────────────────────────────────────────────────────────
// Minimal protobuf wire format parser
// ──────────────────────────────────────────────────────────────

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 70 {
            return None;
        }
        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None
}

fn skip_field(wire_type: u8, buf: &[u8]) -> Option<usize> {
    match wire_type {
        0 => read_varint(buf).map(|(_, n)| n),
        1 => (buf.len() >= 8).then_some(8),
        2 => {
            let (len, n) = read_varint(buf)?;
            let total = n + len as usize;
            (buf.len() >= total).then_some(total)
        },
        5 => (buf.len() >= 4).then_some(4),
        _ => None,
    }
}

fn extract_len_fields(buf: &[u8], target_field: u32) -> Vec<&[u8]> {
    let mut results = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let Some((tag, tag_len)) = read_varint(&buf[pos..]) else {
            break;
        };
        pos += tag_len;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == target_field && wire_type == 2 {
            let Some((len, len_bytes)) = read_varint(&buf[pos..]) else {
                break;
            };
            pos += len_bytes;
            let end = pos + len as usize;
            if end > buf.len() {
                break;
            }
            results.push(&buf[pos..end]);
            pos = end;
        } else {
            let Some(skip) = skip_field(wire_type, &buf[pos..]) else {
                break;
            };
            pos += skip;
        }
    }
    results
}

fn count_repeated_strings(buf: &[u8], target_field: u32) -> Vec<String> {
    extract_len_fields(buf, target_field)
        .into_iter()
        .filter_map(|b| std::str::from_utf8(b).ok().map(String::from))
        .collect()
}

fn extract_map_values(buf: &[u8], map_field: u32) -> Vec<Vec<u8>> {
    extract_len_fields(buf, map_field)
        .into_iter()
        .filter_map(|entry| {
            extract_len_fields(entry, 2)
                .into_iter()
                .next()
                .map(|v| v.to_vec())
        })
        .collect()
}

fn has_rejected(strings: &[String], reject: &HashSet<String>) -> Option<String> {
    strings.iter().find(|s| reject.contains(s.as_str())).cloned()
}

fn read_bool_field(buf: &[u8], target_field: u32) -> Option<bool> {
    let mut pos = 0;
    while pos < buf.len() {
        let Some((tag, tag_len)) = read_varint(&buf[pos..]) else {
            break;
        };
        pos += tag_len;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == target_field && wire_type == 0 {
            return read_varint(&buf[pos..]).map(|(val, _)| val != 0);
        }
        let Some(skip) = skip_field(wire_type, &buf[pos..]) else {
            break;
        };
        pos += skip;
    }
    None
}

// ──────────────────────────────────────────────────────────────
// Validation logic (operates on FilterRules)
// ──────────────────────────────────────────────────────────────

fn validate_subscribe_request(
    rules: &FilterRules,
    proto_buf: &[u8],
) -> std::result::Result<(), String> {
    validate_accounts(rules, proto_buf)?;
    validate_tx_filters(proto_buf, 3, &rules.transactions, "transactions")?;
    validate_blocks(rules, proto_buf)?;
    validate_tx_filters(proto_buf, 10, &rules.transactions_status, "transactions_status")?;
    validate_data_slices(rules, proto_buf)?;
    Ok(())
}

fn validate_accounts(rules: &FilterRules, proto_buf: &[u8]) -> std::result::Result<(), String> {
    for filter_buf in &extract_map_values(proto_buf, 1) {
        let accounts = count_repeated_strings(filter_buf, 2);
        if accounts.len() as i64 > rules.accounts.account_max {
            return Err(format!(
                "accounts filter: too many accounts ({} > {})",
                accounts.len(),
                rules.accounts.account_max
            ));
        }
        if let Some(rejected) = has_rejected(&accounts, &rules.accounts.account_reject) {
            return Err(format!("accounts filter: account {rejected} is not allowed"));
        }

        let owners = count_repeated_strings(filter_buf, 3);
        if owners.len() as i64 > rules.accounts.owner_max {
            return Err(format!(
                "accounts filter: too many owners ({} > {})",
                owners.len(),
                rules.accounts.owner_max
            ));
        }
        if let Some(rejected) = has_rejected(&owners, &rules.accounts.owner_reject) {
            return Err(format!("accounts filter: owner {rejected} is not allowed"));
        }
    }
    Ok(())
}

fn validate_tx_filters(
    proto_buf: &[u8],
    map_field: u32,
    limits: &TransactionsLimits,
    label: &str,
) -> std::result::Result<(), String> {
    for filter_buf in &extract_map_values(proto_buf, map_field) {
        let includes = count_repeated_strings(filter_buf, 3);
        if includes.len() as i64 > limits.account_include_max {
            return Err(format!(
                "{label} filter: too many account_include ({} > {})",
                includes.len(),
                limits.account_include_max
            ));
        }
        if let Some(rejected) = has_rejected(&includes, &limits.account_include_reject) {
            return Err(format!(
                "{label} filter: account {rejected} is not allowed in account_include"
            ));
        }

        let excludes = count_repeated_strings(filter_buf, 4);
        if excludes.len() as i64 > limits.account_exclude_max {
            return Err(format!(
                "{label} filter: too many account_exclude ({} > {})",
                excludes.len(),
                limits.account_exclude_max
            ));
        }

        let required = count_repeated_strings(filter_buf, 6);
        if required.len() as i64 > limits.account_required_max {
            return Err(format!(
                "{label} filter: too many account_required ({} > {})",
                required.len(),
                limits.account_required_max
            ));
        }
    }
    Ok(())
}

fn validate_blocks(rules: &FilterRules, proto_buf: &[u8]) -> std::result::Result<(), String> {
    for filter_buf in &extract_map_values(proto_buf, 4) {
        let includes = count_repeated_strings(filter_buf, 1);
        if includes.len() as i64 > rules.blocks.account_include_max {
            return Err(format!(
                "blocks filter: too many account_include ({} > {})",
                includes.len(),
                rules.blocks.account_include_max
            ));
        }
        if let Some(rejected) = has_rejected(&includes, &rules.blocks.account_include_reject) {
            return Err(format!(
                "blocks filter: account {rejected} is not allowed in account_include"
            ));
        }
        if let Some(true) = read_bool_field(filter_buf, 2) {
            if !rules.blocks.include_transactions {
                return Err("blocks filter: include_transactions is not allowed".to_string());
            }
        }
        if let Some(true) = read_bool_field(filter_buf, 3) {
            if !rules.blocks.include_accounts {
                return Err("blocks filter: include_accounts is not allowed".to_string());
            }
        }
        if let Some(true) = read_bool_field(filter_buf, 4) {
            if !rules.blocks.include_entries {
                return Err("blocks filter: include_entries is not allowed".to_string());
            }
        }
    }
    Ok(())
}

fn validate_data_slices(rules: &FilterRules, proto_buf: &[u8]) -> std::result::Result<(), String> {
    let slices = extract_len_fields(proto_buf, 7);
    if slices.len() as i64 > rules.accounts.data_slice_max {
        return Err(format!(
            "accounts_data_slice: too many slices ({} > {})",
            slices.len(),
            rules.accounts.data_slice_max
        ));
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────
// Plugin trait implementation
// ──────────────────────────────────────────────────────────────

#[async_trait]
impl Plugin for GrpcSubscribeFilter {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }

        let path = session.req_header().uri.path();
        if path == SUBSCRIBE_PATH {
            // Ensure client IP is resolved, then copy it for add_variable
            let ip = ctx
                .conn
                .client_ip
                .get_or_insert_with(|| get_client_ip(session))
                .clone();
            ctx.add_variable("grpc_subscribe_ip", &ip);
        }

        Ok(RequestPluginResult::Continue)
    }

    #[inline]
    fn handle_request_body(
        &self,
        _session: &mut Session,
        ctx: &mut Ctx,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
    ) -> pingora::Result<Option<HttpResponse>> {
        // Check if this is a Subscribe request and get the client IP
        let client_ip = ctx
            .features
            .as_ref()
            .and_then(|f| f.variables.as_ref())
            .and_then(|v| v.get("grpc_subscribe_ip"))
            .cloned();

        let Some(ip) = client_ip else {
            return Ok(None);
        };

        let Some(buf) = body else {
            return Ok(None);
        };

        // gRPC frame: 1 byte compressed + 4 bytes length + protobuf
        if buf.len() < 5 {
            return Ok(None);
        }

        // Lazy reload per-IP rules from disk
        self.maybe_reload();

        let rules = self.get_rules_for_ip(&ip);
        let proto_buf = &buf[5..];

        match validate_subscribe_request(&rules, proto_buf) {
            Ok(()) => Ok(None),
            Err(msg) => {
                tracing::warn!(
                    client_ip = ip.as_str(),
                    error = msg.as_str(),
                    "grpc subscribe filter rejected request"
                );
                Ok(Some(HttpResponse {
                    status: StatusCode::BAD_REQUEST,
                    body: msg.into(),
                    ..Default::default()
                }))
            },
        }
    }
}

#[ctor]
fn init() {
    get_plugin_factory().register("grpc_subscribe_filter", |params| {
        Ok(Arc::new(GrpcSubscribeFilter::new(params)?))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pretty_assertions::assert_eq;

    fn default_conf() -> PluginConf {
        toml::from_str::<PluginConf>(
            r#"
[accounts]
account_max = 40
owner_max = 200
data_slice_max = 3
account_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
owner_reject = ["11111111111111111111111111111111"]

[transactions]
account_include_max = 30
account_exclude_max = 20
account_required_max = 40
account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]

[blocks]
account_include_max = 500
include_accounts = false
include_entries = false
include_transactions = true
account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]

[transactions_status]
account_include_max = 200
account_exclude_max = 20
account_required_max = 200
account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
"#,
        )
        .expect("valid toml")
    }

    #[test]
    fn test_config_nested() {
        let filter =
            GrpcSubscribeFilter::try_from(&default_conf()).expect("should parse");
        let rules = filter.get_rules_for_ip("any");
        assert_eq!(40, rules.accounts.account_max);
        assert_eq!(200, rules.accounts.owner_max);
        assert_eq!(3, rules.accounts.data_slice_max);
        assert_eq!(30, rules.transactions.account_include_max);
        assert_eq!(20, rules.transactions.account_exclude_max);
        assert_eq!(40, rules.transactions.account_required_max);
        assert_eq!(500, rules.blocks.account_include_max);
        assert_eq!(false, rules.blocks.include_accounts);
        assert_eq!(true, rules.blocks.include_transactions);
        assert_eq!(200, rules.transactions_status.account_include_max);
        assert_eq!(20, rules.transactions_status.account_exclude_max);
    }

    #[test]
    fn test_config_defaults_when_empty() {
        let conf = toml::from_str::<PluginConf>("").expect("valid toml");
        let filter = GrpcSubscribeFilter::try_from(&conf).expect("should parse");
        let rules = filter.get_rules_for_ip("any");
        assert_eq!(100, rules.accounts.account_max);
        assert_eq!(20, rules.accounts.owner_max);
        assert_eq!(2, rules.accounts.data_slice_max);
        assert_eq!(100, rules.transactions.account_include_max);
        assert_eq!(20, rules.blocks.account_include_max);
        assert_eq!(20, rules.transactions_status.account_include_max);
    }

    #[test]
    fn test_per_ip_rules_from_dir() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Write default rules
        std::fs::write(
            dir.path().join("default.toml"),
            r#"
[accounts]
account_max = 50
"#,
        )
        .expect("write");

        // Write per-IP rules
        std::fs::write(
            dir.path().join("10.0.0.1.toml"),
            r#"
[accounts]
account_max = 10
"#,
        )
        .expect("write");

        let (default, ip_map) = load_rules_from_dir(dir.path()).expect("load");
        assert_eq!(50, default.accounts.account_max);
        assert_eq!(1, ip_map.len());
        assert_eq!(10, ip_map["10.0.0.1"].accounts.account_max);
    }

    #[test]
    fn test_plugin_with_rules_dir() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(
            dir.path().join("default.toml"),
            r#"
[accounts]
account_max = 100
account_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
"#,
        )
        .expect("write");

        std::fs::write(
            dir.path().join("192.168.1.5.toml"),
            r#"
[accounts]
account_max = 25
"#,
        )
        .expect("write");

        let conf_str = format!(
            r#"rules_dir = "{}""#,
            dir.path().to_str().expect("path").replace('\\', "/")
        );
        let conf = toml::from_str::<PluginConf>(&conf_str).expect("valid toml");
        let filter = GrpcSubscribeFilter::try_from(&conf).expect("should parse");

        // IP with specific rules
        let rules = filter.get_rules_for_ip("192.168.1.5");
        assert_eq!(25, rules.accounts.account_max);

        // IP without specific rules → default
        let rules = filter.get_rules_for_ip("10.0.0.99");
        assert_eq!(100, rules.accounts.account_max);
    }

    #[test]
    fn test_varint() {
        assert_eq!(Some((1, 1)), read_varint(&[0x01]));
        assert_eq!(Some((300, 2)), read_varint(&[0xAC, 0x02]));
        assert_eq!(None, read_varint(&[]));
    }

    fn encode_string(field_num: u32, value: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        let tag = (field_num << 3) | 2;
        encode_varint(&mut buf, tag as u64);
        encode_varint(&mut buf, value.len() as u64);
        buf.extend_from_slice(value.as_bytes());
        buf
    }

    fn encode_len_field(field_num: u32, inner: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let tag = (field_num << 3) | 2;
        encode_varint(&mut buf, tag as u64);
        encode_varint(&mut buf, inner.len() as u64);
        buf.extend_from_slice(inner);
        buf
    }

    fn encode_varint(buf: &mut Vec<u8>, mut val: u64) {
        loop {
            let byte = (val & 0x7F) as u8;
            val >>= 7;
            if val == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
        }
    }

    fn encode_map_entry(key: &str, value_bytes: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend(encode_string(1, key));
        entry.extend(encode_len_field(2, value_bytes));
        entry
    }

    #[test]
    fn test_validate_accounts_within_limits() {
        let rules = FilterRules::from_toml(&default_conf());

        let mut filter_accounts = Vec::new();
        filter_accounts.extend(encode_string(2, "Acct1111111111111111111111111111111111111111"));
        filter_accounts.extend(encode_string(2, "Acct2222222222222222222222222222222222222222"));
        filter_accounts.extend(encode_string(3, "Owner111111111111111111111111111111111111111"));

        let map_entry = encode_map_entry("sub1", &filter_accounts);
        let subscribe_req = encode_len_field(1, &map_entry);

        assert!(validate_subscribe_request(&rules, &subscribe_req).is_ok());
    }

    #[test]
    fn test_validate_accounts_rejected() {
        let rules = FilterRules::from_toml(&default_conf());

        let mut filter_accounts = Vec::new();
        filter_accounts.extend(encode_string(
            2,
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ));

        let map_entry = encode_map_entry("sub1", &filter_accounts);
        let subscribe_req = encode_len_field(1, &map_entry);

        let result = validate_subscribe_request(&rules, &subscribe_req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));
    }

    #[test]
    fn test_validate_data_slices_exceeded() {
        let conf = toml::from_str::<PluginConf>(
            r#"
[accounts]
data_slice_max = 1
"#,
        )
        .expect("valid toml");
        let rules = FilterRules::from_toml(&conf);

        let slice1 = encode_len_field(7, &[0x08, 0x00, 0x10, 0x64]);
        let slice2 = encode_len_field(7, &[0x08, 0x64, 0x10, 0x64]);
        let mut subscribe_req = Vec::new();
        subscribe_req.extend(slice1);
        subscribe_req.extend(slice2);

        let result = validate_subscribe_request(&rules, &subscribe_req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many slices"));
    }

    #[test]
    fn test_empty_request_passes() {
        let rules = FilterRules::defaults();
        assert!(validate_subscribe_request(&rules, &[]).is_ok());
    }
}
