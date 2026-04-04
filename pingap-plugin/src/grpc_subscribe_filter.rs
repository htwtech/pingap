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

use super::{
    Error, get_bool_conf, get_hash_key, get_int_conf, get_int_conf_or_default,
    get_plugin_factory, get_str_slice_conf,
};
use async_trait::async_trait;
use ctor::ctor;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

// gRPC Subscribe path for Yellowstone/Geyser
const SUBSCRIBE_PATH: &str = "/geyser.Geyser/Subscribe";

/// Limits for accounts subscription filters
#[derive(Debug, Clone)]
struct AccountsLimits {
    account_max: i64,
    owner_max: i64,
    data_slice_max: i64,
    account_reject: HashSet<String>,
    owner_reject: HashSet<String>,
}

/// Limits for transactions subscription filters
#[derive(Debug, Clone)]
struct TransactionsLimits {
    account_include_max: i64,
    account_exclude_max: i64,
    account_required_max: i64,
    account_include_reject: HashSet<String>,
}

/// Limits for blocks subscription filters
#[derive(Debug, Clone)]
struct BlocksLimits {
    account_include_max: i64,
    include_accounts: bool,
    include_entries: bool,
    include_transactions: bool,
    account_include_reject: HashSet<String>,
}

/// Plugin that validates Yellowstone gRPC SubscribeRequest filters
/// against configured limits.
pub struct GrpcSubscribeFilter {
    hash_value: String,
    accounts: AccountsLimits,
    transactions: TransactionsLimits,
    blocks: BlocksLimits,
    transactions_status: TransactionsLimits,
}

impl GrpcSubscribeFilter {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new grpc_subscribe_filter plugin");
        Self::try_from(params)
    }
}

impl TryFrom<&PluginConf> for GrpcSubscribeFilter {
    type Error = Error;
    fn try_from(conf: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(conf);
        let rps = get_int_conf_or_default(conf, "rps", 100);

        let accounts = AccountsLimits {
            account_max: get_int_conf_or_default(conf, "accounts_account_max", rps),
            owner_max: get_int_conf_or_default(conf, "accounts_owner_max", rps / 5),
            data_slice_max: get_int_conf_or_default(conf, "accounts_data_slice_max", 2),
            account_reject: get_str_slice_conf(conf, "accounts_account_reject")
                .into_iter()
                .collect(),
            owner_reject: get_str_slice_conf(conf, "accounts_owner_reject")
                .into_iter()
                .collect(),
        };

        let transactions = TransactionsLimits {
            account_include_max: get_int_conf_or_default(
                conf,
                "tx_account_include_max",
                rps,
            ),
            account_exclude_max: get_int_conf_or_default(
                conf,
                "tx_account_exclude_max",
                rps,
            ),
            account_required_max: get_int_conf_or_default(
                conf,
                "tx_account_required_max",
                rps,
            ),
            account_include_reject: get_str_slice_conf(
                conf,
                "tx_account_include_reject",
            )
            .into_iter()
            .collect(),
        };

        let blocks = BlocksLimits {
            account_include_max: get_int_conf_or_default(
                conf,
                "blocks_account_include_max",
                rps / 5,
            ),
            include_accounts: get_bool_conf(conf, "blocks_include_accounts"),
            include_entries: get_bool_conf(conf, "blocks_include_entries"),
            include_transactions: conf
                .get("blocks_include_transactions")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            account_include_reject: get_str_slice_conf(
                conf,
                "blocks_account_include_reject",
            )
            .into_iter()
            .collect(),
        };

        let transactions_status = TransactionsLimits {
            account_include_max: get_int_conf_or_default(
                conf,
                "tx_status_account_include_max",
                rps / 5,
            ),
            account_exclude_max: get_int_conf_or_default(
                conf,
                "tx_status_account_exclude_max",
                rps / 5,
            ),
            account_required_max: get_int_conf_or_default(
                conf,
                "tx_status_account_required_max",
                rps / 5,
            ),
            account_include_reject: get_str_slice_conf(
                conf,
                "tx_status_account_include_reject",
            )
            .into_iter()
            .collect(),
        };

        Ok(Self {
            hash_value,
            accounts,
            transactions,
            blocks,
            transactions_status,
        })
    }
}

// ──────────────────────────────────────────────────────────────
// Minimal protobuf wire format parser
// ──────────────────────────────────────────────────────────────

/// Read a varint from buffer, return (value, bytes_consumed)
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

/// Skip a protobuf field based on wire type
fn skip_field(wire_type: u8, buf: &[u8]) -> Option<usize> {
    match wire_type {
        0 => {
            // Varint
            let (_, n) = read_varint(buf)?;
            Some(n)
        },
        1 => {
            // 64-bit
            if buf.len() < 8 {
                return None;
            }
            Some(8)
        },
        2 => {
            // Length-delimited
            let (len, n) = read_varint(buf)?;
            let total = n + len as usize;
            if buf.len() < total {
                return None;
            }
            Some(total)
        },
        5 => {
            // 32-bit
            if buf.len() < 4 {
                return None;
            }
            Some(4)
        },
        _ => None,
    }
}

/// Extract all length-delimited values for a given field number from protobuf bytes
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
            // Length-delimited
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

/// Count repeated string fields with a given field number
fn count_repeated_strings(buf: &[u8], target_field: u32) -> Vec<String> {
    extract_len_fields(buf, target_field)
        .into_iter()
        .filter_map(|b| std::str::from_utf8(b).ok().map(String::from))
        .collect()
}

/// Extract map entries: protobuf map<string, T> is encoded as repeated message
/// with field 1 = key (string) and field 2 = value (message bytes)
fn extract_map_values(buf: &[u8], map_field: u32) -> Vec<Vec<u8>> {
    extract_len_fields(buf, map_field)
        .into_iter()
        .filter_map(|entry| {
            // Each map entry is a message with field 1 = key, field 2 = value
            let values = extract_len_fields(entry, 2);
            values.into_iter().next().map(|v| v.to_vec())
        })
        .collect()
}

/// Check if any string in the list is in the reject set
fn has_rejected(strings: &[String], reject: &HashSet<String>) -> Option<String> {
    strings.iter().find(|s| reject.contains(s.as_str())).cloned()
}

/// Read a bool field (varint with field number)
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
            let Some((val, _)) = read_varint(&buf[pos..]) else {
                break;
            };
            return Some(val != 0);
        }
        let Some(skip) = skip_field(wire_type, &buf[pos..]) else {
            break;
        };
        pos += skip;
    }
    None
}

// ──────────────────────────────────────────────────────────────
// Validation logic
// ──────────────────────────────────────────────────────────────

impl GrpcSubscribeFilter {
    /// Validate the entire SubscribeRequest protobuf
    fn validate_subscribe_request(&self, proto_buf: &[u8]) -> std::result::Result<(), String> {
        self.validate_accounts(proto_buf)?;
        self.validate_transactions(proto_buf)?;
        self.validate_blocks(proto_buf)?;
        self.validate_transactions_status(proto_buf)?;
        self.validate_data_slices(proto_buf)?;
        Ok(())
    }

    /// Validate accounts filters (SubscribeRequest field 1)
    fn validate_accounts(&self, proto_buf: &[u8]) -> std::result::Result<(), String> {
        let filter_values = extract_map_values(proto_buf, 1);
        for filter_buf in &filter_values {
            // field 2 = account (repeated string)
            let accounts = count_repeated_strings(filter_buf, 2);
            if accounts.len() as i64 > self.accounts.account_max {
                return Err(format!(
                    "accounts filter: too many accounts ({} > {})",
                    accounts.len(),
                    self.accounts.account_max
                ));
            }
            if let Some(rejected) = has_rejected(&accounts, &self.accounts.account_reject) {
                return Err(format!(
                    "accounts filter: account {rejected} is not allowed"
                ));
            }

            // field 3 = owner (repeated string)
            let owners = count_repeated_strings(filter_buf, 3);
            if owners.len() as i64 > self.accounts.owner_max {
                return Err(format!(
                    "accounts filter: too many owners ({} > {})",
                    owners.len(),
                    self.accounts.owner_max
                ));
            }
            if let Some(rejected) = has_rejected(&owners, &self.accounts.owner_reject) {
                return Err(format!(
                    "accounts filter: owner {rejected} is not allowed"
                ));
            }
        }
        Ok(())
    }

    /// Validate transactions filters (SubscribeRequest field 3)
    fn validate_transactions(&self, proto_buf: &[u8]) -> std::result::Result<(), String> {
        self.validate_tx_filters(proto_buf, 3, &self.transactions, "transactions")
    }

    /// Validate transactions_status filters (SubscribeRequest field 10)
    fn validate_transactions_status(&self, proto_buf: &[u8]) -> std::result::Result<(), String> {
        self.validate_tx_filters(proto_buf, 10, &self.transactions_status, "transactions_status")
    }

    fn validate_tx_filters(
        &self,
        proto_buf: &[u8],
        map_field: u32,
        limits: &TransactionsLimits,
        label: &str,
    ) -> std::result::Result<(), String> {
        let filter_values = extract_map_values(proto_buf, map_field);
        for filter_buf in &filter_values {
            // field 3 = account_include
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

            // field 4 = account_exclude
            let excludes = count_repeated_strings(filter_buf, 4);
            if excludes.len() as i64 > limits.account_exclude_max {
                return Err(format!(
                    "{label} filter: too many account_exclude ({} > {})",
                    excludes.len(),
                    limits.account_exclude_max
                ));
            }

            // field 6 = account_required (for transactions)
            // field 5 = account_required? No, check proto:
            // SubscribeRequestFilterTransactions: field 6 = account_required
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

    /// Validate blocks filters (SubscribeRequest field 4)
    fn validate_blocks(&self, proto_buf: &[u8]) -> std::result::Result<(), String> {
        let filter_values = extract_map_values(proto_buf, 4);
        for filter_buf in &filter_values {
            // field 1 = account_include (repeated string)
            let includes = count_repeated_strings(filter_buf, 1);
            if includes.len() as i64 > self.blocks.account_include_max {
                return Err(format!(
                    "blocks filter: too many account_include ({} > {})",
                    includes.len(),
                    self.blocks.account_include_max
                ));
            }
            if let Some(rejected) = has_rejected(&includes, &self.blocks.account_include_reject) {
                return Err(format!(
                    "blocks filter: account {rejected} is not allowed in account_include"
                ));
            }

            // field 2 = include_transactions (bool)
            if let Some(true) = read_bool_field(filter_buf, 2) {
                if !self.blocks.include_transactions {
                    return Err(
                        "blocks filter: include_transactions is not allowed".to_string()
                    );
                }
            }

            // field 3 = include_accounts (bool)
            if let Some(true) = read_bool_field(filter_buf, 3) {
                if !self.blocks.include_accounts {
                    return Err(
                        "blocks filter: include_accounts is not allowed".to_string()
                    );
                }
            }

            // field 4 = include_entries (bool)
            if let Some(true) = read_bool_field(filter_buf, 4) {
                if !self.blocks.include_entries {
                    return Err(
                        "blocks filter: include_entries is not allowed".to_string()
                    );
                }
            }
        }
        Ok(())
    }

    /// Validate accounts_data_slice count (SubscribeRequest field 7)
    fn validate_data_slices(&self, proto_buf: &[u8]) -> std::result::Result<(), String> {
        let slices = extract_len_fields(proto_buf, 7);
        if slices.len() as i64 > self.accounts.data_slice_max {
            return Err(format!(
                "accounts_data_slice: too many slices ({} > {})",
                slices.len(),
                self.accounts.data_slice_max
            ));
        }
        Ok(())
    }
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

        // Mark gRPC Subscribe requests in context for body filter
        let path = session.req_header().uri.path();
        if path == SUBSCRIBE_PATH {
            ctx.add_variable("grpc_subscribe", "true");
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
        // Only process gRPC Subscribe requests
        let is_subscribe = ctx
            .features
            .as_ref()
            .and_then(|f| f.variables.as_ref())
            .and_then(|v| v.get("grpc_subscribe"))
            .is_some();

        if !is_subscribe {
            return Ok(None);
        }

        let Some(buf) = body else {
            return Ok(None);
        };

        // gRPC frame: 1 byte compressed + 4 bytes length + protobuf
        if buf.len() < 5 {
            return Ok(None);
        }

        let proto_buf = &buf[5..];

        match self.validate_subscribe_request(proto_buf) {
            Ok(()) => Ok(None),
            Err(msg) => {
                tracing::warn!(
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
rps = 100
accounts_account_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
accounts_owner_reject = ["11111111111111111111111111111111"]
tx_account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
blocks_account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
blocks_include_accounts = false
blocks_include_entries = false
blocks_include_transactions = true
"#,
        )
        .expect("valid toml")
    }

    #[test]
    fn test_config_defaults() {
        let filter =
            GrpcSubscribeFilter::try_from(&default_conf()).expect("should parse");
        assert_eq!(100, filter.accounts.account_max);
        assert_eq!(20, filter.accounts.owner_max);
        assert_eq!(2, filter.accounts.data_slice_max);
        assert_eq!(100, filter.transactions.account_include_max);
        assert_eq!(20, filter.blocks.account_include_max);
        assert_eq!(20, filter.transactions_status.account_include_max);
    }

    #[test]
    fn test_varint() {
        // Single byte varint: 1
        assert_eq!(Some((1, 1)), read_varint(&[0x01]));
        // Multi-byte varint: 300 = 0xAC 0x02
        assert_eq!(Some((300, 2)), read_varint(&[0xAC, 0x02]));
        // Empty
        assert_eq!(None, read_varint(&[]));
    }

    /// Build a protobuf-encoded string field
    fn encode_string(field_num: u32, value: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // tag: (field_num << 3) | 2 (wire type LEN)
        let tag = (field_num << 3) | 2;
        encode_varint(&mut buf, tag as u64);
        encode_varint(&mut buf, value.len() as u64);
        buf.extend_from_slice(value.as_bytes());
        buf
    }

    /// Build a length-delimited field wrapping inner bytes
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

    /// Build a map entry (key=string field1, value=message field2)
    fn encode_map_entry(key: &str, value_bytes: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend(encode_string(1, key));
        entry.extend(encode_len_field(2, value_bytes));
        entry
    }

    #[test]
    fn test_validate_accounts_within_limits() {
        let filter =
            GrpcSubscribeFilter::try_from(&default_conf()).expect("should parse");

        // Build FilterAccounts with 2 accounts, 1 owner
        let mut filter_accounts = Vec::new();
        filter_accounts.extend(encode_string(2, "Acct1111111111111111111111111111111111111111"));
        filter_accounts.extend(encode_string(2, "Acct2222222222222222222222222222222222222222"));
        filter_accounts.extend(encode_string(3, "Owner111111111111111111111111111111111111111"));

        // Build SubscribeRequest with accounts map field 1
        let map_entry = encode_map_entry("sub1", &filter_accounts);
        let subscribe_req = encode_len_field(1, &map_entry);

        assert!(filter.validate_subscribe_request(&subscribe_req).is_ok());
    }

    #[test]
    fn test_validate_accounts_rejected() {
        let filter =
            GrpcSubscribeFilter::try_from(&default_conf()).expect("should parse");

        // Build FilterAccounts with rejected account
        let mut filter_accounts = Vec::new();
        filter_accounts.extend(encode_string(
            2,
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        ));

        let map_entry = encode_map_entry("sub1", &filter_accounts);
        let subscribe_req = encode_len_field(1, &map_entry);

        let result = filter.validate_subscribe_request(&subscribe_req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));
    }

    #[test]
    fn test_validate_data_slices_exceeded() {
        let conf = toml::from_str::<PluginConf>(
            r#"
rps = 100
accounts_data_slice_max = 1
"#,
        )
        .expect("valid toml");
        let filter = GrpcSubscribeFilter::try_from(&conf).expect("should parse");

        // Build 2 data slices (field 7)
        let slice1 = encode_len_field(7, &[0x08, 0x00, 0x10, 0x64]); // offset=0, length=100
        let slice2 = encode_len_field(7, &[0x08, 0x64, 0x10, 0x64]); // offset=100, length=100
        let mut subscribe_req = Vec::new();
        subscribe_req.extend(slice1);
        subscribe_req.extend(slice2);

        let result = filter.validate_subscribe_request(&subscribe_req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many slices"));
    }

    #[test]
    fn test_empty_request_passes() {
        let filter =
            GrpcSubscribeFilter::try_from(&default_conf()).expect("should parse");
        assert!(filter.validate_subscribe_request(&[]).is_ok());
    }
}
