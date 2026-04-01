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

use super::{Error, get_hash_key, get_plugin_factory, get_str_conf};
use async_trait::async_trait;
use ctor::ctor;
use pingap_config::PluginConf;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

/// QueryRewrite plugin replaces the value of a query parameter in the request URL.
///
/// Use case: client sends `?api-key=CLIENT_KEY`, after auth validation
/// this plugin rewrites it to `?api-key=UPSTREAM_KEY` before forwarding to upstream.
pub struct QueryRewrite {
    plugin_step: PluginStep,
    /// Query parameter name to rewrite (e.g., "api-key")
    name: String,
    /// New value to set (e.g., "upstream-secret-key")
    value: String,
    hash_value: String,
}

impl TryFrom<&PluginConf> for QueryRewrite {
    type Error = Error;
    fn try_from(conf: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(conf);
        let name = get_str_conf(conf, "name");
        let value = get_str_conf(conf, "value");

        if name.is_empty() {
            return Err(Error::Invalid {
                category: "query_rewrite".to_string(),
                message: "query parameter name can't be empty".to_string(),
            });
        }
        if value.is_empty() {
            return Err(Error::Invalid {
                category: "query_rewrite".to_string(),
                message: "query parameter value can't be empty".to_string(),
            });
        }

        let step = get_str_conf(conf, "step");
        let plugin_step = if step == "proxy_upstream" {
            PluginStep::ProxyUpstream
        } else {
            PluginStep::Request
        };

        Ok(Self {
            plugin_step,
            name,
            value,
            hash_value,
        })
    }
}

impl QueryRewrite {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new query rewrite plugin");
        Self::try_from(params)
    }
}

/// Replaces the value of a specific query parameter in the request URI.
fn replace_query_value(
    header: &mut pingora::http::RequestHeader,
    name: &str,
    new_value: &str,
) -> std::result::Result<(), http::uri::InvalidUri> {
    let Some(query_str) = header.uri.query() else {
        return Ok(());
    };

    let mut new_query = String::with_capacity(query_str.len() + new_value.len());

    for item in query_str.split('&') {
        let key = item.split('=').next().unwrap_or(item);

        if !new_query.is_empty() {
            new_query.push('&');
        }

        if key == name {
            let _ = write!(&mut new_query, "{}={}", name, new_value);
        } else {
            new_query.push_str(item);
        }
    }

    let path = header.uri.path();
    let new_uri_str = if new_query.is_empty() {
        Cow::Borrowed(path)
    } else {
        let mut s = String::with_capacity(path.len() + 1 + new_query.len());
        let _ = write!(&mut s, "{}?{}", path, &new_query);
        Cow::Owned(s)
    };

    let new_uri = http::Uri::from_str(&new_uri_str)?;
    header.set_uri(new_uri);
    Ok(())
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("query_rewrite", |params| {
            Ok(Arc::new(QueryRewrite::new(params)?))
        });
}

#[async_trait]
impl Plugin for QueryRewrite {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }

        if let Err(e) =
            replace_query_value(session.req_header_mut(), &self.name, &self.value)
        {
            tracing::error!(error = e.to_string(), "query rewrite fail");
        }

        Ok(RequestPluginResult::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_core::{Ctx, PluginStep};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_query_rewrite_params() {
        let result = QueryRewrite::try_from(
            &toml::from_str::<PluginConf>(
                r###"
name = ""
value = "new_val"
"###,
            )
            .unwrap(),
        );
        assert!(result.is_err());

        let result = QueryRewrite::try_from(
            &toml::from_str::<PluginConf>(
                r###"
name = "api-key"
value = ""
"###,
            )
            .unwrap(),
        );
        assert!(result.is_err());

        let params = QueryRewrite::try_from(
            &toml::from_str::<PluginConf>(
                r###"
name = "api-key"
value = "upstream-secret"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("api-key", params.name);
        assert_eq!("upstream-secret", params.value);
        assert_eq!("request", params.plugin_step.to_string());
    }

    #[tokio::test]
    async fn test_query_rewrite() {
        let plugin = QueryRewrite::new(
            &toml::from_str::<PluginConf>(
                r###"
name = "api-key"
value = "upstream-secret"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        // Test: rewrite api-key value
        let input_header =
            "GET /path?api-key=client-key&other=1 HTTP/1.1\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!(
            "/path?api-key=upstream-secret&other=1",
            session.req_header().uri.to_string()
        );

        // Test: no matching query param — URI unchanged
        let input_header = "GET /path?other=1 HTTP/1.1\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!("/path?other=1", session.req_header().uri.to_string());

        // Test: no query string — URI unchanged
        let input_header = "GET /path HTTP/1.1\r\n\r\n";
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();

        let result = plugin
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result == RequestPluginResult::Continue);
        assert_eq!("/path", session.req_header().uri.to_string());
    }
}
