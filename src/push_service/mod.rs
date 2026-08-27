use std::{sync::LazyLock, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials, SignalServers},
    prelude::ServiceConfiguration,
    utils::serde_device_id_vec,
    websocket::{SignalWebSocket, WebSocketType},
};

use libsignal_core::DeviceId;
use protobuf::{ProtobufRequestBuilderExt, ProtobufResponseExt};
use reqwest::{Method, RequestBuilder};
use reqwest_websocket::Upgrade;
use serde::{Deserialize, Serialize};
use tracing::{debug_span, Instrument};

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub static DEFAULT_DEVICE_ID: LazyLock<libsignal_core::DeviceId> =
    LazyLock::new(|| libsignal_core::DeviceId::try_from(1).unwrap());

mod account;
mod cdn;
mod error;
pub mod linking;
mod messages;
pub(crate) mod response;

pub use account::*;
pub use cdn::*;
pub use error::*;
pub(crate) use response::{ReqwestExt, SignalServiceResponse};

/// Map a rejected websocket-upgrade handshake to a typed `ServiceError`.
///
/// `into_websocket()` yields `Handshake(UnexpectedStatusCode(status))` on any
/// non-101 response, so we recover the HTTP status the same way
/// `service_error_for_status` does for plain requests. Non-handshake errors
/// (TLS failure, connection refused, …) stay `WsError`.
fn map_ws_handshake_error(e: reqwest_websocket::Error) -> ServiceError {
    use reqwest_websocket::{Error, HandshakeError};
    if let Error::Handshake(HandshakeError::UnexpectedStatusCode(status)) = &e {
        match status.as_u16() {
            401 | 403 => return ServiceError::Unauthorized,
            499 => return ServiceError::AppExpired,
            429 => {
                return ServiceError::RateLimitExceeded { retry_after: None }
            },
            _ => {},
        }
    }
    ServiceError::WsError(Box::new(e))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequired {
    pub token: String,
    pub options: Vec<String>,
}

#[derive(derive_more::Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuth {
    pub username: String,
    #[debug(ignore)]
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum HttpAuthOverride {
    NoOverride,
    Unidentified,
    Identified(HttpAuth),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AvatarWrite<C> {
    NewAvatar(C),
    RetainAvatar,
    NoAvatar,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchedDevices {
    #[serde(with = "serde_device_id_vec")]
    pub missing_devices: Vec<DeviceId>,
    #[serde(with = "serde_device_id_vec")]
    pub extra_devices: Vec<DeviceId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevices {
    #[serde(with = "serde_device_id_vec")]
    pub stale_devices: Vec<DeviceId>,
}

#[derive(Clone)]
pub struct PushService {
    pub(crate) servers: SignalServers,
    cfg: ServiceConfiguration,
    credentials: Option<HttpAuth>,
    client: reqwest::Client,
}

impl PushService {
    pub fn new(
        env: SignalServers,
        credentials: Option<ServiceCredentials>,
        user_agent: impl AsRef<str>,
    ) -> Self {
        let cfg: ServiceConfiguration = env.into();

        // Use the ring provider except if the application already installed one.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }

        let client = reqwest::ClientBuilder::new()
            .tls_certs_only([reqwest::Certificate::from_pem(
                cfg.certificate_authority.as_bytes(),
            )
            .unwrap()])
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(65))
            .user_agent(user_agent.as_ref())
            .http1_only()
            .build()
            .unwrap();

        Self {
            servers: env,
            cfg,
            credentials: credentials.and_then(|c| c.authorization()),
            client,
        }
    }

    #[tracing::instrument(skip(self), fields(endpoint = %endpoint))]
    pub fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        auth_override: HttpAuthOverride,
    ) -> Result<RequestBuilder, ServiceError> {
        let url = endpoint.into_url(&self.cfg)?;
        let mut builder = self.client.request(method, url);

        builder = match auth_override {
            HttpAuthOverride::NoOverride => {
                if let Some(HttpAuth { username, password }) =
                    self.credentials.as_ref()
                {
                    builder.basic_auth(username, Some(password))
                } else {
                    builder
                }
            },
            HttpAuthOverride::Identified(HttpAuth { username, password }) => {
                builder.basic_auth(username, Some(password))
            },
            HttpAuthOverride::Unidentified => builder,
        };

        Ok(builder)
    }

    pub async fn ws<C: WebSocketType>(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&'static str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket<C>, ServiceError> {
        let span = debug_span!("websocket");

        let mut url = Endpoint::service(path).into_url(&self.cfg)?;
        url.set_scheme("wss").expect("valid https base url");

        let mut builder = self.client.get(url);
        for (key, value) in additional_headers {
            builder = builder.header(*key, *value);
        }

        if let Some(credentials) = credentials {
            builder =
                builder.basic_auth(credentials.login(), credentials.password);
        }

        let ws = match builder
            .upgrade()
            .send()
            .await?
            .into_websocket()
            .instrument(span.clone())
            .await
        {
            Ok(ws) => ws,
            // Classify a rejected handshake by status so callers can distinguish
            // an unlink (401/403) / expired build (499) / rate-limit (429) from a
            // generic transport failure — mirrors `service_error_for_status` on
            // the HTTP path, which the websocket-upgrade path otherwise bypasses.
            Err(e) => return Err(map_ws_handshake_error(e)),
        };

        let unidentified_push_service = PushService {
            servers: self.servers,
            cfg: self.cfg.clone(),
            credentials: None,
            client: self.client.clone(),
        };
        let (ws, task) = SignalWebSocket::new(
            ws,
            keepalive_path.to_owned(),
            unidentified_push_service,
        );
        let task = task.instrument(span);
        tokio::task::spawn(task);
        Ok(ws)
    }

    pub(crate) async fn get_group(
        &mut self,
        credentials: HttpAuth,
    ) -> Result<crate::proto::Group, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::storage("/v1/groups/"),
            HttpAuthOverride::Identified(credentials),
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .protobuf()
        .await
    }

    /// Create a group.
    ///
    /// The encrypted `Group` is the complete initial state; the server assigns nothing
    /// beyond validating the member presentations. The response body is deliberately
    /// ignored — its shape differs between the v1 endpoint used here and the `v2/groups`
    /// one Signal-Desktop creates through, and the caller reads the group back rather than
    /// depending on it.
    pub(crate) async fn create_group(
        &mut self,
        credentials: HttpAuth,
        group: crate::proto::Group,
    ) -> Result<(), ServiceError> {
        self.request(
            Method::PUT,
            Endpoint::storage("/v1/groups/"),
            HttpAuthOverride::Identified(credentials),
        )?
        .protobuf(group)
        .send()
        .await?
        .service_error_for_status()
        .await?;
        Ok(())
    }

    /// Apply a change-set to a group.
    ///
    /// `actions.version` must be the group's current revision plus one; anything else
    /// is a [`ServiceError::GroupChangeConflict`]. Leave `source_user_id` and `group_id`
    /// unset — the server fills them in, and rejects a request that sets `group_id`.
    ///
    /// The response is the change as the server signed it, with those two fields
    /// populated so the signature binds to this group. Members receive those bytes
    /// inside a `GroupContextV2` and can apply the change without a fetch.
    pub(crate) async fn patch_group(
        &mut self,
        credentials: HttpAuth,
        actions: crate::proto::group_change::Actions,
    ) -> Result<crate::proto::GroupChange, ServiceError> {
        let response = self
            .request(
                Method::PATCH,
                Endpoint::storage("/v1/groups/"),
                HttpAuthOverride::Identified(credentials),
            )?
            .protobuf(actions)
            .send()
            .await?;

        // Must precede `service_error_for_status`, which maps CONFLICT to
        // MismatchedDevices and would try to parse this protobuf body as JSON.
        if response.status().as_u16() == 409 {
            return Err(ServiceError::GroupChangeConflict);
        }

        response.service_error_for_status().await?.protobuf().await
    }
}

pub(crate) mod protobuf {
    use async_trait::async_trait;
    use prost::Message;
    use reqwest::{header, RequestBuilder, Response};

    use super::ServiceError;

    pub(crate) trait ProtobufRequestBuilderExt
    where
        Self: Sized,
    {
        /// Set the request payload encoded as protobuf.
        /// Sets the `Content-Type` header to `application/x-protobuf`
        fn protobuf<T: Message>(self, value: T) -> Self;
    }

    #[async_trait::async_trait]
    pub(crate) trait ProtobufResponseExt {
        /// Get the response body decoded from Protobuf
        async fn protobuf<T>(self) -> Result<T, ServiceError>
        where
            T: prost::Message + Default;
    }

    impl ProtobufRequestBuilderExt for RequestBuilder {
        fn protobuf<T: Message>(self, value: T) -> Self {
            self.header(header::CONTENT_TYPE, "application/x-protobuf")
                .body(value.encode_to_vec())
        }
    }

    #[async_trait]
    impl ProtobufResponseExt for Response {
        async fn protobuf<T>(self) -> Result<T, ServiceError>
        where
            T: Message + Default,
        {
            let body = self.bytes().await?;
            let decoded = T::decode(body)?;
            Ok(decoded)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::SignalServers;
    use bytes::{Buf, Bytes};

    #[test]
    fn create_clients() {
        let environments = &[SignalServers::Staging, SignalServers::Production];

        for env in environments {
            let _ =
                super::PushService::new(*env, None, "libsignal-service test");
        }
    }

    #[test]
    fn serde_json_from_empty_reader() {
        // This fails, so we have handle empty response body separately in HyperPushService::json()
        let bytes: Bytes = "".into();
        assert!(
            serde_json::from_reader::<bytes::buf::Reader<Bytes>, String>(
                bytes.reader()
            )
            .is_err()
        );
    }

    #[test]
    fn serde_json_form_empty_vec() {
        // If we're trying to send and empty payload, serde_json must be able to make a Vec out of it
        assert!(serde_json::to_vec(b"").is_ok());
    }
}
