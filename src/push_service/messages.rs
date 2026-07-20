use base64::prelude::*;
use libsignal_protocol::ServiceId;
use reqwest::Method;
use serde::Serialize;
use uuid::Uuid;

use crate::configuration::Endpoint;

use super::{
    response::ReqwestExt, HttpAuthOverride, PushService, ServiceError,
};

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SpamTokenMessage {
    /// Base64 of the envelope's `report_spam_token`. Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

impl PushService {
    /// Report `sender`'s message (identified by `server_guid`) as spam.
    ///
    /// `token` is the message's `report_spam_token` from the envelope, if any.
    /// Authenticates as the reporting account; the server answers 204 on
    /// success, which [`ReqwestExt::service_error_for_status`] treats as `Ok`.
    pub async fn report_spam(
        &self,
        sender: &ServiceId,
        server_guid: Uuid,
        token: Option<Vec<u8>>,
    ) -> Result<(), ServiceError> {
        let path = format!(
            "/v1/messages/report/{}/{}",
            sender.service_id_string(),
            server_guid
        );
        let body = SpamTokenMessage {
            token: token.map(|t| BASE64_STANDARD.encode(t)),
        };
        self.request(
            Method::POST,
            Endpoint::service(path),
            HttpAuthOverride::NoOverride,
        )?
        .json(&body)
        .send()
        .await?
        .service_error_for_status()
        .await?;
        Ok(())
    }
}
