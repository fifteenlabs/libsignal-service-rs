use libsignal_core::DeviceId;
use reqwest::Method;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    configuration::Endpoint, utils::serde_device_id,
    websocket::registration::DeviceActivationRequest,
};

use super::{
    response::ReqwestExt, HttpAuth, HttpAuthOverride, PushService, ServiceError,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkAccountAttributes {
    pub fetches_messages: bool,
    pub name: String,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub capabilities: LinkCapabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
// Keep in sync with https://github.com/signalapp/Signal-Desktop/blob/main/ts/types/Capabilities.d.ts.
pub struct LinkCapabilities {
    pub attachment_backfill: bool,
    /// Sparse Post-Quantum Ratchet (`SPARSE_POST_QUANTUM_RATCHET` on Signal Server).
    ///
    /// Required for all devices; the server returns 409 if a linking device omits this capability
    /// while the account already has it on any existing device.
    pub spqr: bool,
    pub username_change_sync_message: bool,
    /// Signal Backups v2 support. Fifteen always enables this capability.
    pub backup5: bool,
}

// https://github.com/signalapp/Signal-Desktop/blob/1e57db6aa4786dcddc944349e4894333ac2ffc9e/ts/textsecure/WebAPI.ts#L1287
impl Default for LinkCapabilities {
    fn default() -> Self {
        Self {
            attachment_backfill: false,
            spqr: true,
            username_change_sync_message: true,
            backup5: true,
        }
    }
}

/// Result returned by `GET /v1/devices/transfer_archive`.
///
/// Untagged so serde tries `Available` first (matched by presence of both
/// `cdn` and `key`), then falls back to `Error`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TransferArchiveResult {
    Available { cdn: u32, key: String },
    Error { error: TransferArchiveError },
}

#[derive(Debug, Deserialize)]
pub enum TransferArchiveError {
    #[serde(rename = "RELINK_REQUESTED")]
    RelinkRequested,
    #[serde(rename = "CONTINUE_WITHOUT_UPLOAD")]
    ContinueWithoutUpload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkResponse {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    pub pni: Uuid,
    #[serde(with = "serde_device_id")]
    pub device_id: DeviceId,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkRequest {
    pub verification_code: String,
    pub account_attributes: LinkAccountAttributes,
    #[serde(flatten)]
    pub device_activation_request: DeviceActivationRequest,
}

impl PushService {
    pub async fn link_device(
        &mut self,
        link_request: &LinkRequest,
        http_auth: HttpAuth,
    ) -> Result<LinkResponse, ServiceError> {
        self.request(
            Method::PUT,
            Endpoint::service("/v1/devices/link"),
            HttpAuthOverride::Identified(http_auth),
        )?
        .json(&link_request)
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Long-poll the server for a pending transfer archive from the primary device.
    ///
    /// Owns the full retry loop: each request is capped at min(remaining, 5 min),
    /// with a +15 s HTTP timeout leeway. 204 means not ready — keep polling.
    /// Returns an error when `total_timeout` elapses with no archive available.
    pub async fn get_transfer_archive(
        &mut self,
        total_timeout: std::time::Duration,
    ) -> Result<TransferArchiveResult, ServiceError> {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + total_timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ServiceError::Timeout {
                    reason: "timed out waiting for transfer archive",
                });
            }

            let poll_secs = remaining
                .min(Duration::from_secs(5 * 60))
                .as_secs_f64()
                .round() as u64;
            let http_timeout = Duration::from_secs(poll_secs + 15);

            let response = self
                .request(
                    Method::GET,
                    Endpoint::service(format!(
                        "/v1/devices/transfer_archive?timeout={poll_secs}"
                    )),
                    HttpAuthOverride::NoOverride,
                )?
                .timeout(http_timeout)
                .send()
                .await?;
            match response.status() {
                StatusCode::OK => {
                    let bytes = response.bytes().await?;
                    if bytes.is_empty() {
                        return Err(ServiceError::InvalidFrame {
                            reason: "200 response had empty body",
                        });
                    }
                    return serde_json::from_slice(&bytes).map_err(Into::into);
                },
                StatusCode::NO_CONTENT => continue,
                code => {
                    let body = response.text().await?;
                    return Err(ServiceError::UnhandledResponseCode {
                        status: code,
                        body,
                    });
                },
            }
        }
    }
}
