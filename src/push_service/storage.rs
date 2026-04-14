use prost::Message;
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::{
    configuration::Endpoint,
    master_key::StorageServiceKey,
    profile_cipher::decrypt_aes256_gcm,
    proto::{
        ManifestRecord, ReadOperation, StorageItem, StorageItems,
        StorageManifest, StorageRecord,
    },
};

use super::{
    protobuf::{ProtobufRequestBuilderExt, ProtobufResponseExt},
    HttpAuth, HttpAuthOverride, PushService, ServiceError,
};
use crate::push_service::response::ReqwestExt;

/// Short-lived credentials returned by GET /v1/storage/auth.
/// Used as Basic Auth for all subsequent storage service calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageServiceCredentials {
    pub username: String,
    pub password: String,
}

impl PushService {
    /// GET /v1/storage/auth — fetch short-lived storage credentials from the
    /// main Signal API. These must be passed to all subsequent storage service
    /// calls.
    pub async fn get_storage_credentials(
        &mut self,
    ) -> Result<StorageServiceCredentials, ServiceError> {
        Ok(self
            .request(
                Method::GET,
                Endpoint::service("/v1/storage/auth"),
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json::<StorageServiceCredentials>()
            .await?)
    }

    /// GET /v1/storage/manifest[/version/{n}] — fetch the encrypted storage
    /// manifest.
    ///
    /// Pass `greater_than_version` to only fetch if the server has a newer
    /// version than what you already have. Returns `None` on HTTP 204, meaning
    /// the local manifest is already current.
    pub async fn get_storage_manifest(
        &mut self,
        credentials: &StorageServiceCredentials,
        greater_than_version: Option<u64>,
    ) -> Result<Option<StorageManifest>, ServiceError> {
        let path = match greater_than_version {
            Some(v) => format!("/v1/storage/manifest/version/{}", v),
            None => "/v1/storage/manifest".to_string(),
        };

        let response = self
            .request(
                Method::GET,
                Endpoint::storage(path),
                HttpAuthOverride::Identified(HttpAuth {
                    username: credentials.username.clone(),
                    password: credentials.password.clone(),
                }),
            )?
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }

        Ok(Some(
            response
                .service_error_for_status()
                .await?
                .protobuf::<StorageManifest>()
                .await?,
        ))
    }

    /// PUT /v1/storage/read — fetch specific storage items by key.
    ///
    /// The `read_operation` contains the raw keys from the manifest identifiers
    /// you want to fetch. Returns the encrypted `StorageItems` to be decrypted
    /// individually.
    pub async fn get_storage_records(
        &mut self,
        credentials: &StorageServiceCredentials,
        read_operation: ReadOperation,
    ) -> Result<Vec<StorageItem>, ServiceError> {
        self.request(
            Method::PUT,
            Endpoint::storage("/v1/storage/read"),
            HttpAuthOverride::Identified(HttpAuth {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
            }),
        )?
        .protobuf(read_operation)
        .map_err(|e| ServiceError::SendError {
            reason: e.to_string(),
        })?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .protobuf::<StorageItems>()
        .await
        .map(|s| s.items)
    }
}

pub fn decrypt_manifest(
    manifest: &StorageManifest,
    storage_key: &StorageServiceKey,
) -> Result<ManifestRecord, ServiceError> {
    if manifest.value.is_empty() {
        return Err(ServiceError::InvalidFrame {
            reason: "storage manifest has no value",
        });
    }
    let key = storage_key.derive_storage_manifest_key(manifest.version);
    let plaintext = decrypt_aes256_gcm(&key, &manifest.value)
        .map_err(|_| ServiceError::MacError)?;
    Ok(ManifestRecord::decode(plaintext.as_slice())?)
}

pub fn decrypt_storage_record(
    item: &StorageItem,
    storage_key: &StorageServiceKey,
    record_ikm: Option<&[u8]>,
) -> Result<StorageRecord, ServiceError> {
    if item.value.is_empty() {
        return Err(ServiceError::InvalidFrame {
            reason: "storage item has no value",
        });
    }
    let key = storage_key.derive_storage_item_key(&item.key, record_ikm);
    let plaintext = decrypt_aes256_gcm(&key, &item.value)
        .map_err(|_| ServiceError::MacError)?;
    Ok(StorageRecord::decode(plaintext.as_slice())?)
}
