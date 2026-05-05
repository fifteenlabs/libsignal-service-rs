//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
mod manager;
mod model;
mod operations;
pub mod utils;

pub use manager::{
    decrypt_group, CredentialsCache, CredentialsCacheError, GroupsManager,
    InMemoryCredentialsCache,
};
pub use model::{
    AccessControl, AccessRequired, Group, GroupChange, GroupChanges,
    GroupMemberCandidate, Member, PendingMember, RequestingMember, Role, Timer,
};
pub use operations::{GroupDecodingError, GroupOperations};

use crate::proto::GroupContextV2;
use zkgroup::groups::{GroupMasterKey, GroupSecretParams};

/// Decrypt the `groupChange` field of a `GroupContextV2` using only the
/// master key embedded in the context — no server credentials required.
/// Returns `None` when either field is absent or the bytes are empty.
pub fn decrypt_group_context_changes(
    group_context: &GroupContextV2,
) -> Result<Option<GroupChanges>, GroupDecodingError> {
    let (master_key_bytes, group_change_bytes) = match (
        group_context.master_key.as_ref(),
        group_context.group_change.as_ref(),
    ) {
        (Some(mk), Some(gc)) if !gc.is_empty() => (mk, gc),
        _ => return Ok(None),
    };
    let key: [u8; 32] = master_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| GroupDecodingError::WrongBlob)?;
    let secret_params =
        GroupSecretParams::derive_from_master_key(GroupMasterKey::new(key));
    let encrypted =
        prost::Message::decode(bytes::Bytes::from(group_change_bytes.clone()))?;
    GroupOperations::new(secret_params)
        .decrypt_group_change(encrypted)
        .map(Some)
}
