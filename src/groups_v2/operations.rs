use std::convert::TryInto;

use base64::prelude::*;
use bytes::Bytes;
use libsignal_protocol::{Aci, Pni, ServiceId};
use prost::Message;
use zkgroup::{
    groups::GroupSecretParams,
    profiles::{
        AnyProfileKeyCredentialPresentation, ExpiringProfileKeyCredential,
        ProfileKey,
    },
    ServerPublicParams,
};

use crate::{
    groups_v2::model::{AccessRequired, Timer},
    proto::{
        self, group_attribute_blob, GroupAttributeBlob,
        Member as EncryptedMember,
    },
    utils::BASE64_RELAXED,
};

use super::{
    model::{
        AccessControl, BannedMember, GroupMemberCandidate, Member,
        PendingMember, PromotedMember, RequestingMember,
    },
    Group, GroupChange, GroupChanges,
};

pub struct GroupOperations {
    pub group_secret_params: GroupSecretParams,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupDecodingError {
    #[error("zero-knowledge group deserialization failure")]
    ZkGroupDeserializationFailure,
    #[error("zero-knowledge group verification failure")]
    ZkGroupVerificationFailure,
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error("protobuf message decoding error: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("wrong group attribute blob")]
    WrongBlob,
    #[error("wrong enum value")]
    WrongEnumValue,
    #[error("wrong service ID type: should be ACI")]
    NotAci,
    #[error("wrong service ID type: should be PNI")]
    NotPni,
}

impl From<zkgroup::ZkGroupDeserializationFailure> for GroupDecodingError {
    fn from(_: zkgroup::ZkGroupDeserializationFailure) -> Self {
        GroupDecodingError::ZkGroupDeserializationFailure
    }
}

impl From<zkgroup::ZkGroupVerificationFailure> for GroupDecodingError {
    fn from(_: zkgroup::ZkGroupVerificationFailure) -> Self {
        GroupDecodingError::ZkGroupVerificationFailure
    }
}

impl GroupOperations {
    fn encrypt_service_id(
        &self,
        service_id: ServiceId,
    ) -> Result<Vec<u8>, GroupDecodingError> {
        let ciphertext =
            self.group_secret_params.encrypt_service_id(service_id);
        Ok(zkgroup::serialize(&ciphertext))
    }

    fn decrypt_service_id(
        &self,
        ciphertext: &[u8],
    ) -> Result<ServiceId, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(zkgroup::deserialize(ciphertext)?)?
        {
            ServiceId::Aci(aci) => Ok(ServiceId::from(aci)),
            ServiceId::Pni(pni) => Ok(ServiceId::from(pni)),
        }
    }

    fn encrypt_aci(&self, aci: Aci) -> Result<Vec<u8>, GroupDecodingError> {
        self.encrypt_service_id(aci.into())
    }

    fn decrypt_aci(
        &self,
        ciphertext: &[u8],
    ) -> Result<Aci, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(zkgroup::deserialize(ciphertext)?)?
        {
            ServiceId::Aci(aci) => Ok(aci),
            ServiceId::Pni(pni) => {
                tracing::error!(
                    "Expected Aci, got Pni: {}",
                    pni.service_id_string()
                );
                Err(GroupDecodingError::NotAci)
            },
        }
    }

    fn decrypt_pni(
        &self,
        ciphertext: &[u8],
    ) -> Result<Pni, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(zkgroup::deserialize(ciphertext)?)?
        {
            ServiceId::Pni(pni) => Ok(pni),
            ServiceId::Aci(aci) => {
                tracing::error!(
                    "Expected Pni, got Aci: {}",
                    aci.service_id_string()
                );
                Err(GroupDecodingError::NotPni)
            },
        }
    }

    fn encrypt_profile_key(
        &self,
        profile_key: ProfileKey,
        aci: Aci,
    ) -> Result<Vec<u8>, GroupDecodingError> {
        let ciphertext = self
            .group_secret_params
            .encrypt_profile_key(profile_key, aci);
        Ok(zkgroup::serialize(&ciphertext))
    }

    fn decrypt_profile_key(
        &self,
        encrypted_profile_key: &[u8],
        decrypted_aci: libsignal_protocol::Aci,
    ) -> Result<ProfileKey, GroupDecodingError> {
        Ok(self.group_secret_params.decrypt_profile_key(
            zkgroup::deserialize(encrypted_profile_key)?,
            decrypted_aci,
        )?)
    }

    fn decrypt_profile_key_presentation(
        &self,
        aci: &[u8],
        profile_key: &[u8],
        presentation: &[u8],
    ) -> Result<(Aci, ProfileKey), GroupDecodingError> {
        if presentation.is_empty() {
            let aci = self.decrypt_aci(aci)?;
            let profile_key = self.decrypt_profile_key(profile_key, aci)?;
            return Ok((aci, profile_key));
        }

        let profile_key_credential_presentation =
            AnyProfileKeyCredentialPresentation::new(presentation)?;

        match self.group_secret_params.decrypt_service_id(
            profile_key_credential_presentation.get_uuid_ciphertext(),
        )? {
            ServiceId::Aci(aci) => {
                let profile_key =
                    self.group_secret_params.decrypt_profile_key(
                        profile_key_credential_presentation
                            .get_profile_key_ciphertext(),
                        aci,
                    )?;
                Ok((aci, profile_key))
            },
            _ => Err(GroupDecodingError::NotAci),
        }
    }

    fn decrypt_pni_aci_promotion_presentation(
        &self,
        member: &proto::group_change::actions::PromoteMemberPendingPniAciProfileKeyAction,
    ) -> Result<PromotedMember, GroupDecodingError> {
        let aci = self.decrypt_aci(&member.user_id)?;
        let pni = self.decrypt_pni(&member.pni)?;
        let profile_key = self.decrypt_profile_key(&member.profile_key, aci)?;
        Ok(PromotedMember {
            aci,
            pni,
            profile_key,
        })
    }

    fn decrypt_member(
        &self,
        member: EncryptedMember,
    ) -> Result<Member, GroupDecodingError> {
        let (aci, profile_key) = self.decrypt_profile_key_presentation(
            &member.user_id,
            &member.profile_key,
            &member.presentation,
        )?;

        let label = self.decrypt_member_label_text(&member.label_string);
        let label_emoji = self.decrypt_member_label_emoji(&member.label_emoji);

        Ok(Member {
            aci,
            profile_key,
            role: member.role.try_into()?,
            joined_at_version: member.joined_at_version,
            label,
            label_emoji,
        })
    }

    fn decrypt_pending_member(
        &self,
        member: proto::MemberPendingProfileKey,
    ) -> Result<PendingMember, GroupDecodingError> {
        let inner_member =
            member.member.ok_or(GroupDecodingError::WrongBlob)?;
        let service_id = self.decrypt_service_id(&inner_member.user_id)?;
        let added_by_aci = self.decrypt_aci(&member.added_by_user_id)?;

        Ok(PendingMember {
            address: service_id,
            role: inner_member.role.try_into()?,
            added_by_aci,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_requesting_member(
        &self,
        member: proto::MemberPendingAdminApproval,
    ) -> Result<RequestingMember, GroupDecodingError> {
        let (aci, profile_key) = self.decrypt_profile_key_presentation(
            &member.user_id,
            &member.profile_key,
            &member.presentation,
        )?;
        Ok(RequestingMember {
            profile_key,
            aci,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_banned_member(
        &self,
        member: proto::MemberBanned,
    ) -> Result<BannedMember, GroupDecodingError> {
        Ok(BannedMember {
            user_id: self.decrypt_service_id(&member.user_id)?,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_string(
        &self,
        bytes: &[u8],
    ) -> Result<String, GroupDecodingError> {
        let bytes =
            self.group_secret_params.decrypt_blob_with_padding(bytes)?;
        String::from_utf8(bytes).map_err(|_| GroupDecodingError::WrongBlob)
    }

    /// Decrypts an optional string field, returning `None` when `bytes` is empty
    /// so absent labels don't fail the whole decode.
    fn maybe_decrypt_string(
        &self,
        bytes: &[u8],
    ) -> Result<Option<String>, GroupDecodingError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        self.decrypt_string(bytes).map(Some)
    }

    /// Decrypts a member label, treating both empty input and decryption failure
    /// as unset, matching Signal-Android's `decryptMemberLabelText`.
    fn decrypt_member_label_text(&self, bytes: &[u8]) -> Option<String> {
        match self.maybe_decrypt_string(bytes) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to decrypt member label string: {e}");
                None
            },
        }
    }

    /// Decrypts a member label emoji, treating both empty input and decryption
    /// failure as unset, matching Signal-Android's `decryptMemberLabelEmoji`.
    fn decrypt_member_label_emoji(&self, bytes: &[u8]) -> Option<String> {
        match self.maybe_decrypt_string(bytes) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to decrypt member label emoji: {e}");
                None
            },
        }
    }

    fn decrypt_blob(&self, bytes: &[u8]) -> GroupAttributeBlob {
        if bytes.is_empty() {
            GroupAttributeBlob::default()
        } else if bytes.len() < 29 {
            tracing::warn!("bad encrypted blob length");
            GroupAttributeBlob::default()
        } else {
            self.group_secret_params
                .decrypt_blob_with_padding(bytes)
                .map_err(GroupDecodingError::from)
                .and_then(|plaintext| {
                    GroupAttributeBlob::decode(Bytes::from(plaintext))
                        .map_err(GroupDecodingError::ProtobufDecodeError)
                })
                .unwrap_or_else(|e| {
                    tracing::warn!("bad encrypted blob: {}", e);
                    GroupAttributeBlob::default()
                })
        }
    }

    /// Helper method to encrypt a `group_attribute_blob::Content`.
    ///
    /// # Padding Format
    ///
    /// Uses `encrypt_blob_with_padding` format from Signal's zkgroup's
    /// `GroupSecretParams`, which prepends a 4-byte big-endian padding length value
    /// to the plaintext before encryption. For group attribute blobs, padding is
    /// always 0, so the format is:
    /// - First 4 bytes: `0u32.to_be_bytes()` (padding length = 0)
    /// - Remaining bytes: protobuf-encoded `GroupAttributeBlob`
    ///
    /// # References
    ///
    /// - Signal libsignal repository: <https://github.com/signalapp/libsignal>
    /// - GroupSecretParams implementation:
    ///   `rust/zkgroup/src/api/groups/group_params.rs`
    /// - Java ClientZkGroupCipher usage:
    ///   `java/shared/java/org/signal/libsignal/zkgroup/groups/ClientZkGroupCipher.java`
    fn encrypt_blob_content<R: rand::Rng + rand::CryptoRng>(
        &self,
        content: group_attribute_blob::Content,
        rng: &mut R,
    ) -> Vec<u8> {
        let blob = GroupAttributeBlob {
            content: Some(content),
        };
        let buf = blob.encode_to_vec();

        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        self.group_secret_params
            .encrypt_blob_with_padding(randomness, &buf, 0)
    }

    /// Encrypt an optional string field, the twin of
    /// [`maybe_decrypt_string`](Self::maybe_decrypt_string): `None` and the empty
    /// string both encode as empty, which is how every Signal client says "unset".
    ///
    /// Member labels are the padded blob of the string's own bytes rather than a
    /// [`GroupAttributeBlob`], so this cannot go through
    /// [`encrypt_blob_content`](Self::encrypt_blob_content).
    fn maybe_encrypt_string<R: rand::Rng + rand::CryptoRng>(
        &self,
        s: Option<&str>,
        rng: &mut R,
    ) -> Vec<u8> {
        let Some(s) = s.filter(|s| !s.is_empty()) else {
            return vec![];
        };
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        self.group_secret_params.encrypt_blob_with_padding(
            randomness,
            s.as_bytes(),
            0,
        )
    }

    pub fn encrypt_title<R: rand::Rng + rand::CryptoRng>(
        &self,
        title: &str,
        rng: &mut R,
    ) -> Vec<u8> {
        self.encrypt_blob_content(
            group_attribute_blob::Content::Title(title.to_string()),
            rng,
        )
    }

    /// Encrypt a description blob.
    ///
    /// There is no "absent" encoding: a blob is always produced, and an empty
    /// description encrypts to a blob of the empty string. To omit the field, skip
    /// the call — see [`encrypt_group_with_credentials`](Self::encrypt_group_with_credentials).
    pub fn encrypt_description<R: rand::Rng + rand::CryptoRng>(
        &self,
        description: &str,
        rng: &mut R,
    ) -> Vec<u8> {
        self.encrypt_blob_content(
            group_attribute_blob::Content::DescriptionText(
                description.to_string(),
            ),
            rng,
        )
    }

    /// Encrypt a disappearing messages timer blob.
    ///
    /// As with [`encrypt_description`](Self::encrypt_description), there is no
    /// "absent" encoding — omit the field by skipping the call.
    pub fn encrypt_disappearing_messages_timer<
        R: rand::Rng + rand::CryptoRng,
    >(
        &self,
        timer: &Timer,
        rng: &mut R,
    ) -> Vec<u8> {
        self.encrypt_blob_content(
            group_attribute_blob::Content::DisappearingMessagesDuration(
                timer.duration,
            ),
            rng,
        )
    }

    fn decrypt_title(&self, ciphertext: &[u8]) -> String {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::Title(title)) => title,
            _ => "".into(),
        }
    }

    fn decrypt_description_text(&self, ciphertext: &[u8]) -> Option<String> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::DescriptionText(d)) => {
                Some(d).filter(|d| !d.is_empty())
            },
            _ => None,
        }
    }

    fn decrypt_disappearing_messages_timer(
        &self,
        ciphertext: &[u8],
    ) -> Option<Timer> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::DisappearingMessagesDuration(duration)) => {
                Some(Timer { duration })
            },
            _ => None,
        }
    }

    pub fn new(group_secret_params: GroupSecretParams) -> Self {
        Self {
            group_secret_params,
        }
    }

    pub fn decrypt_group(
        &self,
        group: proto::Group,
    ) -> Result<Group, GroupDecodingError> {
        // Destructuring to catch any future changes
        let proto::Group {
            public_key: _,
            title,
            avatar_url,
            disappearing_messages_timer,
            access_control,
            version,
            members,
            members_pending_profile_key,
            members_pending_admin_approval,
            invite_link_password,
            description,
            announcements_only,
            members_banned,
            terminated,
        } = group;

        let title = self.decrypt_title(&title);

        let description_text = self.decrypt_description_text(&description);

        let disappearing_messages_timer = self
            .decrypt_disappearing_messages_timer(&disappearing_messages_timer);

        let members = members
            .into_iter()
            .map(|m| self.decrypt_member(m))
            .collect::<Result<_, _>>()?;

        let members_pending_profile_key = members_pending_profile_key
            .into_iter()
            .map(|m| self.decrypt_pending_member(m))
            .collect::<Result<_, _>>()?;

        let members_pending_admin_approval = members_pending_admin_approval
            .into_iter()
            .map(|m| self.decrypt_requesting_member(m))
            .collect::<Result<_, _>>()?;

        let members_banned = members_banned
            .into_iter()
            .map(|m| self.decrypt_banned_member(m))
            .collect::<Result<_, _>>()?;

        let access_control =
            access_control.map(TryInto::try_into).transpose()?;

        Ok(Group {
            title,
            avatar: avatar_url,
            disappearing_messages_timer,
            access_control,
            version,
            members,
            members_pending_profile_key,
            members_pending_admin_approval,
            invite_link_password,
            description_text,
            announcements_only,
            members_banned,
            terminated,
        })
    }

    pub fn decrypt_group_change(
        &self,
        group_change: proto::GroupChange,
    ) -> Result<GroupChanges, GroupDecodingError> {
        // Destructuring to catch any future changes
        let proto::GroupChange {
            actions,
            server_signature: _,
            change_epoch,
        } = group_change;

        let proto::group_change::Actions {
            group_id,
            source_user_id,
            version,
            add_members,
            delete_members,
            modify_member_roles,
            modify_member_profile_keys,
            add_members_pending_profile_key,
            delete_members_pending_profile_key,
            promote_members_pending_profile_key,
            modify_title,
            modify_avatar,
            modify_disappearing_message_timer,
            modify_attributes_access,
            modify_member_access,
            modify_add_from_invite_link_access,
            add_members_pending_admin_approval,
            delete_members_pending_admin_approval,
            promote_members_pending_admin_approval,
            modify_invite_link_password,
            modify_description,
            modify_announcements_only,
            add_members_banned,
            delete_members_banned,
            promote_members_pending_pni_aci_profile_key,
            modify_member_labels,
            modify_member_label_access,
            terminate_group,
        } = Message::decode(Bytes::from(actions))?;

        let source_user_id = self.decrypt_aci(&source_user_id)?;

        let new_members =
            add_members
                .into_iter()
                .filter_map(|m| m.added)
                .map(|added| {
                    Ok(GroupChange::NewMember(self.decrypt_member(added)?))
                });

        let delete_members = delete_members.into_iter().map(|c| {
            Ok(GroupChange::DeleteMember(
                self.decrypt_aci(&c.deleted_user_id)?,
            ))
        });

        let modify_member_roles = modify_member_roles.into_iter().map(|m| {
            Ok(GroupChange::ModifyMemberRole {
                aci: self.decrypt_aci(&m.user_id)?,
                role: m.role.try_into()?,
            })
        });

        let modify_member_profile_keys =
            modify_member_profile_keys.into_iter().map(|m| {
                let (aci, profile_key) = self
                    .decrypt_profile_key_presentation(
                        &m.user_id,
                        &m.profile_key,
                        &m.presentation,
                    )?;
                Ok(GroupChange::ModifyMemberProfileKey { aci, profile_key })
            });

        let add_members_pending_profile_key = add_members_pending_profile_key
            .into_iter()
            .filter_map(|m| m.added)
            .map(|added| {
                Ok(GroupChange::NewPendingMember(
                    self.decrypt_pending_member(added)?,
                ))
            });

        let delete_members_pending_profile_key =
            delete_members_pending_profile_key.into_iter().map(|m| {
                Ok(GroupChange::DeletePendingMember(
                    self.decrypt_service_id(&m.deleted_user_id)?,
                ))
            });

        let promote_members_pending_profile_key =
            promote_members_pending_profile_key.into_iter().map(|m| {
                let (aci, profile_key) = self
                    .decrypt_profile_key_presentation(
                        &m.user_id,
                        &m.profile_key,
                        &m.presentation,
                    )?;
                Ok(GroupChange::PromotePendingMember {
                    address: aci.into(),
                    profile_key,
                })
            });

        let modify_title = modify_title
            .into_iter()
            .map(|m| Ok(GroupChange::Title(self.decrypt_title(&m.title))));

        let modify_avatar = modify_avatar
            .into_iter()
            .map(|m| Ok(GroupChange::Avatar(m.avatar)));

        let modify_description = modify_description.into_iter().map(|m| {
            Ok(GroupChange::Description(
                self.decrypt_description_text(&m.description),
            ))
        });

        let modify_disappearing_message_timer =
            modify_disappearing_message_timer.into_iter().map(|m| {
                Ok(GroupChange::Timer(
                    self.decrypt_disappearing_messages_timer(&m.timer),
                ))
            });

        let modify_attributes_access =
            modify_attributes_access.into_iter().map(|m| {
                Ok(GroupChange::AttributeAccess(
                    m.attributes_access.try_into()?,
                ))
            });

        let modify_member_access = modify_member_access.into_iter().map(|m| {
            Ok(GroupChange::MemberAccess(m.members_access.try_into()?))
        });

        let add_members_banned = add_members_banned
            .into_iter()
            .filter_map(|m| m.added)
            .map(|m| {
                Ok(GroupChange::AddBannedMember(self.decrypt_banned_member(m)?))
            });

        let delete_members_banned =
            delete_members_banned.into_iter().map(|m| {
                Ok(GroupChange::DeleteBannedMember(
                    self.decrypt_service_id(&m.deleted_user_id)?,
                ))
            });

        let promote_members_pending_pni_aci_profile_key =
            promote_members_pending_pni_aci_profile_key
                .into_iter()
                .map(|m| {
                    let promoted =
                        self.decrypt_pni_aci_promotion_presentation(&m)?;
                    Ok(GroupChange::PromotePendingPniAciMemberProfileKey(
                        promoted,
                    ))
                });

        let modify_add_from_invite_link_access =
            modify_add_from_invite_link_access.into_iter().map(|m| {
                Ok(GroupChange::InviteLinkAccess(
                    m.add_from_invite_link_access.try_into()?,
                ))
            });

        let add_members_pending_admin_approval =
            add_members_pending_admin_approval
                .into_iter()
                .filter_map(|m| m.added)
                .map(|added| {
                    Ok(GroupChange::NewRequestingMember(
                        self.decrypt_requesting_member(added)?,
                    ))
                });

        let delete_members_pending_admin_approval =
            delete_members_pending_admin_approval.into_iter().map(|m| {
                Ok(GroupChange::DeleteRequestingMember(
                    self.decrypt_aci(&m.deleted_user_id)?,
                ))
            });

        let promote_members_pending_admin_approval =
            promote_members_pending_admin_approval.into_iter().map(|m| {
                Ok(GroupChange::PromoteRequestingMember {
                    aci: self.decrypt_aci(&m.user_id)?,
                    role: m.role.try_into()?,
                })
            });

        let modify_invite_link_password =
            modify_invite_link_password.into_iter().map(|m| {
                Ok(GroupChange::InviteLinkPassword(
                    BASE64_RELAXED.encode(m.invite_link_password),
                ))
            });

        let modify_announcements_only = modify_announcements_only
            .into_iter()
            .map(|m| Ok(GroupChange::AnnouncementOnly(m.announcements_only)));

        let modify_member_labels = modify_member_labels.into_iter().map(|m| {
            Ok(GroupChange::MemberLabel {
                user_id: self.decrypt_service_id(&m.user_id)?,
                label_emoji: self.decrypt_member_label_emoji(&m.label_emoji),
                label_string: self.decrypt_member_label_text(&m.label_string),
            })
        });

        let modify_member_label_access =
            modify_member_label_access.into_iter().map(|m| {
                Ok(GroupChange::MemberLabelAccess(
                    m.member_label_access.try_into()?,
                ))
            });

        let terminate_group = terminate_group.into_iter().map(|_m| {
            // The *presence* of the field signifies termination.
            // TerminateGroupAction is a unit struct.
            Ok(GroupChange::TerminateGroup)
        });

        let changes: Result<Vec<GroupChange>, GroupDecodingError> = new_members
            .chain(delete_members)
            .chain(modify_member_roles)
            .chain(modify_member_profile_keys)
            .chain(add_members_pending_profile_key)
            .chain(delete_members_pending_profile_key)
            .chain(promote_members_pending_profile_key)
            .chain(modify_title)
            .chain(modify_avatar)
            .chain(modify_disappearing_message_timer)
            .chain(modify_attributes_access)
            .chain(modify_description)
            .chain(modify_member_access)
            .chain(add_members_banned)
            .chain(delete_members_banned)
            .chain(promote_members_pending_pni_aci_profile_key)
            .chain(modify_add_from_invite_link_access)
            .chain(add_members_pending_admin_approval)
            .chain(delete_members_pending_admin_approval)
            .chain(promote_members_pending_admin_approval)
            .chain(modify_invite_link_password)
            .chain(modify_announcements_only)
            .chain(modify_member_labels)
            .chain(modify_member_label_access)
            .chain(terminate_group)
            .collect();

        Ok(GroupChanges {
            group_id: group_id
                .try_into()
                .map_err(|_| GroupDecodingError::WrongBlob)?,
            editor: source_user_id,
            version,
            changes: changes?,
            change_epoch,
        })
    }

    pub fn decrypt_avatar(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::Avatar(d)) => Some(d).filter(|d| !d.is_empty()),
            _ => None,
        }
    }

    /// Build an AddMemberAction for a GroupChange.
    ///
    /// # Role Parameter
    ///
    /// The `role` parameter is accepted for API consistency, but note that
    /// Signal-Android only ever adds members with `Role::Default`. Adding a member
    /// with `Role::Administrator` is an illegal operation that the server will reject.
    /// Promotion to administrator requires a separate `ModifyMemberRoleAction` after
    /// the member has been added.
    ///
    /// See Signal-Android's `GroupsV2Operations.GroupOperations.createModifyGroupMembershipChange()`
    /// which hardcodes `Member.Role newMemberRole = Member.Role.DEFAULT`.
    pub fn build_add_member_action(
        &self,
        aci: Aci,
        profile_key: ProfileKey,
        role: super::model::Role,
    ) -> Result<proto::group_change::actions::AddMemberAction, GroupDecodingError>
    {
        Ok(proto::group_change::actions::AddMemberAction {
            added: Some(proto::Member {
                user_id: self.encrypt_aci(aci)?,
                profile_key: self.encrypt_profile_key(profile_key, aci)?,
                presentation: vec![],
                role: role.into(),
                joined_at_version: 0, // Set by server
                // XXX: should these be exposed?
                label_emoji: vec![],
                label_string: vec![],
            }),
            join_from_invite_link: false,
        })
    }

    /// Build a DeleteMemberAction for a GroupChange
    pub fn build_remove_member_action(
        &self,
        aci: Aci,
    ) -> Result<
        proto::group_change::actions::DeleteMemberAction,
        GroupDecodingError,
    > {
        Ok(proto::group_change::actions::DeleteMemberAction {
            deleted_user_id: self.encrypt_aci(aci)?,
        })
    }

    /// Promote a member to administrator or demote one back to a plain member.
    ///
    /// Administrators only, and only for full members: the id is an ACI, matching
    /// what `decrypt_group_change` reads back from the action. Adding someone as an
    /// administrator directly is not a thing — see `build_add_member_action` — so
    /// this is the only way a member's role changes.
    pub fn build_modify_member_role_action(
        &self,
        aci: Aci,
        role: super::model::Role,
    ) -> Result<
        proto::group_change::actions::ModifyMemberRoleAction,
        GroupDecodingError,
    > {
        Ok(proto::group_change::actions::ModifyMemberRoleAction {
            user_id: self.encrypt_aci(aci)?,
            role: role.into(),
        })
    }

    /// Build a DeletePendingMemberAction to retract an outstanding invitation.
    ///
    /// Used when a pending member (invite not yet accepted) is to be removed.
    /// The `invitee` may be ACI or PNI — whichever service ID was used when
    /// the invite was originally created.  The Signal server stores and matches
    /// on the encrypted `user_id` field of `PendingMember`, which may be
    /// either kind of `ServiceId`.
    pub fn build_remove_pending_member_action(
        &self,
        invitee: ServiceId,
    ) -> Result<
        proto::group_change::actions::DeleteMemberPendingProfileKeyAction,
        GroupDecodingError,
    > {
        Ok(
            proto::group_change::actions::DeleteMemberPendingProfileKeyAction {
                deleted_user_id: self.encrypt_service_id(invitee)?,
            },
        )
    }

    pub fn build_modify_title_action<R: rand::Rng + rand::CryptoRng>(
        &self,
        title: &str,
        rng: &mut R,
    ) -> proto::group_change::actions::ModifyTitleAction {
        proto::group_change::actions::ModifyTitleAction {
            title: self.encrypt_title(title, rng),
        }
    }

    /// An empty description clears the field: the server keeps the blob, and
    /// [`decrypt_description_text`](Self::decrypt_description_text) reads an empty
    /// string back as `None`.
    pub fn build_modify_description_action<R: rand::Rng + rand::CryptoRng>(
        &self,
        description: &str,
        rng: &mut R,
    ) -> proto::group_change::actions::ModifyDescriptionAction {
        proto::group_change::actions::ModifyDescriptionAction {
            description: self.encrypt_description(description, rng),
        }
    }

    /// A zero duration turns the timer off — that is how every Signal client
    /// encodes "off", and how [`decrypt_disappearing_messages_timer`](Self::decrypt_disappearing_messages_timer)
    /// reads it back.
    pub fn build_modify_disappearing_messages_timer_action<
        R: rand::Rng + rand::CryptoRng,
    >(
        &self,
        timer: &Timer,
        rng: &mut R,
    ) -> proto::group_change::actions::ModifyDisappearingMessageTimerAction
    {
        proto::group_change::actions::ModifyDisappearingMessageTimerAction {
            timer: self.encrypt_disappearing_messages_timer(timer, rng),
        }
    }

    /// Who may change the group's title, description, avatar and timer. Only
    /// `Member` and `Administrator` are meaningful here; the other variants belong
    /// to the invite-link rule.
    pub fn build_modify_attributes_access_action(
        &self,
        access: AccessRequired,
    ) -> proto::group_change::actions::ModifyAttributesAccessControlAction {
        proto::group_change::actions::ModifyAttributesAccessControlAction {
            attributes_access: access.into(),
        }
    }

    /// Who may add members. Same domain as
    /// [`build_modify_attributes_access_action`](Self::build_modify_attributes_access_action).
    pub fn build_modify_members_access_action(
        &self,
        access: AccessRequired,
    ) -> proto::group_change::actions::ModifyMembersAccessControlAction {
        proto::group_change::actions::ModifyMembersAccessControlAction {
            members_access: access.into(),
        }
    }

    /// Who may set a member label. Same domain as
    /// [`build_modify_attributes_access_action`](Self::build_modify_attributes_access_action).
    pub fn build_modify_member_label_access_action(
        &self,
        access: AccessRequired,
    ) -> proto::group_change::actions::ModifyMemberLabelAccessControlAction
    {
        proto::group_change::actions::ModifyMemberLabelAccessControlAction {
            member_label_access: access.into(),
        }
    }

    /// Set or clear one member's label. `None` clears the field, as does an
    /// empty string — see
    /// [`maybe_encrypt_string`](Self::maybe_encrypt_string).
    pub fn build_modify_member_label_action<R: rand::Rng + rand::CryptoRng>(
        &self,
        aci: Aci,
        label_string: Option<&str>,
        label_emoji: Option<&str>,
        rng: &mut R,
    ) -> Result<
        proto::group_change::actions::ModifyMemberLabelAction,
        GroupDecodingError,
    > {
        Ok(proto::group_change::actions::ModifyMemberLabelAction {
            user_id: self.encrypt_aci(aci)?,
            label_emoji: self.maybe_encrypt_string(label_emoji, rng),
            label_string: self.maybe_encrypt_string(label_string, rng),
        })
    }

    /// Whether only administrators may send to the group.
    pub fn build_modify_announcements_only_action(
        &self,
        announcements_only: bool,
    ) -> proto::group_change::actions::ModifyAnnouncementsOnlyAction {
        proto::group_change::actions::ModifyAnnouncementsOnlyAction {
            announcements_only,
        }
    }

    /// Create a presentation from a credential for adding a member to a group.
    ///
    /// This creates a ZK proof (ExpiringProfileKeyCredentialPresentation) that the
    /// Signal server can verify to validate the member's identity and profile key.
    ///
    /// # Presentation protocol version
    ///
    /// The presentation must carry `PRESENTATION_VERSION_4` (raw value `3`). A V3
    /// presentation makes the server reject the whole group proto with a bare HTTP 400
    /// and no further detail — a server-side policy floor, not a verification failure:
    /// zkgroup itself routes V3 and V4 to the same verifier, differing only in a
    /// `full_checking` flag that binds `C_y5` in the proof (a soundness hardening added
    /// in April 2026, which the service presumably began requiring once clients shipped
    /// it).
    ///
    /// Since libsignal v0.99.0 this is no longer expressible as a mistake:
    /// `create_expiring_profile_key_credential_presentation` lost its version type
    /// parameter and always returns `ExpiringProfileKeyCredentialPresentationV2`, which
    /// is `ExpiringProfileKeyCredentialPresentation<PRESENTATION_VERSION_4>`. If the
    /// floor ever rises again, expect the same undiagnosable 400 until libsignal follows.
    pub fn create_member_presentation(
        &self,
        server_public_params: &ServerPublicParams,
        credential: &ExpiringProfileKeyCredential,
    ) -> Vec<u8> {
        let randomness: [u8; 32] = rand::random();
        let presentation = server_public_params
            .create_expiring_profile_key_credential_presentation(
                randomness,
                self.group_secret_params,
                *credential,
            );
        zkgroup::serialize(&presentation)
    }

    /// Encrypt a group for creation, using credentials for member presentations.
    ///
    /// This method properly populates the `presentation` field for members with
    /// credentials, which is required by the Signal server for group creation.
    ///
    /// Members with credentials get added with presentations (full members).
    /// Members without credentials get added as pending invites.
    ///
    /// # Arguments
    /// * `title` - The group title
    /// * `description` - Optional group description
    /// * `disappearing_messages_timer` - Optional disappearing messages timer
    /// * `access_control` - Optional access control settings
    /// * `self_credential` - The creator's own credential (required)
    /// * `avatar_url` - The group avatar URL
    /// * `member_candidates` - Other members to add, with optional credentials
    /// * `server_public_params` - Server public params for creating presentations
    /// * `rng` - Random number generator
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_group_with_credentials<R: rand::Rng + rand::CryptoRng>(
        &self,
        title: &str,
        description: Option<&str>,
        disappearing_messages_timer: Option<&Timer>,
        access_control: Option<&AccessControl>,
        self_credential: &ExpiringProfileKeyCredential,
        member_candidates: &[GroupMemberCandidate],
        server_public_params: &ServerPublicParams,
        avatar_url: String,
        rng: &mut R,
    ) -> Result<proto::Group, GroupDecodingError> {
        let mut members = Vec::new();
        let mut members_pending_profile_key = Vec::new();

        // Add self as administrator with presentation
        let self_presentation = self
            .create_member_presentation(server_public_params, self_credential);
        members.push(proto::Member {
            user_id: vec![],     // Server extracts from presentation
            profile_key: vec![], // Server extracts from presentation
            presentation: self_presentation,
            role: proto::member::Role::Administrator.into(),
            joined_at_version: 0,
            label_emoji: vec![],
            label_string: vec![],
        });

        // Add other members.
        //
        // Self is already in `members` as administrator, so skip any candidate that is
        // also us: two entries for the same ACI is not a group the server will accept, and
        // callers naturally build the candidate list from a conversation that includes
        // themselves.
        let self_aci = self_credential.aci();
        for candidate in member_candidates {
            if candidate.service_id == ServiceId::from(self_aci) {
                tracing::debug!(
                    "skipping self in group member candidates; already added \
                     as administrator"
                );
                continue;
            }

            if let Some(credential) = &candidate.credential {
                // Has credential - add as full member with presentation
                let presentation = self.create_member_presentation(
                    server_public_params,
                    credential,
                );
                members.push(proto::Member {
                    user_id: vec![],
                    profile_key: vec![],
                    presentation,
                    role: proto::member::Role::Default.into(),
                    joined_at_version: 0,
                    label_emoji: vec![],
                    label_string: vec![],
                });
            } else {
                // No credential - add as pending invite
                let user_id_ciphertext =
                    self.encrypt_service_id(candidate.service_id)?;
                members_pending_profile_key.push(
                    proto::MemberPendingProfileKey {
                        member: Some(proto::Member {
                            user_id: user_id_ciphertext,
                            profile_key: vec![],
                            presentation: vec![],
                            role: proto::member::Role::Default.into(),
                            joined_at_version: 0,
                            label_emoji: vec![],
                            label_string: vec![],
                        }),
                        added_by_user_id: self.encrypt_aci(self_aci)?,
                        timestamp: 0, // Server sets
                    },
                );
            }
        }

        // Encrypt title, description, timer.
        //
        // Description and timer are omitted entirely when unset — an encrypted blob of the
        // empty string is not the same as an absent field, and emitting either on a create
        // is rejected by the server with HTTP 400. Signal-Desktop nulls both in
        // `buildGroupProto`, commenting "Can't create group with these initial fields",
        // and applies the timer afterwards as a separate group change.
        let encrypted_title = self.encrypt_title(title, rng);
        let encrypted_description = description
            .map(|description| self.encrypt_description(description, rng))
            .unwrap_or_default();
        let encrypted_timer = disappearing_messages_timer
            .map(|timer| self.encrypt_disappearing_messages_timer(timer, rng))
            .unwrap_or_default();

        // Convert access control
        let proto_access_control =
            access_control.map(|ac| proto::AccessControl {
                attributes: ac.attributes.into(),
                members: ac.members.into(),
                add_from_invite_link: ac.add_from_invite_link.into(),
                member_label: ac.member_label.into(),
            });

        Ok(proto::Group {
            public_key: zkgroup::serialize(
                &self.group_secret_params.get_public_params(),
            ),
            title: encrypted_title,
            avatar_url,
            disappearing_messages_timer: encrypted_timer,
            access_control: proto_access_control,
            version: 0,
            members,
            members_pending_profile_key,
            members_pending_admin_approval: vec![],
            invite_link_password: vec![],
            description: encrypted_description,
            announcements_only: false,
            members_banned: vec![],
            terminated: false,
        })
    }

    /// Build an AddMemberAction with a credential presentation for a GroupChange.
    ///
    /// This is used when adding members to an existing group with proper ZK proofs.
    ///
    /// # Role Parameter
    ///
    /// The `role` parameter is accepted for API consistency, but note that
    /// Signal-Android only ever adds members with `Role::Default`. Adding a member
    /// with `Role::Administrator` is an illegal operation that the server will reject.
    /// Promotion to administrator requires a separate `ModifyMemberRoleAction` after
    /// the member has been added.
    pub fn build_add_member_action_with_credential(
        &self,
        credential: &ExpiringProfileKeyCredential,
        role: super::model::Role,
        server_public_params: &ServerPublicParams,
    ) -> proto::group_change::actions::AddMemberAction {
        let presentation =
            self.create_member_presentation(server_public_params, credential);
        proto::group_change::actions::AddMemberAction {
            added: Some(proto::Member {
                user_id: vec![],     // Server extracts from presentation
                profile_key: vec![], // Server extracts from presentation
                presentation,
                role: role.into(),
                joined_at_version: 0, // Set by server
                label_emoji: vec![],
                label_string: vec![],
            }),
            join_from_invite_link: false,
        }
    }

    /// Build an AddPendingMemberAction to invite a member without their profile key.
    ///
    /// This adds the member as a pending invite. They will receive a group invite
    /// notification and must accept to become a full member. No profile key is needed.
    ///
    /// The `invitee` may be either an ACI or a PNI. When only a PNI is known (e.g.
    /// the invitee has ACI disclosure disabled in CDSI), passing `ServiceId::Pni`
    /// allows the pending-invite path to proceed without an ACI. The Signal server
    /// stores whichever service ID is provided in the encrypted `user_id` field of
    /// the `PendingMember` proto. The `added_by_aci` must always be an ACI.
    ///
    /// # Role Parameter
    ///
    /// The `role` parameter is accepted for API consistency, but note that
    /// Signal-Android only ever adds pending members with `Role::Default`.
    pub fn build_add_pending_member_action(
        &self,
        invitee: ServiceId,
        added_by_aci: Aci,
        role: super::model::Role,
    ) -> Result<
        proto::group_change::actions::AddMemberPendingProfileKeyAction,
        GroupDecodingError,
    > {
        Ok(
            proto::group_change::actions::AddMemberPendingProfileKeyAction {
                added: Some(proto::MemberPendingProfileKey {
                    member: Some(proto::Member {
                        user_id: self.encrypt_service_id(invitee)?,
                        profile_key: vec![],
                        presentation: vec![],
                        role: role.into(),
                        joined_at_version: 0,
                        label_emoji: vec![],
                        label_string: vec![],
                    }),
                    added_by_user_id: self.encrypt_aci(added_by_aci)?,
                    timestamp: 0, // Server sets
                }),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zkgroup::groups::GroupMasterKey;

    fn create_group_operations() -> GroupOperations {
        // Create a test group master key (32 bytes)
        let master_key_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let group_master_key = GroupMasterKey::new(master_key_bytes);
        let group_secret_params =
            GroupSecretParams::derive_from_master_key(group_master_key);
        GroupOperations::new(group_secret_params)
    }

    #[test]
    fn roundtrip_title() {
        let ops = create_group_operations();
        let mut rng = rand::rng();

        let title = "Test Group Title";
        let encrypted = ops.encrypt_title(title, &mut rng);
        let decrypted = ops.decrypt_title(&encrypted);
        assert_eq!(decrypted, title);
    }

    #[test]
    fn roundtrip_description() {
        let ops = create_group_operations();
        let mut rng = rand::rng();

        let description = "This is a test group description";
        let encrypted = ops.encrypt_description(description, &mut rng);
        let decrypted = ops.decrypt_description_text(&encrypted);
        assert_eq!(decrypted, Some(description.to_string()));
    }

    #[test]
    fn roundtrip_member_label() {
        let ops = create_group_operations();
        let mut rng = rand::rng();
        let aci = Aci::parse_from_service_id_string(
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .unwrap();

        let label = "Whisperfish / rubdos";
        let action = ops
            .build_modify_member_label_action(
                aci,
                Some(label),
                Some("🐟"),
                &mut rng,
            )
            .unwrap();

        assert_eq!(
            ops.decrypt_member_label_text(&action.label_string),
            Some(label.to_string())
        );
        assert_eq!(
            ops.decrypt_member_label_emoji(&action.label_emoji),
            Some("🐟".to_string())
        );
        assert_eq!(
            ops.decrypt_service_id(&action.user_id).unwrap(),
            ServiceId::from(aci)
        );
    }

    #[test]
    fn a_member_label_is_cleared_by_an_empty_blob() {
        let ops = create_group_operations();
        let mut rng = rand::rng();
        let aci = Aci::parse_from_service_id_string(
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .unwrap();

        let action = ops
            .build_modify_member_label_action(aci, None, Some(""), &mut rng)
            .unwrap();

        assert!(action.label_string.is_empty());
        assert!(action.label_emoji.is_empty());
        assert_eq!(ops.decrypt_member_label_text(&action.label_string), None);
    }

    #[test]
    fn attribute_actions_decrypt_to_the_changes_they_encode() {
        use super::super::model::GroupChange;

        let ops = create_group_operations();
        let mut rng = rand::rng();

        let editor = Aci::parse_from_service_id_string(
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .expect("valid ACI");
        let actions = proto::group_change::Actions {
            source_user_id: ops.encrypt_aci(editor).unwrap(),
            group_id: ops.group_secret_params.get_group_identifier().to_vec(),
            version: 7,
            modify_title: Some(
                ops.build_modify_title_action("Renamed", &mut rng),
            ),
            modify_description: Some(
                ops.build_modify_description_action("About us", &mut rng),
            ),
            modify_disappearing_message_timer: Some(
                ops.build_modify_disappearing_messages_timer_action(
                    &Timer { duration: 86_400 },
                    &mut rng,
                ),
            ),
            modify_attributes_access: Some(
                ops.build_modify_attributes_access_action(
                    AccessRequired::Administrator,
                ),
            ),
            modify_member_access: Some(
                ops.build_modify_members_access_action(AccessRequired::Member),
            ),
            ..Default::default()
        };
        let group_change = proto::GroupChange {
            actions: actions.encode_to_vec(),
            server_signature: vec![],
            change_epoch: 0,
        };

        let changes = ops.decrypt_group_change(group_change).unwrap();
        assert_eq!(changes.version, 7);
        assert_eq!(changes.editor, editor);
        assert!(changes
            .changes
            .iter()
            .any(|c| matches!(c, GroupChange::Title(t) if t == "Renamed")));
        assert!(changes.changes.iter().any(
            |c| matches!(c, GroupChange::Description(Some(d)) if d == "About us")
        ));
        assert!(changes.changes.iter().any(
            |c| matches!(c, GroupChange::Timer(Some(t)) if t.duration == 86_400)
        ));
        assert!(changes.changes.iter().any(|c| matches!(
            c,
            GroupChange::AttributeAccess(AccessRequired::Administrator)
        )));
        assert!(changes.changes.iter().any(|c| matches!(
            c,
            GroupChange::MemberAccess(AccessRequired::Member)
        )));
    }

    #[test]
    fn member_role_action_decrypts_to_the_change_it_encodes() {
        use super::super::model::{GroupChange, Role};

        let ops = create_group_operations();
        let editor = Aci::parse_from_service_id_string(
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .expect("valid ACI");
        let promoted = Aci::parse_from_service_id_string(
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        )
        .expect("valid ACI");
        let actions = proto::group_change::Actions {
            source_user_id: ops.encrypt_aci(editor).unwrap(),
            group_id: ops.group_secret_params.get_group_identifier().to_vec(),
            version: 3,
            modify_member_roles: vec![ops
                .build_modify_member_role_action(promoted, Role::Administrator)
                .unwrap()],
            ..Default::default()
        };
        let changes = ops
            .decrypt_group_change(proto::GroupChange {
                actions: actions.encode_to_vec(),
                server_signature: vec![],
                change_epoch: 0,
            })
            .unwrap();

        assert!(changes.changes.iter().any(|c| matches!(
            c,
            GroupChange::ModifyMemberRole { aci, role: Role::Administrator } if *aci == promoted
        )));
    }

    #[test]
    fn roundtrip_disappearing_message_timer() {
        let ops = create_group_operations();
        let mut rng = rand::rng();

        let timer = Timer { duration: 3600 };
        let encrypted =
            ops.encrypt_disappearing_messages_timer(&timer, &mut rng);
        let decrypted = ops.decrypt_disappearing_messages_timer(&encrypted);
        assert_eq!(decrypted, Some(timer));
    }

    #[test]
    fn roundtrip_aci_encryption() {
        let ops = create_group_operations();

        // Use a known ACI string (UUID format from existing test patterns)
        let aci = Aci::parse_from_service_id_string(
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .expect("valid ACI");
        let encrypted =
            ops.encrypt_aci(aci).expect("encrypt_aci should succeed");
        let decrypted = ops
            .decrypt_aci(&encrypted)
            .expect("decrypt_aci should succeed");
        assert_eq!(decrypted, aci);
    }

    #[test]
    fn roundtrip_service_id_encryption() {
        let ops = create_group_operations();

        // Use a known UUID string for the service ID
        let service_id: ServiceId = ServiceId::parse_from_service_id_string(
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .expect("valid service ID");
        let encrypted = ops
            .encrypt_service_id(service_id)
            .expect("encrypt_service_id should succeed");
        let decrypted = ops
            .decrypt_service_id(&encrypted)
            .expect("decrypt_service_id should succeed");
        assert_eq!(decrypted, service_id);
    }

    #[test]
    fn roundtrip_service_id_pni_encryption() {
        let ops = create_group_operations();

        // Use a known UUID string for the service ID
        let service_id: ServiceId = ServiceId::parse_from_service_id_string(
            "PNI:550e8400-e29b-41d4-a716-446655440000",
        )
        .expect("valid service ID");
        let encrypted = ops
            .encrypt_service_id(service_id)
            .expect("encrypt_service_id should succeed");
        let decrypted = ops
            .decrypt_service_id(&encrypted)
            .expect("decrypt_service_id should succeed");
        assert_eq!(decrypted, service_id);
    }

    #[test]
    fn encrypt_title_different_each_time() {
        let ops = create_group_operations();
        let mut rng = rand::rng();

        let title = "Test Title";
        let encrypted1 = ops.encrypt_title(title, &mut rng);
        let encrypted2 = ops.encrypt_title(title, &mut rng);

        // Same plaintext should produce different ciphertext due to random padding
        // but both should decrypt to the same value
        assert_ne!(encrypted1, encrypted2);
        assert_eq!(ops.decrypt_title(&encrypted1), title);
        assert_eq!(ops.decrypt_title(&encrypted2), title);
    }
}
