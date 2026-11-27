use base64::Engine;
use libsignal_protocol::Aci;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use zkgroup::profiles::{ProfileKeyCommitment, ProfileKeyVersion};

use crate::{
    content::ServiceError,
    profile_credential::ProfileCredentialRequest,
    push_service::response::SignalServiceResponse,
    push_service::{AttachmentV2UploadAttributes, AvatarWrite},
    utils::{serde_base64, serde_optional_base64, BASE64_RELAXED},
    websocket::{
        self, account::DeviceCapabilities, SignalWebSocket, WebSocketType,
    },
};

/// A donation badge returned by the server on profile fetch.
///
/// Mirrors the JSON shape of Signal-Android's `SignalServiceProfile.Badge`.
/// Display metadata is render-ready (name, description, sprites6 image URLs).
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Badge {
    /// Server catalog id (e.g. "BOOSTING").
    #[serde(default)]
    pub id: String,
    /// Badge category string.
    #[serde(default)]
    pub category: String,
    /// Render-ready display name.
    #[serde(default)]
    pub name: String,
    /// Render-ready description.
    #[serde(default)]
    pub description: String,
    /// Sprite image URLs (density-tagged).
    #[serde(default)]
    pub sprites6: Vec<String>,
    /// Expiration epoch millis. Java sends this as BigDecimal.
    #[serde(default)]
    pub expiration: Option<f64>,
    /// Whether the badge is displayed on the profile.
    #[serde(default)]
    pub visible: bool,
    /// Duration badge is valid for, in seconds.
    #[serde(default)]
    pub duration: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalServiceProfile {
    #[serde(default, with = "serde_optional_base64")]
    pub identity_key: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub name: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about_emoji: Option<Vec<u8>>,
    /// Encrypted MobileCoin payment address. Never decrypted here: a profile
    /// write sends these bytes back, because the server clears what a write
    /// leaves out.
    #[serde(default, with = "serde_optional_base64")]
    pub payment_address: Option<Vec<u8>>,
    /// Encrypted phone-number-sharing flag, carried over like
    /// `payment_address`.
    #[serde(default, with = "serde_optional_base64")]
    pub phone_number_sharing: Option<Vec<u8>>,
    pub avatar: Option<String>,
    pub unidentified_access: Option<String>,

    #[serde(default)]
    pub unrestricted_unidentified_access: bool,

    pub capabilities: DeviceCapabilities,

    /// Donation badges the server reports for this profile.
    #[serde(default)]
    pub badges: Vec<Badge>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignalServiceProfileWrite<'s> {
    /// Hex-encoded
    version: &'s str,
    #[serde(with = "serde_base64")]
    name: &'s [u8],
    #[serde(with = "serde_base64")]
    about: &'s [u8],
    #[serde(with = "serde_base64")]
    about_emoji: &'s [u8],
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_optional_base64"
    )]
    payment_address: Option<&'s [u8]>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_optional_base64"
    )]
    phone_number_sharing: Option<&'s [u8]>,
    avatar: bool,
    same_avatar: bool,
    #[serde(with = "serde_base64")]
    commitment: &'s [u8],
}

impl SignalWebSocket<websocket::Identified> {
    pub async fn retrieve_profile_by_id(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let path = if let Some(key) = profile_key {
            let version =
                hex::encode(key.get_profile_key_version(address).bytes);
            format!("/v1/profile/{}/{}", address.service_id_string(), version)
        } else {
            format!("/v1/profile/{}", address.service_id_string())
        };
        // TODO: set locale to en_US
        self.http_request(Method::GET, path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }

    /// Fetch our own profile key credential over the authenticated socket, as Signal-Desktop
    /// does for self.
    ///
    /// Verify the returned bytes with [`ProfileCredentialRequest::receive`] on the same
    /// `request`.
    pub async fn retrieve_own_profile_key_credential(
        &mut self,
        request: &ProfileCredentialRequest,
    ) -> Result<Vec<u8>, ServiceError> {
        self.retrieve_profile_key_credential_impl(request, None)
            .await
    }

    /// Writes a profile. For a new avatar, returns the form to upload it with.
    ///
    /// The name, about and emoji fields are encrypted with an [`ProfileCipher`][struct@crate::profile_cipher::ProfileCipher],
    /// and a new avatar's bytes are uploaded separately with the returned form.
    /// See [`AccountManager`][struct@crate::AccountManager] for a convenience method.
    ///
    /// The write replaces the whole profile, and the server clears every field it
    /// leaves out, so `current`'s payment address and phone number sharing go
    /// back exactly as the server holds them.
    ///
    /// Java equivalent: `writeProfile`
    #[allow(clippy::too_many_arguments)]
    pub async fn write_profile(
        &mut self,
        version: &ProfileKeyVersion,
        name: &[u8],
        about: &[u8],
        emoji: &[u8],
        current: Option<&SignalServiceProfile>,
        commitment: &ProfileKeyCommitment,
        avatar: &AvatarWrite<Vec<u8>>,
    ) -> Result<Option<AttachmentV2UploadAttributes>, ServiceError> {
        let version = hex::encode(version.bytes);
        let commitment = bincode::serialize(commitment)?;
        let command = profile_write(
            &version,
            name,
            about,
            emoji,
            current,
            &commitment,
            avatar,
        );

        let response = self
            .http_request(Method::PUT, "/v1/profile")?
            .send_json(&command)
            .await?
            .service_error_for_status()
            .await?;

        // The server answers a new avatar with its upload form, and anything
        // else with an empty body.
        if !matches!(avatar, AvatarWrite::NewAvatar(_)) {
            return Ok(None);
        }
        Ok(Some(response.json().await?))
    }
}

fn profile_write<'s>(
    version: &'s str,
    name: &'s [u8],
    about: &'s [u8],
    emoji: &'s [u8],
    current: Option<&'s SignalServiceProfile>,
    commitment: &'s [u8],
    avatar: &AvatarWrite<Vec<u8>>,
) -> SignalServiceProfileWrite<'s> {
    SignalServiceProfileWrite {
        version,
        name,
        about,
        about_emoji: emoji,
        payment_address: current.and_then(|p| p.payment_address.as_deref()),
        phone_number_sharing: current
            .and_then(|p| p.phone_number_sharing.as_deref()),
        avatar: !matches!(avatar, AvatarWrite::NoAvatar),
        same_avatar: matches!(avatar, AvatarWrite::RetainAvatar),
        commitment,
    }
}

/// Path for a profile key credential fetch.
///
/// Byte-for-byte the URL built by Signal-Desktop's `getProfileUrl` and by libsignal's own
/// `get_profile_key_credential`.
fn profile_key_credential_path(request: &ProfileCredentialRequest) -> String {
    let aci = request.aci();

    let version =
        hex::encode(request.profile_key().get_profile_key_version(aci).bytes);

    let request_hex = request.hex();
    format!(
        "/v1/profile/{}/{version}/{request_hex}?credentialType=expiringProfileKey",
        aci.service_id_string(),
    )
}

impl<C: WebSocketType> SignalWebSocket<C> {
    /// Shared implementation. The two entry points pair the access key with the correct
    /// socket type.
    async fn retrieve_profile_key_credential_impl(
        &mut self,
        request: &ProfileCredentialRequest,
        access_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, ServiceError> {
        let path = profile_key_credential_path(request);

        let mut builder = self.http_request(Method::GET, path)?;
        if let Some(access_key) = access_key {
            builder = builder.header(
                "Unidentified-Access-Key",
                BASE64_RELAXED.encode(access_key),
            );
        }

        // The endpoint returns a whole profile; we only want this one field.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct CredentialResponse {
            #[serde(default, with = "serde_optional_base64")]
            credential: Option<Vec<u8>>,
        }

        let response: CredentialResponse = builder
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;

        response
            .credential
            .filter(|bytes| !bytes.is_empty())
            .ok_or(ServiceError::UnsupportedContent)
    }
}

impl SignalWebSocket<websocket::Unidentified> {
    /// Fetch another user's profile key credential, authorised by the access key derived from
    /// their profile key. This is the path Signal-Desktop uses for everyone but self.
    ///
    /// A 401/403 surfaces as [`ServiceError::Unauthorized`] (our profile key is stale) and a
    /// 404 as [`ServiceError::NotFoundError`] (profile version not found).
    ///
    /// Verify the returned bytes with [`ProfileCredentialRequest::receive`] on the same
    /// `request`.
    pub async fn retrieve_profile_key_credential(
        &mut self,
        request: &ProfileCredentialRequest,
    ) -> Result<Vec<u8>, ServiceError> {
        let access_key = request.profile_key().derive_access_key();
        self.retrieve_profile_key_credential_impl(request, Some(&access_key))
            .await
    }

    pub async fn retrieve_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        Ok(self
            .unidentified_push_service
            .get_from_cdn(0, path)
            .await?
            .stream)
    }

    pub async fn retrieve_groups_v2_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        Ok(self
            .unidentified_push_service
            .get_from_cdn(0, path)
            .await?
            .stream)
    }
}

#[cfg(test)]
mod tests {
    use zkgroup::{
        profiles::ProfileKey, ServerSecretParams, TEST_ARRAY_32,
        TEST_ARRAY_32_1,
    };

    use super::*;

    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

    /// The expected URL is lifted verbatim from libsignal's own test of this exchange
    /// (`rust/net/chat/src/ws/profiles.rs`), built from the same ACI and the same zkgroup test
    /// vectors. If our path ever drifts from libsignal's, this fails.
    #[test]
    fn credential_path_matches_libsignal() {
        let expected = concat!(
            "/v1/profile/9d0652a3-dcc3-4d11-975f-74d61598733f",
            "/f74078448aa501a163593a4c0b2ec4644b27a2a747639bb1a5e2af71ff355d9c",
            "/0014ee4cf2cbdad90c58980cba3f5d9b900e57b52597834580aaaf83a87f5439",
            "1faa03f125f289279492292e958f96e9f79d8f9924f866acb168a85cdb5bbc69",
            "3a12115f946407fe6154813854293c955103f82e47788ac8e227123de9d99b22",
            "6c500a11ec4a532623bc1a2a25f8664ac3e1af3b71fb59f0b6fb9ea9a647650a",
            "0f4e34696d86a7602ad0e918aabfaee4c15528d44a76842f9bf760c23f9fa5a2",
            "50a000000000000000b3e5952105bee26968d4781d7530d4a0c3fde51605eb73",
            "540ca08d30ee34080d15280d1ed736c2673ebd9ad71fc0917dfdde1a0ca259ff",
            "573e3a1a3868d2110c61f74b1fa3a5b281d85a68bd7b7c092f21bd5a45c8eef5",
            "2cb987c895737598093ca2f47bdb2251df556a2cea9186be716a394e13d4a71a",
            "4d88b8914212ecb40f238ee645547012ae531392c311138171d9ac26a56fcce8",
            "cfb617e061f3e4f50d",
            "?credentialType=expiringProfileKey"
        );

        let aci = Aci::parse_from_service_id_string(ACI_UUID).expect("valid");
        let profile_key = ProfileKey::create(TEST_ARRAY_32_1);
        let request = ProfileCredentialRequest::with_randomness(
            TEST_ARRAY_32,
            &ServerSecretParams::generate(TEST_ARRAY_32).get_public_params(),
            aci,
            profile_key,
        );

        assert_eq!(profile_key_credential_path(&request), expected);
    }

    fn written(
        current: Option<&SignalServiceProfile>,
        avatar: &AvatarWrite<Vec<u8>>,
    ) -> serde_json::Value {
        serde_json::to_value(profile_write(
            "ab",
            b"name",
            b"about",
            b"emoji",
            current,
            b"commitment",
            avatar,
        ))
        .unwrap()
    }

    #[test]
    fn a_profile_write_carries_over_the_fields_it_does_not_edit() {
        let current: SignalServiceProfile =
            serde_json::from_value(serde_json::json!({
                "paymentAddress": "cGF5bWVudA==",
                "phoneNumberSharing": "c2hhcmluZw==",
                "capabilities": {},
            }))
            .unwrap();

        let json = written(Some(&current), &AvatarWrite::RetainAvatar);

        assert_eq!(json["paymentAddress"], "cGF5bWVudA==");
        assert_eq!(json["phoneNumberSharing"], "c2hhcmluZw==");
    }

    #[test]
    fn a_profile_write_leaves_out_what_the_server_never_had() {
        let json = written(None, &AvatarWrite::RetainAvatar);

        assert!(json.get("paymentAddress").is_none());
        assert!(json.get("phoneNumberSharing").is_none());
    }

    #[test]
    fn a_profile_write_says_which_avatar_change_it_is() {
        let flags = |avatar| {
            let json = written(None, &avatar);
            (json["avatar"].clone(), json["sameAvatar"].clone())
        };

        assert_eq!(
            flags(AvatarWrite::RetainAvatar),
            (true.into(), true.into())
        );
        assert_eq!(
            flags(AvatarWrite::NewAvatar(vec![1])),
            (true.into(), false.into())
        );
        assert_eq!(flags(AvatarWrite::NoAvatar), (false.into(), false.into()));
    }
}
