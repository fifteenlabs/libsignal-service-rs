//! Fetching [`ExpiringProfileKeyCredential`]s.
//!
//! A credential proves to the group server that we know a member's profile key, and is
//! required to add them to a group as a full member rather than a pending invite. Obtaining
//! one is a two-step dance: the request is generated locally and embedded in the fetch URL,
//! and the response can only be verified with the context that produced the request — so that
//! context has to survive the round-trip.

use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::Aci;
use rand::{CryptoRng, Rng};
use zkgroup::{
    profiles::{
        ExpiringProfileKeyCredential, ExpiringProfileKeyCredentialResponse,
        ProfileKey, ProfileKeyCredentialRequestContext,
    },
    ServerPublicParams, ZkGroupDeserializationFailure,
    ZkGroupVerificationFailure,
};

#[derive(thiserror::Error, Debug)]
pub enum ProfileCredentialError {
    #[error("failed to deserialize the profile key credential response")]
    Deserialization(#[from] ZkGroupDeserializationFailure),
    #[error("the profile key credential response did not verify")]
    Verification(#[from] ZkGroupVerificationFailure),
}

/// A pending profile key credential request.
///
/// Hold on to this across the fetch: [`hex`](Self::hex) goes into the request URL, and
/// [`receive`](Self::receive) needs the context generated alongside it.
pub struct ProfileCredentialRequest {
    server_public_params: ServerPublicParams,
    context: ProfileKeyCredentialRequestContext,
    hex: String,
}

impl ProfileCredentialRequest {
    pub fn new<R: Rng + CryptoRng>(
        csprng: &mut R,
        server_public_params: &ServerPublicParams,
        aci: Aci,
        profile_key: ProfileKey,
    ) -> Self {
        let mut randomness = [0u8; 32];
        csprng.fill_bytes(&mut randomness);
        Self::with_randomness(
            randomness,
            server_public_params,
            aci,
            profile_key,
        )
    }

    /// Deterministic constructor, mirroring libsignal's bridge API. Prefer [`new`](Self::new)
    /// outside of tests.
    pub fn with_randomness(
        randomness: [u8; 32],
        server_public_params: &ServerPublicParams,
        aci: Aci,
        profile_key: ProfileKey,
    ) -> Self {
        let context = server_public_params
            .create_profile_key_credential_request_context(
                randomness,
                aci,
                profile_key,
            );
        let hex = hex::encode(zkgroup::serialize(&context.get_request()));

        Self {
            server_public_params: server_public_params.clone(),
            context,
            hex,
        }
    }

    /// The hex-encoded request, to be embedded in the fetch URL.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Verify and unwrap a `credential` response body.
    ///
    /// Note that zkgroup rejects credentials expiring today or more than seven days out, so
    /// this errors rather than handing back a stale credential.
    pub fn receive(
        &self,
        response: &[u8],
        now: SystemTime,
    ) -> Result<ExpiringProfileKeyCredential, ProfileCredentialError> {
        let response: ExpiringProfileKeyCredentialResponse =
            zkgroup::deserialize(response)?;

        let now = zkgroup::Timestamp::from_epoch_seconds(
            now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        );

        Ok(self
            .server_public_params
            .receive_expiring_profile_key_credential(
                &self.context,
                &response,
                now,
            )?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use zkgroup::{ServerSecretParams, TEST_ARRAY_32, TEST_ARRAY_32_1};

    use super::*;

    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

    /// Issues a credential the way the server would, expiring `days` out from the epoch.
    fn round_trip(
        expiration_days: u64,
        now: SystemTime,
    ) -> Result<ExpiringProfileKeyCredential, ProfileCredentialError> {
        let server_params = ServerSecretParams::generate(TEST_ARRAY_32);
        let aci = Aci::parse_from_service_id_string(ACI_UUID).expect("valid");
        let profile_key = ProfileKey::create(TEST_ARRAY_32_1);

        let request = ProfileCredentialRequest::with_randomness(
            TEST_ARRAY_32,
            &server_params.get_public_params(),
            aci,
            profile_key,
        );

        let response = server_params
            .issue_expiring_profile_key_credential(
                TEST_ARRAY_32,
                &request.context.get_request(),
                aci,
                profile_key.get_commitment(aci),
                zkgroup::Timestamp::from_epoch_seconds(
                    expiration_days * zkgroup::SECONDS_PER_DAY,
                ),
            )
            .expect("issued");

        request.receive(&zkgroup::serialize(&response), now)
    }

    #[test]
    fn receives_a_credential_within_the_validity_window() {
        // Issued expiring on day 3, redeemed on day 1: three days remaining.
        let credential = round_trip(
            3,
            UNIX_EPOCH + Duration::from_secs(zkgroup::SECONDS_PER_DAY),
        )
        .expect("verified");

        assert_eq!(
            credential.get_expiration_time().epoch_seconds(),
            3 * zkgroup::SECONDS_PER_DAY
        );
    }

    #[test]
    fn rejects_a_credential_that_expires_today() {
        // zkgroup requires days_remaining > 0, so redeeming on the expiry day fails rather
        // than handing back something stale.
        let result = round_trip(
            3,
            UNIX_EPOCH + Duration::from_secs(3 * zkgroup::SECONDS_PER_DAY),
        );

        assert!(matches!(
            result,
            Err(ProfileCredentialError::Verification(_))
        ));
    }

    #[test]
    fn rejects_a_credential_valid_for_more_than_a_week() {
        // days_remaining > 7 is refused too.
        let result = round_trip(9, UNIX_EPOCH);

        assert!(matches!(
            result,
            Err(ProfileCredentialError::Verification(_))
        ));
    }

    #[test]
    fn rejects_a_malformed_response() {
        let server_params = ServerSecretParams::generate(TEST_ARRAY_32);
        let aci = Aci::parse_from_service_id_string(ACI_UUID).expect("valid");

        let request = ProfileCredentialRequest::with_randomness(
            TEST_ARRAY_32,
            &server_params.get_public_params(),
            aci,
            ProfileKey::create(TEST_ARRAY_32_1),
        );

        assert!(matches!(
            request.receive(&[0xAA; 8], SystemTime::now()),
            Err(ProfileCredentialError::Deserialization(_))
        ));
    }

    #[test]
    fn hex_is_the_serialized_request() {
        let server_params = ServerSecretParams::generate(TEST_ARRAY_32);
        let aci = Aci::parse_from_service_id_string(ACI_UUID).expect("valid");

        let request = ProfileCredentialRequest::with_randomness(
            TEST_ARRAY_32,
            &server_params.get_public_params(),
            aci,
            ProfileKey::create(TEST_ARRAY_32_1),
        );

        assert_eq!(
            request.hex(),
            hex::encode(zkgroup::serialize(&request.context.get_request()))
        );
    }
}
