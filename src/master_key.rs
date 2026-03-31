use base64::prelude::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, Rng};
use sha2::Sha256;

const MASTER_KEY_LEN: usize = 32;
const STORAGE_KEY_LEN: usize = 32;
const STORAGE_KEY_DERIVED_LEN: usize = 32;

const STORAGE_SERVICE_ENCRYPTION_INFO: &[u8] = b"Storage Service Encryption";
const STORAGE_SERVICE_MANIFEST_INFO_PREFIX: &[u8] = b"Manifest_";
const STORAGE_SERVICE_ITEM_INFO_PREFIX: &[u8] = b"Item_";
const STORAGE_SERVICE_ITEM_KEY_INFO_PREFIX: &[u8] =
    b"20240801_SIGNAL_STORAGE_SERVICE_ITEM_";

#[derive(Debug, PartialEq)]
pub struct MasterKey {
    pub inner: [u8; MASTER_KEY_LEN],
}

impl MasterKey {
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        // Create random bytes
        let mut inner = [0_u8; MASTER_KEY_LEN];
        csprng.fill(&mut inner);
        Self { inner }
    }

    pub fn from_slice(
        slice: &[u8],
    ) -> Result<Self, std::array::TryFromSliceError> {
        let inner = slice.try_into()?;
        Ok(Self { inner })
    }
}

impl From<MasterKey> for Vec<u8> {
    fn from(val: MasterKey) -> Self {
        val.inner.to_vec()
    }
}

#[derive(Debug, PartialEq)]
pub struct StorageServiceKey {
    pub inner: [u8; STORAGE_KEY_LEN],
}

impl StorageServiceKey {
    pub fn from_master_key(master_key: &MasterKey) -> Self {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&master_key.inner).unwrap();
        mac.update(STORAGE_SERVICE_ENCRYPTION_INFO);
        let inner: [u8; STORAGE_KEY_LEN] = mac.finalize().into_bytes().into();

        Self { inner }
    }

    pub fn from_slice(
        slice: &[u8],
    ) -> Result<Self, std::array::TryFromSliceError> {
        let inner = slice.try_into()?;
        Ok(Self { inner })
    }

    pub fn derive_storage_item_key(
        &self,
        item_key: &[u8],
        record_ikm: Option<&[u8]>,
    ) -> [u8; STORAGE_KEY_DERIVED_LEN] {
        match record_ikm {
            None => {
                type HmacSha256 = Hmac<Sha256>;

                let item_id = BASE64_STANDARD.encode(item_key);
                let mut mac = HmacSha256::new_from_slice(&self.inner).unwrap();

                mac.update(STORAGE_SERVICE_ITEM_INFO_PREFIX);
                mac.update(item_id.as_bytes());

                mac.finalize().into_bytes().into()
            },
            Some(ikm) => {
                let mut info = Vec::with_capacity(
                    STORAGE_SERVICE_ITEM_KEY_INFO_PREFIX.len() + item_key.len(),
                );

                info.extend_from_slice(STORAGE_SERVICE_ITEM_KEY_INFO_PREFIX);
                info.extend_from_slice(item_key);

                let hk = Hkdf::<Sha256>::new(Some(&[]), ikm);
                let mut okm = [0u8; STORAGE_KEY_DERIVED_LEN];

                hk.expand(&info, &mut okm).unwrap();
                okm
            },
        }
    }

    pub fn derive_storage_manifest_key(
        &self,
        version: u64,
    ) -> [u8; STORAGE_KEY_DERIVED_LEN] {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.inner).unwrap();
        mac.update(STORAGE_SERVICE_MANIFEST_INFO_PREFIX);
        mac.update(version.to_string().as_bytes());
        mac.finalize().into_bytes().into()
    }
}

impl From<StorageServiceKey> for Vec<u8> {
    fn from(val: StorageServiceKey) -> Self {
        val.inner.to_vec()
    }
}

/// Storage trait for handling MasterKey and StorageKey.
pub trait MasterKeyStore {
    /// Fetch the master key from the store if it exists.
    fn fetch_master_key(&self) -> Option<MasterKey>;

    /// Fetch the storage service key from the store if it exists.
    fn fetch_storage_service_key(&self) -> Option<StorageServiceKey>;

    /// Save (or clear) the master key to the store.
    fn store_master_key(&self, master_key: Option<&MasterKey>);

    /// Save (or clear) the storage service key to the store.
    fn store_storage_service_key(
        &self,
        storage_key: Option<&StorageServiceKey>,
    );
}

mod tests {
    #[test]
    fn derive_storage_key_from_master_key() {
        use super::{MasterKey, StorageServiceKey};
        use base64::prelude::*;

        // This test passed with actual 'masterKey' and 'storageKey' values taken
        // from Signal Desktop v7.23.0 database at 2024-09-08 after linking it with Signal Andoid.

        let master_key_bytes = BASE64_STANDARD
            .decode("9hquLIIZmom8fHF7H8pbUAreawmPLEqli5ceJ94pFkU=")
            .unwrap();
        let storage_key_bytes = BASE64_STANDARD
            .decode("QMgZ5RGTLFTr4u/J6nypaJX6DKDlSgMw8vmxU6gxnvI=")
            .unwrap();
        assert_eq!(master_key_bytes.len(), 32);
        assert_eq!(storage_key_bytes.len(), 32);

        let master_key = MasterKey::from_slice(&master_key_bytes).unwrap();
        let storage_key = StorageServiceKey::from_master_key(&master_key);

        assert_eq!(master_key.inner, master_key_bytes.as_slice());
        assert_eq!(storage_key.inner, storage_key_bytes.as_slice());
    }
}
