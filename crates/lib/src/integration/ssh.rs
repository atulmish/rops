use ssh_key::{private::KeypairData, PublicKey};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct SshIntegration;

impl SshIntegration {
    fn load_ssh_key(private_key_str: impl AsRef<str>) -> IntegrationResult<KeypairData> {
        let private_key_str = private_key_str.as_ref();

        let private_key = ssh_key::PrivateKey::from_openssh(private_key_str)
            .map_err(|e| IntegrationError::PrivateKeyParsing(anyhow::anyhow!(e)))?;

        match private_key.key_data() {
            KeypairData::Ed25519(_) => Ok(private_key.key_data().clone()),
            _ => Err(IntegrationError::PrivateKeyParsing(anyhow::anyhow!(
                "Only Ed25519 SSH keys are supported"
            ))),
        }
    }
}

impl Integration for SshIntegration {
    const NAME: &'static str = "ssh";
    type KeyId = SshPublicKey;
    type PrivateKey = KeypairData;
    type Config = SshConfig;

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId> {
        SshPublicKey::from_openssh_format(key_id_str)
    }

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
        Self::load_ssh_key(private_key_str)
    }

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String> {
        use sha2::{Digest, Sha256};

        let x25519_pub = key_id.to_x25519_public()?;
        let mut ephemeral_seed = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut ephemeral_seed);
        let ephemeral_secret = x25519_dalek::StaticSecret::from(ephemeral_seed);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

        let shared_secret = ephemeral_secret.diffie_hellman(&x25519_pub);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        hasher.update(b"rops-ssh-encryption");
        let derived_key: [u8; 32] = hasher.finalize().into();

        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(ephemeral_public.as_bytes());

        let data_bytes: &[u8] = data_key.as_ref();
        for i in 0..DataKey::byte_size() {
            encrypted_data.push(data_bytes[i] ^ derived_key[i % 32]);
        }

        Ok(hex::encode(encrypted_data))
    }

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
        use sha2::{Digest, Sha256};

        let private_keys = Self::retrieve_private_keys()?;

        let matched_private_key = private_keys.into_iter().find(|private_key| {
            match SshPublicKey::from_keypair(private_key) {
                Ok(pub_key) => &pub_key == key_id,
                Err(_) => false,
            }
        });

        let Some(matched_private_key) = matched_private_key else {
            return Ok(None);
        };

        let encrypted_bytes = hex::decode(encrypted_data_key)
            .map_err(|e| IntegrationError::Decryption(anyhow::anyhow!(e)))?;

        if encrypted_bytes.len() < 32 + DataKey::byte_size() {
            return Err(IntegrationError::Decryption(anyhow::anyhow!(
                "Invalid encrypted data key format"
            )));
        }

        let ephemeral_public_bytes = &encrypted_bytes[0..32];
        let ciphertext = &encrypted_bytes[32..];

        let ephemeral_public = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(ephemeral_public_bytes)
                .map_err(|_| IntegrationError::Decryption(anyhow::anyhow!("Invalid ephemeral public key")))?,
        );

        let x25519_secret = matched_private_key.to_x25519_secret()?;
        let shared_secret = x25519_secret.diffie_hellman(&ephemeral_public);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        hasher.update(b"rops-ssh-encryption");
        let derived_key: [u8; 32] = hasher.finalize().into();

        let mut decrypted_data_key = DataKey::empty();
        for i in 0..DataKey::byte_size() {
            decrypted_data_key.as_mut()[i] = ciphertext[i] ^ derived_key[i % 32];
        }

        Ok(Some(decrypted_data_key))
    }

    fn select_metadata_units(integration_metadata: &mut IntegrationMetadata) -> &mut IntegrationMetadataUnits<Self> {
        &mut integration_metadata.ssh
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshPublicKey {
    bytes: [u8; 32],
}

impl SshPublicKey {
    fn from_openssh_format(key_str: &str) -> IntegrationResult<Self> {
        let public_key = PublicKey::from_openssh(key_str)
            .map_err(|e| IntegrationError::KeyIdParsing(anyhow::anyhow!(e)))?;

        match public_key.key_data() {
            ssh_key::public::KeyData::Ed25519(bytes) => Ok(Self { bytes: bytes.0 }),
            _ => Err(IntegrationError::KeyIdParsing(anyhow::anyhow!(
                "Only Ed25519 SSH keys are supported"
            ))),
        }
    }

    fn from_keypair(keypair: &KeypairData) -> IntegrationResult<Self> {
        match keypair {
            KeypairData::Ed25519(kp) => Ok(Self {
                bytes: kp.public.0,
            }),
            _ => Err(IntegrationError::KeyIdParsing(anyhow::anyhow!(
                "Only Ed25519 SSH keys are supported"
            ))),
        }
    }

    fn to_x25519_public(&self) -> IntegrationResult<x25519_dalek::PublicKey> {
        let x25519_bytes = convert_ed25519_to_x25519_public(&self.bytes)?;
        Ok(x25519_dalek::PublicKey::from(x25519_bytes))
    }
}

impl std::fmt::Display for SshPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64::Engine;
        write!(f, "ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(&self.bytes))
    }
}

impl std::str::FromStr for SshPublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SshPublicKey::from_openssh_format(s)
            .map_err(|e| match e {
                IntegrationError::KeyIdParsing(e) => e,
                _ => anyhow::anyhow!("Failed to parse SSH public key"),
            })
    }
}

impl AppendIntegrationKey<SshIntegration> for SshPublicKey {
    fn append_to_metadata_builder(self, integration_metadata_builder: &mut IntegrationMetadataBuilder) {
        integration_metadata_builder.ssh_key_ids.push(self)
    }
}

trait ToX25519Secret {
    fn to_x25519_secret(&self) -> IntegrationResult<x25519_dalek::StaticSecret>;
}

impl ToX25519Secret for KeypairData {
    fn to_x25519_secret(&self) -> IntegrationResult<x25519_dalek::StaticSecret> {
        match self {
            KeypairData::Ed25519(keypair) => {
                let x25519_bytes = convert_ed25519_to_x25519_private(&keypair.private)?;
                Ok(x25519_dalek::StaticSecret::from(x25519_bytes))
            }
            _ => Err(IntegrationError::PrivateKeyParsing(anyhow::anyhow!(
                "Only Ed25519 SSH keys are supported"
            ))),
        }
    }
}

fn convert_ed25519_to_x25519_public(ed_bytes: &[u8; 32]) -> IntegrationResult<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let compressed = CompressedEdwardsY(*ed_bytes);
    let point = compressed
        .decompress()
        .ok_or_else(|| IntegrationError::PrivateKeyParsing(anyhow::anyhow!("Invalid Ed25519 key")))?;

    Ok(point.to_montgomery().as_bytes().clone())
}

fn convert_ed25519_to_x25519_private(ed_private_key: &ssh_key::private::Ed25519PrivateKey) -> IntegrationResult<[u8; 32]> {
    use sha2::{Digest, Sha512};

    let ed_bytes = ed_private_key.to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(ed_bytes);
    let hash = hasher.finalize();

    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&hash[..32]);
    x25519_bytes[0] &= 248;
    x25519_bytes[31] &= 127;
    x25519_bytes[31] |= 64;

    Ok(x25519_bytes)
}

pub use config::SshConfig;
mod config {
    use serde::{Deserialize, Serialize};
    use serde_with::{serde_as, DisplayFromStr};

    use crate::*;

    #[serde_as]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SshConfig {
        #[serde_as(as = "DisplayFromStr")]
        #[serde(rename = "recipient")]
        pub key_id: <SshIntegration as Integration>::KeyId,
    }

    impl IntegrationConfig<SshIntegration> for SshConfig {
        const INCLUDE_DATA_KEY_CREATED_AT: bool = false;

        fn new(key_id: <SshIntegration as Integration>::KeyId) -> Self {
            Self { key_id }
        }

        fn key_id(&self) -> &<SshIntegration as Integration>::KeyId {
            &self.key_id
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockTestUtil for SshConfig {
            fn mock() -> Self {
                Self {
                    key_id: MockTestUtil::mock(),
                }
            }
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl IntegrationTestUtils for SshIntegration {
        fn mock_private_key_str() -> impl AsRef<str> {
            indoc::indoc! {"
                -----BEGIN OPENSSH PRIVATE KEY-----
                b3BlbnNzaC1rZXktdjEAAAAABG5vbmUtbm9uZS1ub25lAAAAaQAAAAxFZDI1NTE5
                AAAAIEMqlOmKqVhOzQj8A3kJnAR8fxS3xVdZlBl1h3REv0N3AAAAF11PFQtdTxULAAAA
                DGEyYTEzMDYzNDliYQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUm
                JygpKissLS4vMDEyMzQ1Njc4OTo7PDw+P0AxQgAAAB9T2K76U9iuelPYrvrToxCCGGK4
                VRV0JhpJf+AAAAAEdGVzdAECAwQ=
                -----END OPENSSH PRIVATE KEY-----
            "}
        }

        fn mock_encrypted_data_key_str() -> &'static str {
            "b6efbbf4453fd8ee8b7de45af3836cf42863e5cbfa64b1ef8d0a2487d4c09873b8f8c8f40f4e4a0c2d2e2f303132333435363738393a3b3c3d3e3f40410"
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock_key_id {
    use super::*;

    impl MockDisplayTestUtil for SshPublicKey {
        fn mock_display() -> String {
            "ssh-ed25519 Jyqk6YqpWE7NCPwDeQmcBHx/FLfFV1mUGXWHdES/Q3c=".to_string()
        }
    }

    impl MockTestUtil for SshPublicKey {
        fn mock() -> Self {
            Self {
                bytes: [
                    35, 42, 148, 233, 138, 169, 88, 78, 205, 8, 252, 3, 121, 9, 156, 4, 124, 127, 20, 183, 197,
                    87, 89, 148, 25, 117, 135, 116, 68, 191, 67, 119,
                ],
            }
        }
    }

    impl MockOtherTestUtil for SshPublicKey {
        fn mock_other() -> Self {
            Self {
                bytes: [
                    100, 42, 148, 233, 138, 169, 88, 78, 205, 8, 252, 3, 121, 9, 156, 4, 124, 127, 20, 183, 201,
                    87, 89, 148, 25, 117, 135, 116, 68, 191, 99, 119,
                ],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    generate_integration_test_suite!(SshIntegration);
}
