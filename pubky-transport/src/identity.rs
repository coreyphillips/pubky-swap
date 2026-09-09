//! Deriving the ed25519 identity secret from a recovery phrase, matching how pubky-messenger
//! derives it, so an iroh endpoint built from this secret has `endpoint_id == pubky` (see
//! [`crate::p2p`]). Feature `iroh`.

use crate::{Result, TransportError};

/// Derive the 32-byte ed25519 secret from a BIP39 recovery phrase (+ optional passphrase), exactly
/// as pubky-messenger does: `seed = mnemonic.to_seed(passphrase)`, secret = `seed[..32]`. Keeping
/// this in lockstep with the messenger's derivation is what guarantees the iroh endpoint id equals
/// the pubky the swap DMs come from (see the `secret_matches_messenger_identity` test).
pub fn secret_from_phrase(mnemonic: &str, passphrase: Option<&str>) -> Result<[u8; 32]> {
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, mnemonic)
        .map_err(|e| TransportError::Iroh(format!("parse recovery phrase: {e}")))?;
    let seed = mnemonic.to_seed(passphrase.unwrap_or(""));
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&seed[..32]);
    Ok(secret)
}

/// The pubky string for an identity secret (equals the `endpoint_id` of an iroh endpoint built
/// from it).
pub fn pubky_from_secret(secret: &[u8; 32]) -> String {
    pkarr::Keypair::from_secret_key(secret)
        .public_key()
        .to_string()
}

/// Derive the 32-byte ed25519 secret from a `.pkarr` recovery file and its passphrase.
///
/// The same bytes `pubky-messenger` gets from the same file, so the iroh endpoint id equals the
/// pubky again. `pubky-common` and the messenger both resolve to one `pkarr`, so the `Keypair`
/// types are the same type and the secret is the same secret.
pub fn secret_from_file(path: &str, passphrase: &str) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)
        .map_err(|e| TransportError::Iroh(format!("read recovery file {path}: {e}")))?;
    let keypair = pubky_common::recovery_file::decrypt_recovery_file(&bytes, passphrase)
        .map_err(|e| TransportError::Iroh(format!("decrypt recovery file {path}: {e:?}")))?;
    Ok(keypair.secret_key())
}

/// Derive the identity secret from a daemon's recovery configuration, by either method.
///
/// The `"file"` arm used to return an error, and the provider logged it and carried on. So an
/// operator who uploaded a recovery file, which is one of the two ways the Umbrel app offers to
/// load an identity, got a provider that ran, reported healthy, and answered no doorbell: nobody
/// who had only been handed their pubky could reach them, and nothing said why.
pub fn secret_from_recovery(method: &str, value: &str, passphrase: &str) -> Result<[u8; 32]> {
    match method {
        "phrase" => secret_from_phrase(value, Some(passphrase)),
        "file" => secret_from_file(value, passphrase),
        other => Err(TransportError::Iroh(format!(
            "unknown recovery method: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// The derived identity must match pubky-messenger's own derivation, so the iroh endpoint id
    /// equals the pubky the swap DMs come from. This guards against the two derivations drifting.
    #[tokio::test]
    async fn secret_matches_messenger_identity() {
        let secret = secret_from_phrase(MNEMONIC, None).unwrap();
        let ours = pubky_from_secret(&secret);
        let messenger =
            pubky_messenger::PrivateMessengerClient::from_recovery_phrase(MNEMONIC, None, None)
                .unwrap();
        assert_eq!(ours, messenger.public_key_string());
    }

    /// The same, for the other way an identity is loaded.
    ///
    /// The `"file"` arm returned an error and the provider logged it and carried on, so an
    /// operator who uploaded a recovery file, one of the two ways the Umbrel app offers, got a
    /// provider that ran and reported healthy and could not be reached by anyone who had only
    /// been handed their pubky. This asserts the file yields the identity the messenger reads
    /// from the very same bytes, which is what makes the iroh endpoint id equal the pubky.
    #[tokio::test]
    async fn a_recovery_file_yields_the_same_identity_as_the_messenger_reads() {
        const PASSPHRASE: &str = "correct horse battery staple";
        let keypair = pkarr::Keypair::random();
        let bytes = pubky_common::recovery_file::create_recovery_file(&keypair, PASSPHRASE);

        let path = std::env::temp_dir().join(format!(
            "pubky-swap-recovery-{}.pkarr",
            keypair.public_key()
        ));
        std::fs::write(&path, &bytes).unwrap();

        let ours =
            pubky_from_secret(&secret_from_file(path.to_str().unwrap(), PASSPHRASE).unwrap());
        let messenger =
            pubky_messenger::PrivateMessengerClient::from_recovery_file(&bytes, Some(PASSPHRASE))
                .unwrap();
        assert_eq!(ours, messenger.public_key_string());
        assert_eq!(ours, keypair.public_key().to_string());

        // And the generic entry point, which is what the daemon actually calls.
        let via_recovery =
            secret_from_recovery("file", path.to_str().unwrap(), PASSPHRASE).unwrap();
        assert_eq!(pubky_from_secret(&via_recovery), ours);

        // A wrong passphrase is an error, not a different identity.
        assert!(secret_from_file(path.to_str().unwrap(), "wrong").is_err());

        let _ = std::fs::remove_file(&path);
    }
}
