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

/// Derive the identity secret from a daemon's recovery configuration. Only the `"phrase"` method is
/// supported for iroh today; recovery-file support is a follow-up (it needs `pubky-common`, whose
/// version must be matched to the messenger's).
pub fn secret_from_recovery(method: &str, value: &str, passphrase: &str) -> Result<[u8; 32]> {
    match method {
        "phrase" => secret_from_phrase(value, Some(passphrase)),
        "file" => Err(TransportError::Iroh(
            "iroh rendezvous currently requires --recovery-phrase (recovery-file support is a \
             follow-up)"
                .to_string(),
        )),
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
}
