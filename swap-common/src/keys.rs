//! Key helpers.
//!
//! `bitcoin 0.30` re-exports `secp256k1` without its `rand` feature, so `SecretKey::new`
//! (which needs an RNG) isn't available. These helpers build keys from OS randomness
//! instead, retrying on the negligible chance of an out-of-range scalar.

use bitcoin::secp256k1::{Secp256k1, SecretKey, Signing};
use bitcoin::PublicKey;

/// Generate a random secret key from OS randomness.
pub fn random_secret_key() -> SecretKey {
    use rand::RngCore;
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

/// Generate a random `(secret, compressed public)` keypair.
pub fn random_keypair<C: Signing>(secp: &Secp256k1<C>) -> (SecretKey, PublicKey) {
    let sk = random_secret_key();
    let pk = PublicKey::new(sk.public_key(secp));
    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_random_and_compressed() {
        let secp = Secp256k1::new();
        let (_, pk1) = random_keypair(&secp);
        let (_, pk2) = random_keypair(&secp);
        assert_ne!(pk1, pk2);
        assert_eq!(pk1.to_bytes().len(), 33); // compressed
    }
}
