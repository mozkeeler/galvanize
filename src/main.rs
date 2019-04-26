extern crate ring;

use ring::rand::SecureRandom;
use ring::{aead, digest, error, pbkdf2, rand};
use std::num::NonZeroU32;

fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, error::Unspecified> {
    let mut in_out = plaintext.to_owned();
    for _ in 0..aead::MAX_TAG_LEN {
        in_out.push(0);
    }
    let mut nonce = [0u8; aead::NONCE_LEN];
    let rng = rand::SystemRandom::new();
    rng.fill(&mut nonce)?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let mut ciphertext = Vec::with_capacity(aead::NONCE_LEN + plaintext.len() + aead::MAX_TAG_LEN);
    ciphertext.extend_from_slice(nonce.as_ref());
    let seal_key = aead::SealingKey::new(&aead::AES_256_GCM, key)?;
    let out_len = aead::seal_in_place(
        &seal_key,
        nonce,
        aead::Aad::empty(),
        &mut in_out,
        aead::MAX_TAG_LEN,
    )?;
    ciphertext.extend_from_slice(&in_out[..out_len]);
    Ok(ciphertext)
}

fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, error::Unspecified> {
    let mut ciphertext = ciphertext.to_owned();
    let mut nonce = [0u8; aead::NONCE_LEN];
    for i in 0..aead::NONCE_LEN {
        nonce[i] = ciphertext[i];
    }
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let open_key = aead::OpeningKey::new(&aead::AES_256_GCM, key)?;
    let out = aead::open_in_place(
        &open_key,
        nonce,
        aead::Aad::empty(),
        aead::NONCE_LEN,
        &mut ciphertext,
    )?;
    let mut plaintext = Vec::with_capacity(out.len());
    plaintext.extend_from_slice(out);
    Ok(plaintext)
}

fn password_to_key(password: &str) -> Result<[u8; digest::SHA256_OUTPUT_LEN], error::Unspecified> {
    let mut key = [0u8; digest::SHA256_OUTPUT_LEN];
    let salt = vec![0u8; 0];
    pbkdf2::derive(
        &digest::SHA256,
        NonZeroU32::new(1000).ok_or(error::Unspecified {})?,
        &salt,
        password.as_bytes(),
        &mut key,
    );
    Ok(key)
}

fn main() {
    println!("hello, world");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0xbbu8; digest::SHA256_OUTPUT_LEN];
        let plaintext = "arm not alas sand, way south in the west".as_bytes();
        let ciphertext = encrypt(&key, &plaintext).expect("encrypt should succeed");
        let ciphertext_decrypted = decrypt(&key, &ciphertext).expect("decrypt should succeed");
        assert_eq!(ciphertext_decrypted, plaintext);
    }

    #[test]
    fn test_password_to_key() {
        let password = "salamandastron";
        let key = password_to_key(&password).expect("password_to_key should succeed");
        let expected_key = [
            0x6a, 0xf0, 0xe7, 0x90, 0x53, 0xbf, 0xa, 0xbd, 0xaf, 0x73, 0xf7, 0xb6, 0xde, 0x70,
            0x9f, 0xfc, 0x88, 0x3, 0x2e, 0xcd, 0x20, 0xd5, 0x5a, 0x59, 0xcc, 0x1c, 0xee, 0x48,
            0xab, 0x9, 0xfd, 0x16,
        ];
        assert_eq!(key, expected_key);
    }
}
