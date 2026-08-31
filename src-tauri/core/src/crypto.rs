use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use rand::RngCore;
use rsa::{pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use secrecy::{ExposeSecret, SecretString};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::models::KdfType;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

// Clone is required so the parked `PendingTwoFactor` slot can hand
// out copies of the master key for the second-factor IPC step
// without releasing the original. The clone keeps the same
// ZeroizeOnDrop semantics — both copies are wiped when their
// respective owners go out of scope.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct MasterKey([u8; 32]);

// MasterPasswordHash gained Zeroize/ZeroizeOnDrop alongside the
// PendingTwoFactor refactor: the hash is the credential we actually
// post to /connect/token, so it deserves the same wipe-on-drop
// treatment as the master key. zeroize 1.8 implements Zeroize for
// String out of the box, so the derive Just Works.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct MasterPasswordHash(String);

impl MasterPasswordHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl SymmetricKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::Crypto {
                reason: format!("symmetric key must be 64 bytes, got {}", bytes.len()),
            });
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&bytes[..32]);
        mac.copy_from_slice(&bytes[32..]);
        Ok(Self { enc, mac })
    }

    /// Return the raw 64-byte representation (`enc || mac`) wrapped in
    /// `Zeroizing` so the caller's copy is wiped on drop. Reserved for
    /// the Yubikey unlock path, which has to wrap the user key under a
    /// hardware-derived key — every other consumer should keep the key
    /// behind the existing `decrypt_*` / `encrypt_*` helpers.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.enc);
        out[32..].copy_from_slice(&self.mac);
        Zeroizing::new(out)
    }

    /// A fresh random 64-byte key. Used for per-attachment keys, which
    /// Bitwarden generates client-side and ships wrapped under the
    /// cipher's key — the server never sees the file key.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 64]);
        rand::thread_rng().fill_bytes(bytes.as_mut());
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&bytes[..32]);
        mac.copy_from_slice(&bytes[32..]);
        Self { enc, mac }
    }
}

/// Absolute client-side floors on server-supplied KDF parameters. The prelogin
/// KDF settings come from the (untrusted, possibly MITM'd) server; without a
/// floor a hostile server could return `iterations = 1` and make offline
/// brute-force of the master password essentially free. These mirror the
/// minimums the official Bitwarden clients enforce.
const PBKDF2_MIN_ITERATIONS: u32 = 5_000;
const ARGON2_MIN_ITERATIONS: u32 = 2;
const ARGON2_MIN_MEMORY_MIB: u32 = 15;
const ARGON2_MIN_PARALLELISM: u32 = 1;

/// Run the configured KDF over `password` with `salt` used **verbatim**.
///
/// Callers resolve the salt themselves, because the two entry points
/// disagree about what it is: the master key follows Bitwarden and
/// salts with the e-mail address (hashed for Argon2id, raw for PBKDF2),
/// while an encrypted export file carries 16 random bytes of its own.
/// Folding both into one function and letting it decide would mean
/// re-deriving the wrong key for one of them.
///
/// `source` names where the parameters came from, so a rejection reads
/// as either a hostile server or a tampered file rather than a generic
/// "bad KDF".
fn derive_kdf_key(
    password: &SecretString,
    salt: &[u8],
    kdf: KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    source: &str,
) -> Result<[u8; 32]> {
    let password_bytes = password.expose_secret().as_bytes();

    match kdf {
        KdfType::Pbkdf2 => {
            if iterations < PBKDF2_MIN_ITERATIONS {
                return Err(Error::Crypto {
                    reason: format!(
                        "{source} PBKDF2 iterations {iterations} below the minimum {PBKDF2_MIN_ITERATIONS} — refusing to derive a weak key"
                    ),
                });
            }
            Ok(pbkdf2_hmac_array::<Sha256, 32>(
                password_bytes,
                salt,
                iterations,
            ))
        }
        KdfType::Argon2id => {
            let memory_mib = memory.ok_or_else(|| Error::Crypto {
                reason: "kdfMemory required for Argon2id".into(),
            })?;
            let parallelism = parallelism.ok_or_else(|| Error::Crypto {
                reason: "kdfParallelism required for Argon2id".into(),
            })?;

            if iterations < ARGON2_MIN_ITERATIONS
                || memory_mib < ARGON2_MIN_MEMORY_MIB
                || parallelism < ARGON2_MIN_PARALLELISM
            {
                return Err(Error::Crypto {
                    reason: format!(
                        "{source} Argon2id parameters (iterations={iterations}, memory={memory_mib} MiB, parallelism={parallelism}) below the minimums (iterations>={ARGON2_MIN_ITERATIONS}, memory>={ARGON2_MIN_MEMORY_MIB} MiB, parallelism>={ARGON2_MIN_PARALLELISM}) — refusing to derive a weak key"
                    ),
                });
            }

            let params = Params::new(
                memory_mib.saturating_mul(1024),
                iterations,
                parallelism,
                Some(32),
            )
            .map_err(|e| Error::Crypto {
                reason: format!("invalid Argon2 parameters: {e}"),
            })?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut out = [0u8; 32];
            argon
                .hash_password_into(password_bytes, salt, &mut out)
                .map_err(|e| Error::Crypto {
                    reason: format!("Argon2id derivation failed: {e}"),
                })?;
            Ok(out)
        }
    }
}

pub fn derive_master_key(
    password: &SecretString,
    email: &str,
    kdf: KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<MasterKey> {
    let email_lower = email.trim().to_ascii_lowercase();

    // Bitwarden salts PBKDF2 with the raw e-mail and Argon2id with its
    // SHA-256 digest. Not a design choice of ours — changing either
    // would make every existing vault undecryptable.
    let argon_salt: [u8; 32];
    let salt: &[u8] = match kdf {
        KdfType::Pbkdf2 => email_lower.as_bytes(),
        KdfType::Argon2id => {
            argon_salt = Sha256::digest(email_lower.as_bytes()).into();
            &argon_salt
        }
    };

    Ok(MasterKey(derive_kdf_key(
        password,
        salt,
        kdf,
        iterations,
        memory,
        parallelism,
        "server-supplied",
    )?))
}

/// Derive the key protecting an encrypted export file.
///
/// Same primitives as the master key, different salt discipline: the
/// file carries 16 random bytes and they are used exactly as written,
/// with no lowercasing and no hashing. That matters — an export has no
/// e-mail to anchor to, and a per-file random salt is what stops one
/// precomputation from covering every Clavix export in existence.
///
/// The same KDF floors apply. The parameters here come out of the file
/// being opened, which is attacker-controlled input in exactly the way
/// a hostile server's prelogin response is.
pub fn derive_file_key(
    password: &SecretString,
    salt: &[u8],
    kdf: KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<MasterKey> {
    // Argon2 itself rejects a salt under 8 bytes, but failing here says
    // "this file is malformed" instead of surfacing a KDF internal.
    if salt.len() < 16 {
        return Err(Error::Crypto {
            reason: format!(
                "export salt must be at least 16 bytes, got {} — refusing to derive a file key",
                salt.len()
            ),
        });
    }

    Ok(MasterKey(derive_kdf_key(
        password,
        salt,
        kdf,
        iterations,
        memory,
        parallelism,
        "file-supplied",
    )?))
}

pub fn derive_master_password_hash(
    master_key: &MasterKey,
    password: &SecretString,
) -> MasterPasswordHash {
    let hash =
        pbkdf2_hmac_array::<Sha256, 32>(&master_key.0, password.expose_secret().as_bytes(), 1);
    MasterPasswordHash(STANDARD.encode(hash))
}

pub fn stretch_master_key(master_key: &MasterKey) -> Result<SymmetricKey> {
    let hk = Hkdf::<Sha256>::from_prk(&master_key.0).map_err(|e| Error::Crypto {
        reason: format!("HKDF from_prk: {e}"),
    })?;
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    hk.expand(b"enc", &mut enc).map_err(|e| Error::Crypto {
        reason: format!("HKDF expand enc: {e}"),
    })?;
    hk.expand(b"mac", &mut mac).map_err(|e| Error::Crypto {
        reason: format!("HKDF expand mac: {e}"),
    })?;
    Ok(SymmetricKey { enc, mac })
}

pub enum EncString {
    AesCbc256HmacSha256 {
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
    },
    Rsa2048OaepSha1 {
        ciphertext: Vec<u8>,
    },
}

impl EncString {
    pub fn parse(s: &str) -> Result<Self> {
        let (kind_str, rest) = s.split_once('.').ok_or_else(|| Error::Crypto {
            reason: "EncString missing type prefix".into(),
        })?;

        match kind_str {
            "2" => {
                let parts: Vec<&str> = rest.split('|').collect();
                if parts.len() != 3 {
                    return Err(Error::Crypto {
                        reason: format!("EncString type 2 expects 3 parts, got {}", parts.len()),
                    });
                }
                let iv = STANDARD.decode(parts[0]).map_err(|e| Error::Crypto {
                    reason: format!("invalid IV base64: {e}"),
                })?;
                let ciphertext = STANDARD.decode(parts[1]).map_err(|e| Error::Crypto {
                    reason: format!("invalid ciphertext base64: {e}"),
                })?;
                let mac = STANDARD.decode(parts[2]).map_err(|e| Error::Crypto {
                    reason: format!("invalid MAC base64: {e}"),
                })?;
                if iv.len() != 16 {
                    return Err(Error::Crypto {
                        reason: format!("IV must be 16 bytes, got {}", iv.len()),
                    });
                }
                if mac.len() != 32 {
                    return Err(Error::Crypto {
                        reason: format!("MAC must be 32 bytes, got {}", mac.len()),
                    });
                }
                Ok(Self::AesCbc256HmacSha256 {
                    iv,
                    ciphertext,
                    mac,
                })
            }
            "4" => {
                let ciphertext = STANDARD.decode(rest).map_err(|e| Error::Crypto {
                    reason: format!("invalid RSA ciphertext base64: {e}"),
                })?;
                Ok(Self::Rsa2048OaepSha1 { ciphertext })
            }
            other => Err(Error::Crypto {
                reason: format!("unsupported EncString type: {other}"),
            }),
        }
    }

    pub fn decrypt_sym(&self, key: &SymmetricKey) -> Result<Vec<u8>> {
        match self {
            Self::AesCbc256HmacSha256 {
                iv,
                ciphertext,
                mac,
            } => {
                let mut hmac = HmacSha256::new_from_slice(&key.mac).map_err(|e| Error::Crypto {
                    reason: format!("HMAC init: {e}"),
                })?;
                hmac.update(iv);
                hmac.update(ciphertext);
                hmac.verify_slice(mac).map_err(|_| Error::Crypto {
                    reason: "MAC verification failed (wrong key or tampered data)".into(),
                })?;

                let cipher =
                    Aes256CbcDec::new_from_slices(&key.enc, iv).map_err(|e| Error::Crypto {
                        reason: format!("AES-CBC init: {e}"),
                    })?;
                cipher
                    .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                    .map_err(|e| Error::Crypto {
                        reason: format!("AES-CBC decrypt: {e}"),
                    })
            }
            Self::Rsa2048OaepSha1 { .. } => Err(Error::Crypto {
                reason: "RSA EncString cannot be decrypted with a symmetric key".into(),
            }),
        }
    }

    pub fn decrypt_rsa(&self, private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        match self {
            Self::Rsa2048OaepSha1 { ciphertext } => {
                // SHA-1 in OAEP is per the Bitwarden spec (fine). The residual
                // risk is RUSTSEC-2023-0071: the `rsa` crate's decryption is not
                // constant-time (Marvin timing side-channel), with no fixed 0.9.x
                // release yet. We reach this only for server-supplied type-4
                // EncStrings (org key unwrap), over HTTPS, with no attacker-facing
                // oracle — exposure is low. Tracked/ignored in ci.yml's cargo-audit
                // step; upgrade the crate as soon as a constant-time release lands.
                let padding = Oaep::new::<Sha1>();
                private_key
                    .decrypt(padding, ciphertext)
                    .map_err(|e| Error::Crypto {
                        reason: format!("RSA-OAEP-SHA1 decrypt: {e}"),
                    })
            }
            Self::AesCbc256HmacSha256 { .. } => Err(Error::Crypto {
                reason: "symmetric EncString cannot be decrypted with an RSA key".into(),
            }),
        }
    }

    pub fn decrypt_string_sym(&self, key: &SymmetricKey) -> Result<String> {
        let bytes = self.decrypt_sym(key)?;
        String::from_utf8(bytes).map_err(|e| Error::Crypto {
            reason: format!("decrypted bytes are not valid UTF-8: {e}"),
        })
    }
}

pub fn decrypt_user_key(master_key: &MasterKey, token_set_key: &str) -> Result<SymmetricKey> {
    let stretched = stretch_master_key(master_key)?;
    let encstring = EncString::parse(token_set_key)?;
    let bytes = encstring.decrypt_sym(&stretched)?;
    SymmetricKey::from_bytes(&bytes)
}

pub fn decrypt_private_key(
    user_key: &SymmetricKey,
    encrypted_pkcs8: &str,
) -> Result<RsaPrivateKey> {
    let encstring = EncString::parse(encrypted_pkcs8)?;
    let pkcs8_bytes = encstring.decrypt_sym(user_key)?;
    RsaPrivateKey::from_pkcs8_der(&pkcs8_bytes).map_err(|e| Error::Crypto {
        reason: format!("invalid PKCS8 private key: {e}"),
    })
}

pub fn decrypt_org_key(
    user_key: &SymmetricKey,
    private_key: Option<&RsaPrivateKey>,
    encrypted: &str,
) -> Result<SymmetricKey> {
    let encstring = EncString::parse(encrypted)?;
    let bytes = match &encstring {
        EncString::AesCbc256HmacSha256 { .. } => encstring.decrypt_sym(user_key)?,
        EncString::Rsa2048OaepSha1 { .. } => {
            let pk = private_key.ok_or_else(|| Error::Crypto {
                reason:
                    "RSA-encrypted org key requires the user's private key, which is not available"
                        .into(),
            })?;
            encstring.decrypt_rsa(pk)?
        }
    };
    SymmetricKey::from_bytes(&bytes)
}

pub fn decrypt_name(encrypted: &str, key: &SymmetricKey) -> Result<String> {
    EncString::parse(encrypted)?.decrypt_string_sym(key)
}

/// Unwrap a cipher's own encryption key ("cipher key encryption").
///
/// Bitwarden may give an individual cipher its own symmetric key, shipped
/// in the cipher's `key` field and wrapped under the key that owns the
/// item — the org key for an org item, the user key for a personal one.
/// When that field is present, *every* field of the cipher (its name
/// included) is encrypted under the item key rather than the owning key,
/// so decrypting with the owning key fails MAC verification.
pub fn decrypt_cipher_key(owning_key: &SymmetricKey, encrypted: &str) -> Result<SymmetricKey> {
    let bytes = EncString::parse(encrypted)?.decrypt_sym(owning_key)?;
    SymmetricKey::from_bytes(&bytes)
}

/// Re-wrap an item key under a different owning key. Used when sharing a
/// cipher into an org: the fields stay encrypted under the item key, and
/// only the wrapper changes from the user key to the org key.
pub fn encrypt_cipher_key(item_key: &SymmetricKey, owning_key: &SymmetricKey) -> Result<String> {
    encrypt_bytes(item_key.to_bytes().as_slice(), owning_key)
}

pub fn reencrypt_with_key(
    encrypted: &str,
    from_key: &SymmetricKey,
    to_key: &SymmetricKey,
) -> Result<String> {
    let plaintext = EncString::parse(encrypted)?.decrypt_string_sym(from_key)?;
    encrypt_string(&plaintext, to_key)
}

pub fn encrypt_string(plaintext: &str, key: &SymmetricKey) -> Result<String> {
    encrypt_bytes(plaintext.as_bytes(), key)
}

pub fn encrypt_bytes(plaintext: &[u8], key: &SymmetricKey) -> Result<String> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Aes256CbcEnc::new_from_slices(&key.enc, &iv).map_err(|e| Error::Crypto {
        reason: format!("AES-CBC encrypt init: {e}"),
    })?;
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut mac = HmacSha256::new_from_slice(&key.mac).map_err(|e| Error::Crypto {
        reason: format!("HMAC init: {e}"),
    })?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(&ciphertext),
        STANDARD.encode(mac_bytes)
    ))
}

/// Attachment payloads travel in Bitwarden's *binary* EncString layout,
/// not the base64 `2.iv|ct|mac` text form: one type byte, then the raw
/// IV, MAC and ciphertext back to back.
///
///   [0]      encryption type (2 = AesCbc256_HmacSha256_B64)
///   [1..17]  IV
///   [17..49] HMAC-SHA256 over IV || ciphertext
///   [49..]   AES-256-CBC ciphertext
///
/// A 5 MB file would otherwise pay a 33 % base64 tax in both directions.
const ENC_TYPE_AES_CBC_HMAC: u8 = 2;
const BUFFER_HEADER_LEN: usize = 1 + 16 + 32;

pub fn encrypt_buffer(plaintext: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Aes256CbcEnc::new_from_slices(&key.enc, &iv).map_err(|e| Error::Crypto {
        reason: format!("AES-CBC encrypt init: {e}"),
    })?;
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut mac = HmacSha256::new_from_slice(&key.mac).map_err(|e| Error::Crypto {
        reason: format!("HMAC init: {e}"),
    })?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(BUFFER_HEADER_LEN + ciphertext.len());
    out.push(ENC_TYPE_AES_CBC_HMAC);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&mac_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_buffer(buffer: &[u8], key: &SymmetricKey) -> Result<Vec<u8>> {
    // Length and type are checked before anything is fed to the cipher:
    // this input comes straight off the wire, and a truncated download
    // must be an error rather than a panic on a slice index.
    if buffer.len() <= BUFFER_HEADER_LEN {
        return Err(Error::Crypto {
            reason: format!(
                "encrypted attachment too short: {} bytes, header alone is {BUFFER_HEADER_LEN}",
                buffer.len()
            ),
        });
    }
    if buffer[0] != ENC_TYPE_AES_CBC_HMAC {
        return Err(Error::Crypto {
            reason: format!("unsupported attachment encryption type: {}", buffer[0]),
        });
    }
    let iv = &buffer[1..17];
    let expected_mac = &buffer[17..BUFFER_HEADER_LEN];
    let ciphertext = &buffer[BUFFER_HEADER_LEN..];

    let mut hmac = HmacSha256::new_from_slice(&key.mac).map_err(|e| Error::Crypto {
        reason: format!("HMAC init: {e}"),
    })?;
    hmac.update(iv);
    hmac.update(ciphertext);
    hmac.verify_slice(expected_mac).map_err(|_| Error::Crypto {
        reason: "MAC verification failed on attachment (wrong key or tampered file)".into(),
    })?;

    let cipher = Aes256CbcDec::new_from_slices(&key.enc, iv).map_err(|e| Error::Crypto {
        reason: format!("AES-CBC init: {e}"),
    })?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| Error::Crypto {
            reason: format!("AES-CBC decrypt: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_sym_key(seed: u8) -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8)
                .wrapping_mul(seed.wrapping_add(1))
                .wrapping_add(seed);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn split_parts(encoded: &str) -> (String, String, String) {
        let rest = encoded.strip_prefix("2.").expect("type-2 prefix");
        let parts: Vec<&str> = rest.split('|').collect();
        assert_eq!(parts.len(), 3, "type-2 EncString must have 3 b64 parts");
        (parts[0].into(), parts[1].into(), parts[2].into())
    }

    #[test]
    fn encrypt_then_decrypt_string_roundtrip() {
        let key = deterministic_sym_key(7);
        let plaintext = "héllo world ✨ — multi-byte content";
        let encoded = encrypt_string(plaintext, &key).expect("encrypt");
        let parsed = EncString::parse(&encoded).expect("parse");
        let decoded = parsed.decrypt_string_sym(&key).expect("decrypt");
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn encrypt_then_decrypt_bytes_roundtrip() {
        let key = deterministic_sym_key(11);
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let encoded = encrypt_bytes(&plaintext, &key).expect("encrypt");
        let parsed = EncString::parse(&encoded).expect("parse");
        let decoded = parsed.decrypt_sym(&key).expect("decrypt");
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn encrypt_produces_unique_iv_each_call() {
        let key = deterministic_sym_key(3);
        let a = encrypt_string("same plaintext", &key).unwrap();
        let b = encrypt_string("same plaintext", &key).unwrap();
        assert_ne!(a, b);
        let (iv_a, _, _) = split_parts(&a);
        let (iv_b, _, _) = split_parts(&b);
        assert_ne!(iv_a, iv_b);
    }

    #[test]
    fn decrypt_rejects_tampered_mac() {
        let key = deterministic_sym_key(5);
        let encoded = encrypt_string("secret", &key).unwrap();
        let (iv, ct, mac) = split_parts(&encoded);
        let mut mac_bytes = STANDARD.decode(&mac).unwrap();
        mac_bytes[0] ^= 0x01;
        let tampered = format!("2.{iv}|{ct}|{}", STANDARD.encode(&mac_bytes));
        let parsed = EncString::parse(&tampered).unwrap();
        assert!(parsed.decrypt_sym(&key).is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = deterministic_sym_key(9);
        let encoded = encrypt_string("a long enough secret to span a block", &key).unwrap();
        let (iv, ct, mac) = split_parts(&encoded);
        let mut ct_bytes = STANDARD.decode(&ct).unwrap();
        ct_bytes[0] ^= 0x01;
        let tampered = format!("2.{iv}|{}|{mac}", STANDARD.encode(&ct_bytes));
        let parsed = EncString::parse(&tampered).unwrap();
        assert!(parsed.decrypt_sym(&key).is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_iv() {
        let key = deterministic_sym_key(13);
        let encoded = encrypt_string("a payload", &key).unwrap();
        let (iv, ct, mac) = split_parts(&encoded);
        let mut iv_bytes = STANDARD.decode(&iv).unwrap();
        iv_bytes[0] ^= 0x01;
        let tampered = format!("2.{}|{ct}|{mac}", STANDARD.encode(&iv_bytes));
        let parsed = EncString::parse(&tampered).unwrap();
        assert!(parsed.decrypt_sym(&key).is_err());
    }

    #[test]
    fn parse_rejects_bad_iv_length() {
        let key = deterministic_sym_key(17);
        let encoded = encrypt_string("payload", &key).unwrap();
        let (_, ct, mac) = split_parts(&encoded);
        let short_iv = STANDARD.encode([0u8; 8]);
        let bad = format!("2.{short_iv}|{ct}|{mac}");
        assert!(EncString::parse(&bad).is_err());
    }

    #[test]
    fn parse_rejects_bad_mac_length() {
        let key = deterministic_sym_key(19);
        let encoded = encrypt_string("payload", &key).unwrap();
        let (iv, ct, _) = split_parts(&encoded);
        let short_mac = STANDARD.encode([0u8; 16]);
        let bad = format!("2.{iv}|{ct}|{short_mac}");
        assert!(EncString::parse(&bad).is_err());
    }

    #[test]
    fn parse_rejects_missing_type_separator() {
        assert!(EncString::parse("foobar").is_err());
    }

    #[test]
    fn parse_rejects_unknown_prefix() {
        assert!(EncString::parse("9.somecontent").is_err());
        assert!(EncString::parse("0.aGVsbG8=").is_err());
    }

    #[test]
    fn parse_rejects_invalid_base64() {
        assert!(EncString::parse("2.!!!|@@@|###").is_err());
    }

    #[test]
    fn parse_rejects_wrong_part_count() {
        let iv = STANDARD.encode([0u8; 16]);
        let mac = STANDARD.encode([0u8; 32]);
        let ct = STANDARD.encode([0u8; 16]);
        assert!(EncString::parse(&format!("2.{iv}|{ct}")).is_err());
        assert!(EncString::parse(&format!("2.{iv}|{ct}|{mac}|extra")).is_err());
    }

    #[test]
    fn symmetric_key_from_bytes_validates_length() {
        assert!(SymmetricKey::from_bytes(&[0u8; 32]).is_err());
        assert!(SymmetricKey::from_bytes(&[0u8; 63]).is_err());
        assert!(SymmetricKey::from_bytes(&[0u8; 65]).is_err());
        assert!(SymmetricKey::from_bytes(&[0u8; 64]).is_ok());
    }

    #[test]
    fn pbkdf2_normalizes_email_case_and_whitespace() {
        let pwd: SecretString = "password".to_string().into();
        let key_a =
            derive_master_key(&pwd, "User@Example.COM", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let key_b = derive_master_key(
            &pwd,
            "  user@example.com  ",
            KdfType::Pbkdf2,
            5000,
            None,
            None,
        )
        .unwrap();
        let h_a = derive_master_password_hash(&key_a, &pwd);
        let h_b = derive_master_password_hash(&key_b, &pwd);
        assert_eq!(h_a.as_str(), h_b.as_str());
    }

    #[test]
    fn pbkdf2_iterations_change_output() {
        let pwd: SecretString = "password".to_string().into();
        let k1 = derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let k2 = derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 6000, None, None).unwrap();
        let h1 = derive_master_password_hash(&k1, &pwd);
        let h2 = derive_master_password_hash(&k2, &pwd);
        assert_ne!(h1.as_str(), h2.as_str());
    }

    // Known-answer vector computed with an INDEPENDENT implementation
    // (Python `hashlib.pbkdf2_hmac`), so a divergence from the Bitwarden
    // scheme — wrong salt (must be lower-cased email), wrong hash (SHA-256),
    // wrong output length (32), or wrong master-password-hash construction —
    // fails here even though the self-consistency tests above would still pass.
    #[test]
    fn derive_master_key_matches_independent_pbkdf2_known_answer() {
        let pwd: SecretString = "correct horse battery staple".to_string().into();
        // email is intentionally mixed-case + not trimmed to exercise the
        // trim + lower-case normalisation that feeds the PBKDF2 salt.
        let mk =
            derive_master_key(&pwd, "User@Example.COM", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let got_hex: String = mk.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got_hex,
            "52ce2d33e007a7c15b3e3083c551fcff97da83045fa80cc6bbbd2cbc52c6f084"
        );
        // masterPasswordHash = base64(PBKDF2-HMAC-SHA256(masterKey, password, 1)).
        let mph = derive_master_password_hash(&mk, &pwd);
        assert_eq!(mph.as_str(), "0FMeontUyfpu9Ga/DvERL9LMAXg9KB82VK6UqHdnKko=");
    }

    // The Argon2id counterpart of the vector above, computed with the
    // reference C implementation (`argon2-cffi`'s `hash_secret_raw`), not
    // with this crate. It is what stops a major bump of `argon2` from
    // silently changing what we derive: every parameter-validation test
    // below still passes if the output bytes move, and a moved output
    // means every existing Argon2id vault stops unlocking.
    #[test]
    fn derive_master_key_matches_independent_argon2id_known_answer() {
        let pwd: SecretString = "correct horse battery staple".to_string().into();
        // Same mixed-case, untrimmed email as the PBKDF2 vector: the salt is
        // SHA-256 of the *normalised* address, so this pins the normalisation
        // and the digest-as-salt rule at the same time.
        let mk = derive_master_key(
            &pwd,
            "User@Example.COM",
            KdfType::Argon2id,
            3,
            Some(16),
            Some(2),
        )
        .unwrap();
        let got_hex: String = mk.0.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got_hex,
            "3b8af27eff0eee164d9d4be6313a684cafb14f646af4cad056c51ff0d7155dc9"
        );
    }

    #[test]
    fn derive_master_key_rejects_pbkdf2_below_the_floor() {
        // A hostile/MITM server returning a tiny iteration count must be
        // refused rather than deriving a brute-forceable master key.
        let pwd: SecretString = "password".to_string().into();
        assert!(derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 1, None, None).is_err());
        assert!(derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 4999, None, None).is_err());
        assert!(derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 5000, None, None).is_ok());
    }

    #[test]
    fn derive_master_key_rejects_weak_argon2id_params() {
        let pwd: SecretString = "password".to_string().into();
        // Below memory floor (15 MiB).
        assert!(
            derive_master_key(&pwd, "u@e.com", KdfType::Argon2id, 3, Some(8), Some(4)).is_err()
        );
        // Below iteration floor.
        assert!(
            derive_master_key(&pwd, "u@e.com", KdfType::Argon2id, 1, Some(64), Some(4)).is_err()
        );
        // At the minimums it is accepted.
        assert!(
            derive_master_key(&pwd, "u@e.com", KdfType::Argon2id, 2, Some(15), Some(1)).is_ok()
        );
    }

    #[test]
    fn pbkdf2_different_passwords_diverge() {
        let p1: SecretString = "password-one".to_string().into();
        let p2: SecretString = "password-two".to_string().into();
        let k1 = derive_master_key(&p1, "u@e.com", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let k2 = derive_master_key(&p2, "u@e.com", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let h1 = derive_master_password_hash(&k1, &p1);
        let h2 = derive_master_password_hash(&k2, &p2);
        assert_ne!(h1.as_str(), h2.as_str());
    }

    #[test]
    fn argon2id_requires_memory_and_parallelism() {
        let pwd: SecretString = "password".to_string().into();
        assert!(derive_master_key(&pwd, "u@e.com", KdfType::Argon2id, 2, None, Some(2)).is_err());
        assert!(derive_master_key(&pwd, "u@e.com", KdfType::Argon2id, 2, Some(15), None).is_err());
        assert!(
            derive_master_key(&pwd, "u@e.com", KdfType::Argon2id, 2, Some(15), Some(2)).is_ok()
        );
    }

    #[test]
    fn master_password_hash_is_b64_32_bytes() {
        let pwd: SecretString = "password".to_string().into();
        let mk = derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let hash = derive_master_password_hash(&mk, &pwd);
        let raw = STANDARD
            .decode(hash.as_str())
            .expect("hash must be valid base64");
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn stretch_master_key_is_deterministic() {
        let pwd: SecretString = "password".to_string().into();
        let mk = derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let s1 = stretch_master_key(&mk).unwrap();
        let s2 = stretch_master_key(&mk).unwrap();
        let payload = "deterministic check";
        let enc = encrypt_string(payload, &s1).unwrap();
        let dec = EncString::parse(&enc)
            .unwrap()
            .decrypt_string_sym(&s2)
            .unwrap();
        assert_eq!(dec, payload);
    }

    #[test]
    fn decrypt_user_key_roundtrip() {
        let pwd: SecretString = "password".to_string().into();
        let mk = derive_master_key(&pwd, "u@e.com", KdfType::Pbkdf2, 5000, None, None).unwrap();
        let stretched = stretch_master_key(&mk).unwrap();
        let user_key_bytes = [42u8; 64];
        let encoded = encrypt_bytes(&user_key_bytes, &stretched).unwrap();
        let recovered = decrypt_user_key(&mk, &encoded).expect("recovers user key");
        // Probe: original and recovered keys must be byte-identical → encrypting with
        // one and decrypting with the other must work.
        let original_user_key = SymmetricKey::from_bytes(&user_key_bytes).unwrap();
        let probe = encrypt_string("probe", &recovered).unwrap();
        let dec = EncString::parse(&probe)
            .unwrap()
            .decrypt_string_sym(&original_user_key)
            .unwrap();
        assert_eq!(dec, "probe");
    }

    // ── Property-based tests on EncString parsing/round-trip ──────────
    //
    // Goal: anything the server hands us as an EncString is adversarial
    // input. The parser must never panic and must reject malformed
    // values; the encrypt/parse/decrypt round-trip must be lossless for
    // any plaintext; and any single-bit flip in IV/ciphertext/MAC must
    // be caught by the HMAC.
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            // Garbage input must produce a Result, not a panic. The
            // server can hand us anything; we must survive it.
            #[test]
            fn parse_never_panics_on_arbitrary_strings(s in ".{0,256}") {
                let _ = EncString::parse(&s);
            }

            // encrypt → parse → decrypt is the identity for any byte
            // sequence we might throw at it (binary safe, length safe).
            #[test]
            fn encrypt_parse_decrypt_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
                let key = deterministic_sym_key(31);
                let encoded = encrypt_bytes(&plaintext, &key).expect("encrypt");
                let parsed = EncString::parse(&encoded).expect("parse");
                let decoded = parsed.decrypt_sym(&key).expect("decrypt");
                prop_assert_eq!(decoded, plaintext);
            }

            // Flip exactly one bit somewhere in the IV / ciphertext /
            // MAC base64 portion of a valid type-2 EncString. After
            // re-parsing, the HMAC must reject the tampered value.
            //
            // We flip a bit in the *raw* (decoded) bytes rather than in
            // the base64 string so we don't accidentally produce
            // unparseable b64 — this exercises the HMAC, not the
            // base64 decoder (which we cover separately).
            #[test]
            fn single_bit_flip_breaks_decryption(
                plaintext in proptest::collection::vec(any::<u8>(), 1..256),
                part_idx in 0usize..3,
                byte_idx in any::<u32>(),
                bit_idx in 0u8..8,
            ) {
                let key = deterministic_sym_key(37);
                let encoded = encrypt_bytes(&plaintext, &key).expect("encrypt");
                let (iv_b64, ct_b64, mac_b64) = split_parts(&encoded);

                let (target, others): (String, [String; 2]) = match part_idx {
                    0 => (iv_b64, [ct_b64, mac_b64]),
                    1 => (ct_b64, [iv_b64, mac_b64]),
                    _ => (mac_b64, [iv_b64, ct_b64]),
                };

                let mut bytes = STANDARD.decode(&target).expect("valid b64");
                let i = (byte_idx as usize) % bytes.len();
                bytes[i] ^= 1u8 << bit_idx;
                let tampered_b64 = STANDARD.encode(&bytes);

                let tampered = match part_idx {
                    0 => format!("2.{tampered_b64}|{}|{}", others[0], others[1]),
                    1 => format!("2.{}|{tampered_b64}|{}", others[0], others[1]),
                    _ => format!("2.{}|{}|{tampered_b64}", others[0], others[1]),
                };

                // Tampered IV may parse fine (still 16 bytes) — what
                // matters is that decryption fails, not where exactly.
                let result = EncString::parse(&tampered).and_then(|p| p.decrypt_sym(&key));
                prop_assert!(result.is_err(), "MAC should have rejected single-bit flip");
            }
        }
    }

    #[test]
    fn reencrypt_with_key_pivots_value_correctly() {
        let key_a = deterministic_sym_key(23);
        let key_b = deterministic_sym_key(31);
        let original = "secret value";
        let enc_a = encrypt_string(original, &key_a).unwrap();
        let enc_b = reencrypt_with_key(&enc_a, &key_a, &key_b).unwrap();
        // Old key MUST NOT be able to decrypt the re-encrypted ciphertext.
        assert!(EncString::parse(&enc_b)
            .unwrap()
            .decrypt_string_sym(&key_a)
            .is_err());
        let dec = EncString::parse(&enc_b)
            .unwrap()
            .decrypt_string_sym(&key_b)
            .unwrap();
        assert_eq!(dec, original);
    }

    #[test]
    fn decrypt_sym_rejects_rsa_encstring() {
        let key = deterministic_sym_key(2);
        let rsa_enc = EncString::Rsa2048OaepSha1 {
            ciphertext: vec![0u8; 256],
        };
        assert!(rsa_enc.decrypt_sym(&key).is_err());
    }

    #[test]
    fn decrypt_string_sym_rejects_non_utf8_payload() {
        let key = deterministic_sym_key(4);
        let invalid_utf8 = vec![0xff, 0xfe, 0xfd];
        let encoded = encrypt_bytes(&invalid_utf8, &key).unwrap();
        let parsed = EncString::parse(&encoded).unwrap();
        assert!(parsed.decrypt_sym(&key).is_ok());
        assert!(parsed.decrypt_string_sym(&key).is_err());
    }

    // ============ attachment buffers ============

    #[test]
    fn buffer_round_trips_arbitrary_bytes() {
        let key = deterministic_sym_key(7);
        // Deliberately not a multiple of the AES block size, and with a
        // NUL and a high byte in it: attachment payloads are arbitrary
        // binary, not text.
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let encrypted = encrypt_buffer(&payload, &key).unwrap();

        assert_eq!(encrypted[0], 2, "type byte");
        assert_eq!(encrypted.len() % 16, BUFFER_HEADER_LEN % 16);
        assert_ne!(&encrypted[BUFFER_HEADER_LEN..], &payload[..]);

        assert_eq!(decrypt_buffer(&encrypted, &key).unwrap(), payload);
    }

    #[test]
    fn buffer_round_trips_an_empty_payload() {
        let key = deterministic_sym_key(8);
        let encrypted = encrypt_buffer(&[], &key).unwrap();
        assert_eq!(decrypt_buffer(&encrypted, &key).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn buffer_uses_a_fresh_iv_per_call() {
        let key = deterministic_sym_key(9);
        let a = encrypt_buffer(b"same input", &key).unwrap();
        let b = encrypt_buffer(b"same input", &key).unwrap();
        assert_ne!(a, b, "a reused IV would leak that two files are identical");
    }

    #[test]
    fn buffer_rejects_a_tampered_payload() {
        let key = deterministic_sym_key(10);
        let mut encrypted = encrypt_buffer(b"invoice.pdf contents", &key).unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(decrypt_buffer(&encrypted, &key).is_err());
    }

    #[test]
    fn buffer_rejects_the_wrong_key() {
        let key = deterministic_sym_key(11);
        let other = deterministic_sym_key(12);
        let encrypted = encrypt_buffer(b"secret", &key).unwrap();
        assert!(decrypt_buffer(&encrypted, &other).is_err());
    }

    #[test]
    fn buffer_rejects_truncated_and_unknown_input() {
        let key = deterministic_sym_key(13);
        let encrypted = encrypt_buffer(b"payload", &key).unwrap();

        // A download cut short must be an error, never a panic on a slice.
        for len in [0, 1, BUFFER_HEADER_LEN - 1, BUFFER_HEADER_LEN] {
            assert!(
                decrypt_buffer(&encrypted[..len], &key).is_err(),
                "len {len}"
            );
        }

        let mut wrong_type = encrypted.clone();
        wrong_type[0] = 6;
        assert!(decrypt_buffer(&wrong_type, &key).is_err());
    }

    #[test]
    fn generated_keys_differ_and_are_usable() {
        let a = SymmetricKey::generate();
        let b = SymmetricKey::generate();
        assert_ne!(a.to_bytes().as_slice(), b.to_bytes().as_slice());
        let encrypted = encrypt_buffer(b"file", &a).unwrap();
        assert_eq!(decrypt_buffer(&encrypted, &a).unwrap(), b"file");
        assert!(decrypt_buffer(&encrypted, &b).is_err());
    }
}
