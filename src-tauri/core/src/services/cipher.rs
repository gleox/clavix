use crate::crypto::{
    decrypt_cipher_key, decrypt_name, encrypt_cipher_key, encrypt_string, reencrypt_with_key,
    SymmetricKey,
};
use crate::error::{Error, Result};
use crate::models::{
    CardInput, Cipher, CipherCreateInput, CipherType, CustomFieldInput, IdentityInput, LoginInput,
    SshKeyInput,
};
use std::collections::HashMap;

/// The key a cipher is *owned* by: the org key for an org item, the user
/// key otherwise. Falls back to the user key when the org key is missing
/// so callers still produce a `[decrypt failed]` placeholder instead of
/// aborting the whole listing.
pub fn owning_key<'a>(
    cipher: &Cipher,
    user_key: &'a SymmetricKey,
    org_keys: &'a HashMap<String, SymmetricKey>,
) -> &'a SymmetricKey {
    cipher
        .organization_id
        .as_ref()
        .and_then(|oid| org_keys.get(oid))
        .unwrap_or(user_key)
}

/// The key a cipher's *fields* are encrypted under.
///
/// Same as the owning key, except for items that carry their own key
/// (Bitwarden "cipher key encryption"), where the owning key only unwraps
/// the item key and every field hangs off the latter. Returns `None` for
/// the common no-item-key case so the caller can keep borrowing the
/// owning key rather than cloning it.
///
/// An item key that fails to unwrap yields `None`, degrading to the same
/// `[decrypt failed]` placeholder as any other undecryptable field — one
/// broken item must not take the listing down with it.
pub fn item_key(cipher: &Cipher, owning_key: &SymmetricKey) -> Option<SymmetricKey> {
    cipher
        .key
        .as_deref()
        .and_then(|k| decrypt_cipher_key(owning_key, k).ok())
}

fn enc_opt(s: Option<&str>, key: &SymmetricKey) -> Result<Option<String>> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| encrypt_string(s, key))
        .transpose()
}

fn enc_opt_raw(s: Option<&str>, key: &SymmetricKey) -> Result<Option<String>> {
    // Same as enc_opt but preserves whitespace (for multi-line SSH keys, notes,
    // passwords).  Only skips `None` and empty strings.
    s.filter(|s| !s.is_empty())
        .map(|s| encrypt_string(s, key))
        .transpose()
}

fn encrypt_login(login: &LoginInput, key: &SymmetricKey) -> Result<serde_json::Value> {
    let uris_val: Vec<serde_json::Value> = login
        .uris
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|u| -> Result<serde_json::Value> {
            Ok(serde_json::json!({
                "uri": encrypt_string(u, key)?,
                "match": serde_json::Value::Null,
            }))
        })
        .collect::<Result<_>>()?;

    Ok(serde_json::json!({
        "username": enc_opt(login.username.as_deref(), key)?,
        "password": enc_opt_raw(login.password.as_deref(), key)?,
        "uris": uris_val,
        "totp": enc_opt(login.totp.as_deref(), key)?,
    }))
}

fn encrypt_card(card: &CardInput, key: &SymmetricKey) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "cardholderName": enc_opt(card.cardholder_name.as_deref(), key)?,
        "brand": enc_opt(card.brand.as_deref(), key)?,
        "number": enc_opt(card.number.as_deref(), key)?,
        "expMonth": enc_opt(card.exp_month.as_deref(), key)?,
        "expYear": enc_opt(card.exp_year.as_deref(), key)?,
        "code": enc_opt(card.code.as_deref(), key)?,
    }))
}

fn encrypt_identity(id: &IdentityInput, key: &SymmetricKey) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "title": enc_opt(id.title.as_deref(), key)?,
        "firstName": enc_opt(id.first_name.as_deref(), key)?,
        "middleName": enc_opt(id.middle_name.as_deref(), key)?,
        "lastName": enc_opt(id.last_name.as_deref(), key)?,
        "address1": enc_opt(id.address1.as_deref(), key)?,
        "address2": enc_opt(id.address2.as_deref(), key)?,
        "address3": enc_opt(id.address3.as_deref(), key)?,
        "city": enc_opt(id.city.as_deref(), key)?,
        "state": enc_opt(id.state.as_deref(), key)?,
        "postalCode": enc_opt(id.postal_code.as_deref(), key)?,
        "country": enc_opt(id.country.as_deref(), key)?,
        "company": enc_opt(id.company.as_deref(), key)?,
        "email": enc_opt(id.email.as_deref(), key)?,
        "phone": enc_opt(id.phone.as_deref(), key)?,
        "ssn": enc_opt(id.ssn.as_deref(), key)?,
        "username": enc_opt(id.username.as_deref(), key)?,
        "passportNumber": enc_opt(id.passport_number.as_deref(), key)?,
        "licenseNumber": enc_opt(id.license_number.as_deref(), key)?,
    }))
}

fn encrypt_ssh_key(ssh: &SshKeyInput, key: &SymmetricKey) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "privateKey": enc_opt_raw(ssh.private_key.as_deref(), key)?,
        "publicKey": enc_opt(ssh.public_key.as_deref(), key)?,
        "keyFingerprint": enc_opt(ssh.key_fingerprint.as_deref(), key)?,
    }))
}

/// Custom fields, encrypted under the item's key.
///
/// `name` and `value` are EncStrings; `type` and `linkedId` are plaintext
/// metadata. Boolean fields (type 2) carry the literal strings "true" /
/// "false", so they go through the same encryption as any text value.
/// Empty names are kept: Bitwarden allows an unnamed field and dropping
/// it here would silently delete data on the next save.
fn encrypt_fields(
    fields: &[CustomFieldInput],
    key: &SymmetricKey,
) -> Result<Vec<serde_json::Value>> {
    fields
        .iter()
        .map(|f| -> Result<serde_json::Value> {
            Ok(serde_json::json!({
                "type": f.kind,
                "name": enc_opt_raw(f.name.as_deref(), key)?,
                "value": enc_opt_raw(f.value.as_deref(), key)?,
                "linkedId": f.linked_id,
            }))
        })
        .collect()
}

pub fn build_cipher_body(
    input: &CipherCreateInput,
    key: &SymmetricKey,
) -> Result<serde_json::Value> {
    let name_enc = encrypt_string(&input.name, key)?;
    let notes_enc = enc_opt_raw(input.notes.as_deref(), key)?;

    let mut body = serde_json::json!({
        "type": input.cipher_type,
        "name": name_enc,
        "notes": notes_enc,
        "folderId": input.folder_id,
        "favorite": input.favorite,
        "organizationId": input.organization_id,
        "fields": encrypt_fields(&input.fields, key)?,
        "reprompt": u8::from(input.reprompt),
    });
    let obj = body.as_object_mut().expect("json! returned a map");

    match input.cipher_type {
        1 => {
            let login = input.login.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=1 (Login) requires a login field".into(),
            })?;
            obj.insert("login".into(), encrypt_login(login, key)?);
        }
        2 => {
            // SecureNote: Bitwarden expects a SecureNote sub-object with type=0.
            obj.insert("secureNote".into(), serde_json::json!({ "type": 0 }));
        }
        3 => {
            let card = input.card.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=3 (Card) requires a card field".into(),
            })?;
            obj.insert("card".into(), encrypt_card(card, key)?);
        }
        4 => {
            let id = input.identity.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=4 (Identity) requires an identity field".into(),
            })?;
            obj.insert("identity".into(), encrypt_identity(id, key)?);
        }
        5 => {
            let ssh = input.ssh_key.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=5 (SshKey) requires an sshKey field".into(),
            })?;
            obj.insert("sshKey".into(), encrypt_ssh_key(ssh, key)?);
        }
        n => {
            return Err(Error::Storage {
                reason: format!("unsupported cipher type: {n}"),
            });
        }
    }

    Ok(body)
}

/// Backwards-compatible alias — used to be the only builder.  Kept so
/// the existing `create_login_cipher` / `update_login_cipher` Tauri
/// commands stay valid.
pub fn build_login_cipher_body(
    input: &CipherCreateInput,
    key: &SymmetricKey,
) -> Result<serde_json::Value> {
    // Force Login type so an older frontend that omits `cipher_type`
    // still ends up creating a Login.
    let mut input = input.clone();
    input.cipher_type = 1;
    build_cipher_body(&input, key)
}

/// The body for an update (PUT /ciphers/{id}), which is `build_cipher_body`
/// plus the two things only the *existing* cipher can supply.
///
/// The cipher PUT has replace semantics: whatever the body omits is gone
/// from the server copy. Until this existed, saving an item through the
/// editor silently deleted its password history — the editor never had a
/// reason to know about it, so it could not send it back.
///
/// It also does what every Bitwarden client does on save: when the
/// password changed, the previous one is pushed onto the history. The old
/// value is echoed as-is, still encrypted: it is already under `key` (the
/// same key the new body is written with), so there is nothing to
/// re-encrypt and no plaintext to handle.
///
/// `now` is passed in rather than read from the clock so the behaviour is
/// testable.
pub fn build_update_cipher_body(
    input: &CipherCreateInput,
    key: &SymmetricKey,
    existing: &Cipher,
    now: &str,
) -> Result<serde_json::Value> {
    let mut body = build_cipher_body(input, key)?;

    let mut history: Vec<serde_json::Value> = existing
        .password_history
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|h| {
            h.password
                .as_ref()
                .map(|p| serde_json::json!({ "password": p, "lastUsedDate": h.last_used_date }))
        })
        .collect();

    let previous = existing.login.as_ref().and_then(|l| l.password.as_deref());
    if let Some(previous_enc) = previous {
        let previous_plain = decrypt_name(previous_enc, key).ok();
        let next_plain = input
            .login
            .as_ref()
            .and_then(|l| l.password.as_deref())
            .filter(|p| !p.is_empty());
        // Compare plaintext, not ciphertext: a fresh IV on every write
        // means the same password re-encrypts to a different string, and
        // comparing those would push a history entry on every single save.
        // An old password we cannot decrypt is left alone rather than
        // recorded blind.
        if let Some(old) = previous_plain.filter(|p| !p.is_empty()) {
            if next_plain != Some(old.as_str()) {
                history.insert(
                    0,
                    serde_json::json!({ "password": previous_enc, "lastUsedDate": now }),
                );
            }
        }
    }

    // Bitwarden's own cap; keeps a decade of rotations from growing the
    // item without bound.
    history.truncate(5);

    body.as_object_mut()
        .expect("build_cipher_body returns a map")
        .insert("passwordHistory".into(), serde_json::Value::Array(history));
    Ok(body)
}

/// Decrypt a stored cipher back into the input shape a write takes.
///
/// This is what makes "duplicate" possible without the plaintext ever
/// leaving Rust: the copy is rebuilt from decrypted values here and
/// re-encrypted by `build_cipher_body` on the way out. `key` must be the
/// key the cipher's fields are actually under (item key when it has one).
///
/// Deliberately dropped from the copy: attachments (their bytes live on
/// the server, and cloning them means re-uploading each one) and the
/// password history (it belongs to the original item's timeline).
///
/// Fields that fail to decrypt come back as `None` rather than failing
/// the whole conversion — one unreadable field must not block the copy.
pub fn cipher_to_create_input(cipher: &Cipher, key: &SymmetricKey) -> Result<CipherCreateInput> {
    let dec = |s: Option<&str>| -> Option<String> {
        s.and_then(|v| decrypt_name(v, key).ok())
            .filter(|v| !v.is_empty())
    };

    Ok(CipherCreateInput {
        name: decrypt_name(&cipher.name, key)?,
        folder_id: cipher.folder_id.clone(),
        favorite: cipher.favorite,
        notes: dec(cipher.notes.as_deref()),
        login: cipher.login.as_ref().map(|l| LoginInput {
            username: dec(l.username.as_deref()),
            password: dec(l.password.as_deref()),
            uris: l
                .uris
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|u| dec(u.uri.as_deref()))
                .collect(),
            totp: dec(l.totp.as_deref()),
        }),
        card: cipher.card.as_ref().map(|c| CardInput {
            cardholder_name: dec(c.cardholder_name.as_deref()),
            brand: dec(c.brand.as_deref()),
            number: dec(c.number.as_deref()),
            exp_month: dec(c.exp_month.as_deref()),
            exp_year: dec(c.exp_year.as_deref()),
            code: dec(c.code.as_deref()),
        }),
        identity: cipher.identity.as_ref().map(|i| IdentityInput {
            title: dec(i.title.as_deref()),
            first_name: dec(i.first_name.as_deref()),
            middle_name: dec(i.middle_name.as_deref()),
            last_name: dec(i.last_name.as_deref()),
            address1: dec(i.address1.as_deref()),
            address2: dec(i.address2.as_deref()),
            address3: dec(i.address3.as_deref()),
            city: dec(i.city.as_deref()),
            state: dec(i.state.as_deref()),
            postal_code: dec(i.postal_code.as_deref()),
            country: dec(i.country.as_deref()),
            company: dec(i.company.as_deref()),
            email: dec(i.email.as_deref()),
            phone: dec(i.phone.as_deref()),
            ssn: dec(i.ssn.as_deref()),
            username: dec(i.username.as_deref()),
            passport_number: dec(i.passport_number.as_deref()),
            license_number: dec(i.license_number.as_deref()),
        }),
        ssh_key: cipher.ssh_key.as_ref().map(|s| SshKeyInput {
            private_key: dec(s.private_key.as_deref()),
            public_key: dec(s.public_key.as_deref()),
            key_fingerprint: dec(s.key_fingerprint.as_deref()),
        }),
        cipher_type: cipher.kind as u8,
        organization_id: cipher.organization_id.clone(),
        collection_ids: cipher.collection_ids.clone(),
        fields: cipher
            .fields
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|f| CustomFieldInput {
                kind: f.kind.unwrap_or(0),
                name: dec(f.name.as_deref()),
                value: dec(f.value.as_deref()),
                linked_id: f.linked_id,
            })
            .collect(),
        reprompt: cipher.reprompt.unwrap_or(0) != 0,
    })
}

/// Validates that a cipher can be moved into the given organisation
/// collection *as a straight move*. Cross-org moves (personal → org,
/// or org A → org B) require a full share — different key, different
/// endpoint. This helper centralises the rule so the frontend's error
/// message stays consistent even if the command is called from a new
/// entry point later.
pub fn validate_move_to_collection(
    cipher_organization_id: Option<&str>,
    target_collection_organization_id: &str,
) -> Result<()> {
    if cipher_organization_id == Some(target_collection_organization_id) {
        return Ok(());
    }
    Err(Error::AuthFailed {
        message: "personal items cannot be dropped on an organization collection directly — share the item first".into(),
    })
}

/// Builds the request body for POST /ciphers/share. Re-encrypts every
/// encrypted field of `cipher` from `source_key` to `target_key` and
/// returns a JSON value ready to hand to the API client. `folderId` is
/// intentionally dropped — a folder is personal by nature and does not
/// follow the cipher into the target organization.
pub fn build_share_cipher_body(
    cipher: &Cipher,
    source_key: &SymmetricKey,
    target_key: &SymmetricKey,
    target_org_id: &str,
    collection_ids: &[String],
) -> Result<serde_json::Value> {
    // An item with its own key moves without touching its fields: they are
    // encrypted under the item key, which travels with the item. Only the
    // wrapper changes, from the source key to the target org key. Items
    // without one have every field rewrapped, source → target, as before.
    let unwrapped = item_key(cipher, source_key);
    let (from_key, to_key) = match &unwrapped {
        Some(ik) => (ik, ik),
        None => (source_key, target_key),
    };
    let rewrapped_key = unwrapped
        .as_ref()
        .map(|ik| encrypt_cipher_key(ik, target_key))
        .transpose()?;

    let reenc = |s: &str| reencrypt_with_key(s, from_key, to_key);
    let reenc_opt = |s: Option<&str>| -> Result<Option<String>> { s.map(reenc).transpose() };

    let name = reenc(&cipher.name)?;
    let notes = reenc_opt(cipher.notes.as_deref())?;

    let login_json = cipher
        .login
        .as_ref()
        .map(|l| -> Result<serde_json::Value> {
            let uris: Vec<serde_json::Value> = l
                .uris
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|u| u.uri.as_deref().map(reenc))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .map(|uri| serde_json::json!({ "uri": uri, "match": serde_json::Value::Null }))
                .collect();
            Ok(serde_json::json!({
                "username": reenc_opt(l.username.as_deref())?,
                "password": reenc_opt(l.password.as_deref())?,
                "totp": reenc_opt(l.totp.as_deref())?,
                "uris": uris,
            }))
        })
        .transpose()?;

    let card_json = cipher
        .card
        .as_ref()
        .map(|c| -> Result<serde_json::Value> {
            Ok(serde_json::json!({
                "cardholderName": reenc_opt(c.cardholder_name.as_deref())?,
                "brand": reenc_opt(c.brand.as_deref())?,
                "number": reenc_opt(c.number.as_deref())?,
                "expMonth": reenc_opt(c.exp_month.as_deref())?,
                "expYear": reenc_opt(c.exp_year.as_deref())?,
                "code": reenc_opt(c.code.as_deref())?,
            }))
        })
        .transpose()?;

    let identity_json = cipher
        .identity
        .as_ref()
        .map(|i| -> Result<serde_json::Value> {
            Ok(serde_json::json!({
                "title": reenc_opt(i.title.as_deref())?,
                "firstName": reenc_opt(i.first_name.as_deref())?,
                "middleName": reenc_opt(i.middle_name.as_deref())?,
                "lastName": reenc_opt(i.last_name.as_deref())?,
                "address1": reenc_opt(i.address1.as_deref())?,
                "address2": reenc_opt(i.address2.as_deref())?,
                "address3": reenc_opt(i.address3.as_deref())?,
                "city": reenc_opt(i.city.as_deref())?,
                "state": reenc_opt(i.state.as_deref())?,
                "postalCode": reenc_opt(i.postal_code.as_deref())?,
                "country": reenc_opt(i.country.as_deref())?,
                "company": reenc_opt(i.company.as_deref())?,
                "email": reenc_opt(i.email.as_deref())?,
                "phone": reenc_opt(i.phone.as_deref())?,
                "ssn": reenc_opt(i.ssn.as_deref())?,
                "username": reenc_opt(i.username.as_deref())?,
                "passportNumber": reenc_opt(i.passport_number.as_deref())?,
                "licenseNumber": reenc_opt(i.license_number.as_deref())?,
            }))
        })
        .transpose()?;

    let ssh_key_json = cipher
        .ssh_key
        .as_ref()
        .map(|s| -> Result<serde_json::Value> {
            Ok(serde_json::json!({
                "privateKey": reenc_opt(s.private_key.as_deref())?,
                "publicKey": reenc_opt(s.public_key.as_deref())?,
                "keyFingerprint": reenc_opt(s.key_fingerprint.as_deref())?,
            }))
        })
        .transpose()?;

    // Custom fields and password history must be rewrapped and carried across,
    // or the replace-semantics share PUT silently deletes them for everyone.
    let fields_json = cipher
        .fields
        .as_ref()
        .map(|fields| -> Result<serde_json::Value> {
            let arr = fields
                .iter()
                .map(|f| -> Result<serde_json::Value> {
                    Ok(serde_json::json!({
                        "type": f.kind,
                        "name": reenc_opt(f.name.as_deref())?,
                        "value": reenc_opt(f.value.as_deref())?,
                        "linkedId": f.linked_id,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(serde_json::Value::Array(arr))
        })
        .transpose()?;

    let password_history_json = cipher
        .password_history
        .as_ref()
        .map(|hist| -> Result<serde_json::Value> {
            let arr = hist
                .iter()
                .map(|h| -> Result<serde_json::Value> {
                    Ok(serde_json::json!({
                        "lastUsedDate": h.last_used_date,
                        "password": reenc_opt(h.password.as_deref())?,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(serde_json::Value::Array(arr))
        })
        .transpose()?;

    let mut cipher_json = serde_json::json!({
        "type": cipher.kind as u8,
        "key": rewrapped_key,
        "name": name,
        "notes": notes,
        "organizationId": target_org_id,
        "folderId": serde_json::Value::Null,
        "favorite": cipher.favorite,
        // The share PUT has replace semantics and the server clears any
        // field the body omits, so an absent `reprompt` silently turned off
        // master-password reprompt on every shared item. Absent means 0.
        "reprompt": cipher.reprompt.unwrap_or(0),
        "login": login_json,
        "card": card_json,
        "identity": identity_json,
        "sshKey": ssh_key_json,
        "fields": fields_json,
        "passwordHistory": password_history_json,
    });

    // The server keys the stored data blob off `type` and rejects the whole
    // PUT with "Data missing" when the matching sub-object is absent. A
    // SecureNote has no encrypted sub-object of its own — its payload lives
    // in `notes` — so nothing above ever produces one, and sharing a note
    // used to fail with an opaque 400. Synthesise the marker Bitwarden
    // expects, exactly as `build_cipher_body` does on create.
    let obj = cipher_json.as_object_mut().expect("json! returned a map");
    let type_key = match cipher.kind {
        CipherType::Login => "login",
        CipherType::SecureNote => {
            obj.insert("secureNote".into(), serde_json::json!({ "type": 0 }));
            "secureNote"
        }
        CipherType::Card => "card",
        CipherType::Identity => "identity",
        CipherType::SshKey => "sshKey",
    };

    // Guard every other type the same way. A cipher whose declared type has
    // no matching sub-object would hit that same opaque server-side 400,
    // but only after we re-encrypted the whole item; failing here names the
    // culprit instead.
    if !matches!(obj.get(type_key), Some(v) if !v.is_null()) {
        return Err(Error::Storage {
            reason: format!(
                "cannot share cipher {}: declared type {} carries no '{type_key}' data",
                cipher.id, cipher.kind as u8
            ),
        });
    }

    Ok(serde_json::json!({
        "cipher": cipher_json,
        "collectionIds": collection_ids,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_name, SymmetricKey};
    use crate::models::{
        CardInput, CipherCreateInput, CipherField, CipherLogin, CipherLoginUri,
        CipherPasswordHistory, CipherType, IdentityInput, LoginInput, SshKeyInput,
    };

    fn test_key() -> SymmetricKey {
        // 64 bytes of arbitrary but deterministic material — splits into
        // a 32-byte encryption key and a 32-byte MAC key inside the type.
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn other_test_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(47);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn base_cipher(kind: CipherType, source_key: &SymmetricKey) -> Cipher {
        Cipher {
            id: "cipher-id".into(),
            kind,
            key: None,
            name: encrypt_string("My item", source_key).unwrap(),
            notes: None,
            organization_id: None,
            folder_id: Some("personal-folder-id".into()),
            collection_ids: vec![],
            revision_date: None,
            deleted_date: None,
            favorite: false,
            // A cipher always carries the sub-object matching its type;
            // the server rejects the share PUT outright without it. Every
            // field on these is `#[serde(default)]`, so an empty object
            // yields an all-None instance. SecureNote has no sub-object of
            // its own — its payload is `notes`.
            login: matches!(kind, CipherType::Login).then(|| serde_json::from_str("{}").unwrap()),
            card: matches!(kind, CipherType::Card).then(|| serde_json::from_str("{}").unwrap()),
            identity: matches!(kind, CipherType::Identity)
                .then(|| serde_json::from_str("{}").unwrap()),
            ssh_key: matches!(kind, CipherType::SshKey)
                .then(|| serde_json::from_str("{}").unwrap()),
            fields: None,
            password_history: None,
            reprompt: None,
            attachments: None,
        }
    }

    fn base_input() -> CipherCreateInput {
        CipherCreateInput {
            name: "My item".into(),
            folder_id: None,
            favorite: false,
            notes: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            cipher_type: 1,
            organization_id: None,
            collection_ids: vec![],
            fields: vec![],
            reprompt: false,
        }
    }

    fn item_test_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(3);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    /// Sharing an item that owns its key must NOT rewrap its fields under
    /// the org key — the fields stay under the item key, and only the item
    /// key is rewrapped. Rewrapping the fields while the server keeps the
    /// old `key` would leave the item undecryptable for every client.
    #[test]
    fn share_body_rewraps_the_item_key_and_leaves_fields_under_it() {
        let user = test_key();
        let org = other_test_key();
        let item = item_test_key();

        let mut cipher = base_cipher(CipherType::Login, &item);
        cipher.key = Some(encrypt_cipher_key(&item, &user).unwrap());
        cipher.login = Some(CipherLogin {
            username: Some(encrypt_string("alice", &item).unwrap()),
            password: Some(encrypt_string("hunter2", &item).unwrap()),
            totp: None,
            uris: Some(vec![CipherLoginUri {
                uri: Some(encrypt_string("https://example.com", &item).unwrap()),
            }]),
        });

        let body =
            build_share_cipher_body(&cipher, &user, &org, "org-1", &["col-1".into()]).unwrap();
        let c = &body["cipher"];

        // The wrapped key travels, rewrapped under the org key, and unwraps
        // back to the very same item key.
        let rewrapped = c["key"].as_str().expect("shared item keeps its key");
        let unwrapped = decrypt_cipher_key(&org, rewrapped).unwrap();
        assert_eq!(unwrapped.to_bytes().as_slice(), item.to_bytes().as_slice());

        // ...and the fields are still readable with the item key, not the org key.
        assert_eq!(
            decrypt_name(c["name"].as_str().unwrap(), &unwrapped).unwrap(),
            "My item"
        );
        assert_eq!(
            decrypt_name(c["login"]["password"].as_str().unwrap(), &unwrapped).unwrap(),
            "hunter2"
        );
        assert!(decrypt_name(c["name"].as_str().unwrap(), &org).is_err());
    }

    /// The pre-existing path: no item key, so every field is rewrapped
    /// source → target and no `key` is sent.
    #[test]
    fn share_body_without_item_key_rewraps_fields_under_the_org_key() {
        let user = test_key();
        let org = other_test_key();
        let cipher = base_cipher(CipherType::Login, &user);

        let body =
            build_share_cipher_body(&cipher, &user, &org, "org-1", &["col-1".into()]).unwrap();
        let c = &body["cipher"];

        assert!(c["key"].is_null());
        assert_eq!(
            decrypt_name(c["name"].as_str().unwrap(), &org).unwrap(),
            "My item"
        );
    }

    #[test]
    fn item_key_is_none_when_the_owning_key_is_wrong() {
        let user = test_key();
        let stranger = other_test_key();
        let item = item_test_key();

        let mut cipher = base_cipher(CipherType::Login, &item);
        cipher.key = Some(encrypt_cipher_key(&item, &stranger).unwrap());

        assert!(item_key(&cipher, &user).is_none());
    }

    #[test]
    fn share_body_rewraps_custom_fields_and_password_history() {
        // Regression for the silent data loss on share (L7): custom fields and
        // password history must be rewrapped source -> org key and carried in
        // the body, not dropped.
        let user = test_key();
        let org = other_test_key();
        let mut cipher = base_cipher(CipherType::Login, &user);
        cipher.fields = Some(vec![CipherField {
            kind: Some(1),
            name: Some(encrypt_string("recovery", &user).unwrap()),
            value: Some(encrypt_string("code-123", &user).unwrap()),
            linked_id: None,
        }]);
        cipher.password_history = Some(vec![CipherPasswordHistory {
            last_used_date: Some("2024-01-01T00:00:00Z".into()),
            password: Some(encrypt_string("old-pass", &user).unwrap()),
        }]);

        let body =
            build_share_cipher_body(&cipher, &user, &org, "org-1", &["col-1".into()]).unwrap();
        let c = &body["cipher"];

        let f = &c["fields"][0];
        assert_eq!(f["type"], 1);
        assert_eq!(
            decrypt_name(f["name"].as_str().unwrap(), &org).unwrap(),
            "recovery"
        );
        assert_eq!(
            decrypt_name(f["value"].as_str().unwrap(), &org).unwrap(),
            "code-123"
        );

        let h = &c["passwordHistory"][0];
        assert_eq!(h["lastUsedDate"], "2024-01-01T00:00:00Z");
        assert_eq!(
            decrypt_name(h["password"].as_str().unwrap(), &org).unwrap(),
            "old-pass"
        );
    }

    #[test]
    fn login_body_has_encrypted_login_subobject() {
        let mut input = base_input();
        input.login = Some(LoginInput {
            username: Some("alice".into()),
            password: Some("hunter2".into()),
            uris: vec!["https://example.com".into(), "".into()],
            totp: None,
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert_eq!(body["type"], 1);
        assert!(body["name"].as_str().unwrap().starts_with("2."));
        let login = &body["login"];
        assert!(login["username"].as_str().unwrap().starts_with("2."));
        assert!(login["password"].as_str().unwrap().starts_with("2."));
        assert!(login["totp"].is_null());
        let uris = login["uris"].as_array().unwrap();
        assert_eq!(uris.len(), 1, "empty URI should be dropped");
        assert!(uris[0]["uri"].as_str().unwrap().starts_with("2."));
        assert!(uris[0]["match"].is_null());
    }

    #[test]
    fn secure_note_body_carries_sub_type_and_no_login() {
        let mut input = base_input();
        input.cipher_type = 2;
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert_eq!(body["type"], 2);
        assert_eq!(body["secureNote"]["type"], 0);
        assert!(body.get("login").is_none());
    }

    #[test]
    fn card_body_encrypts_each_field() {
        let mut input = base_input();
        input.cipher_type = 3;
        input.card = Some(CardInput {
            cardholder_name: Some("A. B.".into()),
            brand: None,
            number: Some("4111 1111 1111 1111".into()),
            exp_month: Some("12".into()),
            exp_year: Some("2030".into()),
            code: Some("123".into()),
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        let card = &body["card"];
        assert!(card["cardholderName"].as_str().unwrap().starts_with("2."));
        assert!(card["number"].as_str().unwrap().starts_with("2."));
        assert!(card["brand"].is_null(), "missing field stays null");
    }

    #[test]
    fn identity_body_encrypts_all_set_fields() {
        let mut input = base_input();
        input.cipher_type = 4;
        input.identity = Some(IdentityInput {
            first_name: Some("Alice".into()),
            last_name: Some("Doe".into()),
            email: Some("a@example.com".into()),
            ..Default::default()
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        let id = &body["identity"];
        assert!(id["firstName"].as_str().unwrap().starts_with("2."));
        assert!(id["lastName"].as_str().unwrap().starts_with("2."));
        assert!(id["email"].as_str().unwrap().starts_with("2."));
        assert!(id["ssn"].is_null());
    }

    #[test]
    fn ssh_key_body_preserves_private_key_whitespace() {
        let mut input = base_input();
        input.cipher_type = 5;
        input.ssh_key = Some(SshKeyInput {
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----\n".into()),
            public_key: Some("ssh-ed25519 AAAA".into()),
            key_fingerprint: Some("SHA256:xxx".into()),
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        let ssh = &body["sshKey"];
        assert!(ssh["privateKey"].as_str().unwrap().starts_with("2."));
        assert!(ssh["publicKey"].as_str().unwrap().starts_with("2."));
    }

    #[test]
    fn org_scoping_injects_organization_id() {
        let mut input = base_input();
        input.cipher_type = 2;
        input.organization_id = Some("org-uuid".into());
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert_eq!(body["organizationId"], "org-uuid");
    }

    #[test]
    fn missing_variant_payload_is_a_storage_error() {
        let mut input = base_input();
        input.cipher_type = 1; // says Login, but no login field
        input.login = None;
        let err = build_cipher_body(&input, &test_key()).unwrap_err();
        assert!(matches!(err, Error::Storage { .. }));
    }

    #[test]
    fn unsupported_cipher_type_errors_out() {
        let mut input = base_input();
        input.cipher_type = 99;
        let err = build_cipher_body(&input, &test_key()).unwrap_err();
        assert!(matches!(err, Error::Storage { .. }));
    }

    #[test]
    fn notes_are_encrypted_when_non_empty() {
        let mut input = base_input();
        input.cipher_type = 2;
        input.notes = Some("  a multi-line\nnote\n".into());
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert!(body["notes"].as_str().unwrap().starts_with("2."));
    }

    #[test]
    fn empty_notes_stay_null() {
        // Empty-string notes must not be encrypted — otherwise we'd emit
        // an EncString that the server would happily round-trip and the
        // detail pane would later show a blank encrypted blob. Pure
        // whitespace is *not* trimmed because the same code path also
        // encrypts passwords and SSH private keys where spaces matter.
        let mut input = base_input();
        input.cipher_type = 2;
        input.notes = Some(String::new());
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert!(body["notes"].is_null());

        input.notes = None;
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert!(body["notes"].is_null());
    }

    // ============ build_share_cipher_body ============

    #[test]
    fn share_body_drops_folder_id() {
        // folderId must be null in the share payload even when the cipher
        // currently sits inside a personal folder: folders are personal
        // and do not follow a cipher into an organization.
        let source = test_key();
        let target = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);
        assert!(cipher.folder_id.is_some());

        let body = build_share_cipher_body(&cipher, &source, &target, "target-org", &[]).unwrap();
        assert!(body["cipher"]["folderId"].is_null());
    }

    #[test]
    fn share_body_reencrypts_name_with_target_key() {
        // The decisive invariant of share: after re-encryption, the name
        // must open under the target (org) key and NOT under the original
        // (personal or source-org) key. A bug here would either leak the
        // item as unreadable to all org members, or tie org data to a key
        // only the original owner can read.
        let source = test_key();
        let target = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);

        let body = build_share_cipher_body(&cipher, &source, &target, "target-org", &[]).unwrap();
        let name = body["cipher"]["name"].as_str().unwrap();

        assert_eq!(decrypt_name(name, &target).unwrap(), "My item");
        assert!(
            decrypt_name(name, &source).is_err(),
            "name must no longer open under the source key"
        );
    }

    #[test]
    fn share_body_sets_target_org_and_collection_ids() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::SecureNote, &source);
        cipher.organization_id = Some("old-org".into());

        let body = build_share_cipher_body(
            &cipher,
            &source,
            &target,
            "target-org",
            &["coll-a".into(), "coll-b".into()],
        )
        .unwrap();

        assert_eq!(body["cipher"]["organizationId"], "target-org");
        let colls = body["collectionIds"].as_array().unwrap();
        assert_eq!(colls.len(), 2);
        assert_eq!(colls[0], "coll-a");
        assert_eq!(colls[1], "coll-b");
    }

    #[test]
    fn share_body_preserves_favorite_and_type() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::Card, &source);
        cipher.favorite = true;

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        assert_eq!(body["cipher"]["type"], CipherType::Card as u8);
        assert_eq!(body["cipher"]["favorite"], true);
    }

    #[test]
    fn share_body_reencrypts_login_subfields_and_uris() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::Login, &source);
        cipher.login = Some(CipherLogin {
            username: Some(encrypt_string("alice", &source).unwrap()),
            password: Some(encrypt_string("hunter2", &source).unwrap()),
            totp: Some(encrypt_string("otpauth://x", &source).unwrap()),
            uris: Some(vec![
                CipherLoginUri {
                    uri: Some(encrypt_string("https://a.example", &source).unwrap()),
                },
                CipherLoginUri {
                    uri: Some(encrypt_string("https://b.example", &source).unwrap()),
                },
            ]),
        });

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        let login = &body["cipher"]["login"];
        assert_eq!(
            decrypt_name(login["username"].as_str().unwrap(), &target).unwrap(),
            "alice"
        );
        assert_eq!(
            decrypt_name(login["password"].as_str().unwrap(), &target).unwrap(),
            "hunter2"
        );
        assert_eq!(
            decrypt_name(login["totp"].as_str().unwrap(), &target).unwrap(),
            "otpauth://x"
        );
        let uris = login["uris"].as_array().unwrap();
        assert_eq!(uris.len(), 2);
        assert_eq!(
            decrypt_name(uris[0]["uri"].as_str().unwrap(), &target).unwrap(),
            "https://a.example"
        );
        assert!(uris[0]["match"].is_null());
    }

    #[test]
    fn share_body_reencrypts_ssh_private_key() {
        // The SSH private key is the most sensitive field — any corruption
        // in the re-encryption loses the user's identity. Verify end-to-end
        // that the original PEM round-trips verbatim under the target key.
        let source = test_key();
        let target = other_test_key();
        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabcdef\n-----END OPENSSH PRIVATE KEY-----\n";
        let mut cipher = base_cipher(CipherType::SshKey, &source);
        cipher.ssh_key = Some(crate::models::CipherSshKey {
            private_key: Some(encrypt_string(pem, &source).unwrap()),
            public_key: Some(encrypt_string("ssh-ed25519 AAAA", &source).unwrap()),
            key_fingerprint: None,
        });

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        let ssh = &body["cipher"]["sshKey"];
        assert_eq!(
            decrypt_name(ssh["privateKey"].as_str().unwrap(), &target).unwrap(),
            pem
        );
        assert!(ssh["keyFingerprint"].is_null());
    }

    #[test]
    fn share_body_keeps_optional_fields_null_when_absent() {
        // A SecureNote has none of login/card/identity/sshKey set; the
        // corresponding body fields must remain null so the server keeps
        // the cipher as a pure SecureNote instead of accidentally
        // promoting it.
        let source = test_key();
        let target = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        let c = &body["cipher"];
        assert!(c["login"].is_null());
        assert!(c["card"].is_null());
        assert!(c["identity"].is_null());
        assert!(c["sshKey"].is_null());
        assert!(c["notes"].is_null());
    }

    #[test]
    fn share_body_preserves_reprompt() {
        // Regression: `reprompt` was omitted entirely, and the server treats
        // an omitted field as "clear it" — so sharing an item quietly
        // dropped its master-password reprompt flag.
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::Login, &source);
        cipher.reprompt = Some(1);

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        assert_eq!(body["cipher"]["reprompt"], 1);
    }

    #[test]
    fn share_body_defaults_reprompt_to_zero_when_absent() {
        let source = test_key();
        let target = other_test_key();
        let cipher = base_cipher(CipherType::Login, &source); // reprompt: None

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        assert_eq!(body["cipher"]["reprompt"], 0);
    }

    #[test]
    fn share_body_carries_secure_note_marker() {
        // Regression: the body used to declare `type: 2` while emitting no
        // `secureNote` sub-object at all. The server keys its stored data
        // blob off `type` and answered "Data missing" with a bare 400, so
        // moving a note into a shared collection simply never worked.
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::SecureNote, &source);
        cipher.notes = Some(encrypt_string("recovery codes", &source).unwrap());

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        let c = &body["cipher"];

        assert_eq!(c["type"], 2);
        assert_eq!(c["secureNote"]["type"], 0);
        // The note body itself must survive, rewrapped under the org key.
        assert_eq!(
            decrypt_name(c["notes"].as_str().unwrap(), &target).unwrap(),
            "recovery codes"
        );
    }

    #[test]
    fn share_body_errors_when_declared_type_has_no_data() {
        // Every non-note type must carry its sub-object. Without the guard
        // this produced the same opaque server-side 400, but only after the
        // whole item had been re-encrypted.
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::Login, &source);
        cipher.login = None; // the shape the server would reject

        let err = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("login"), "unexpected error: {msg}");
    }

    #[test]
    fn share_body_emits_type_data_for_every_type() {
        // Guards against a new CipherType arriving without its key mapping.
        let source = test_key();
        let target = other_test_key();
        for (kind, key) in [
            (CipherType::Login, "login"),
            (CipherType::SecureNote, "secureNote"),
            (CipherType::Card, "card"),
            (CipherType::Identity, "identity"),
            (CipherType::SshKey, "sshKey"),
        ] {
            let cipher = base_cipher(kind, &source);
            let body = build_share_cipher_body(&cipher, &source, &target, "org", &[])
                .unwrap_or_else(|e| panic!("{kind:?} failed to build: {e}"));
            assert!(
                !body["cipher"][key].is_null(),
                "{kind:?} produced a null '{key}'"
            );
        }
    }

    #[test]
    fn share_body_reencrypts_notes_when_present() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::SecureNote, &source);
        cipher.notes = Some(encrypt_string("line 1\nline 2\n", &source).unwrap());

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        assert_eq!(
            decrypt_name(body["cipher"]["notes"].as_str().unwrap(), &target).unwrap(),
            "line 1\nline 2\n"
        );
    }

    #[test]
    fn share_body_errors_when_source_key_cannot_decrypt() {
        // Mismatched source key must bubble up as a crypto error, not
        // produce a body ciphertext nobody can read.
        let source = test_key();
        let target = other_test_key();
        let wrong = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);

        let err = build_share_cipher_body(&cipher, &wrong, &target, "org", &[]).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::Crypto { .. } | crate::error::Error::InvalidResponse { .. }
        ));
    }

    // ============ validate_move_to_collection ============

    #[test]
    fn move_to_collection_allows_same_org() {
        assert!(validate_move_to_collection(Some("org-1"), "org-1").is_ok());
    }

    #[test]
    fn move_to_collection_rejects_personal_into_org() {
        // The UX rule: drag-drop a personal item onto an org collection
        // silently "would" re-encrypt under the org key, which is a
        // security-sensitive change disguised as a move. Force the user
        // through the explicit share path instead.
        let err = validate_move_to_collection(None, "org-1").unwrap_err();
        assert!(matches!(err, Error::AuthFailed { .. }));
    }

    #[test]
    fn move_to_collection_rejects_cross_org() {
        let err = validate_move_to_collection(Some("org-a"), "org-b").unwrap_err();
        assert!(matches!(err, Error::AuthFailed { .. }));
    }

    // ============ custom fields / reprompt ============

    #[test]
    fn body_encrypts_custom_fields_and_keeps_metadata_plain() {
        let key = test_key();
        let mut input = base_input();
        input.cipher_type = 2;
        input.fields = vec![
            CustomFieldInput {
                kind: 0,
                name: Some("Account ID".into()),
                value: Some("AC-42".into()),
                linked_id: None,
            },
            CustomFieldInput {
                kind: 1,
                name: Some("Recovery".into()),
                value: Some("code-123".into()),
                linked_id: None,
            },
        ];
        let body = build_cipher_body(&input, &key).unwrap();

        let first = &body["fields"][0];
        assert_eq!(first["type"], 0);
        assert_eq!(first["linkedId"], serde_json::Value::Null);
        assert_eq!(
            decrypt_name(first["name"].as_str().unwrap(), &key).unwrap(),
            "Account ID"
        );
        assert_eq!(
            decrypt_name(first["value"].as_str().unwrap(), &key).unwrap(),
            "AC-42"
        );
        // Hidden fields are encrypted exactly like visible ones — "hidden"
        // is a display hint, not a second layer of protection.
        let second = &body["fields"][1];
        assert_eq!(second["type"], 1);
        assert_eq!(
            decrypt_name(second["value"].as_str().unwrap(), &key).unwrap(),
            "code-123"
        );
    }

    #[test]
    fn body_carries_the_reprompt_flag() {
        let key = test_key();
        let mut input = base_input();
        input.cipher_type = 2;
        assert_eq!(build_cipher_body(&input, &key).unwrap()["reprompt"], 0);
        input.reprompt = true;
        assert_eq!(build_cipher_body(&input, &key).unwrap()["reprompt"], 1);
    }

    // ============ build_update_cipher_body ============

    fn login_cipher_with_password(key: &SymmetricKey, password: &str) -> Cipher {
        let mut cipher = base_cipher(CipherType::Login, key);
        cipher.login = Some(crate::models::CipherLogin {
            username: Some(encrypt_string("alice", key).unwrap()),
            password: Some(encrypt_string(password, key).unwrap()),
            totp: None,
            uris: None,
        });
        cipher
    }

    fn login_input_with_password(password: &str) -> CipherCreateInput {
        let mut input = base_input();
        input.login = Some(LoginInput {
            username: Some("alice".into()),
            password: Some(password.into()),
            uris: vec![],
            totp: None,
        });
        input
    }

    #[test]
    fn update_body_preserves_existing_password_history() {
        // The regression that motivated this: PUT /ciphers/{id} replaces the
        // server's copy, so a body without `passwordHistory` deletes it.
        let key = test_key();
        let mut cipher = login_cipher_with_password(&key, "same");
        cipher.password_history = Some(vec![CipherPasswordHistory {
            last_used_date: Some("2024-01-01T00:00:00.000Z".into()),
            password: Some(encrypt_string("ancient", &key).unwrap()),
        }]);

        let body = build_update_cipher_body(
            &login_input_with_password("same"),
            &key,
            &cipher,
            "2026-08-03T10:00:00.000Z",
        )
        .unwrap();

        let history = body["passwordHistory"].as_array().unwrap();
        assert_eq!(history.len(), 1, "unchanged password adds no entry");
        assert_eq!(
            decrypt_name(history[0]["password"].as_str().unwrap(), &key).unwrap(),
            "ancient"
        );
        assert_eq!(history[0]["lastUsedDate"], "2024-01-01T00:00:00.000Z");
    }

    #[test]
    fn update_body_pushes_the_replaced_password_onto_the_history() {
        let key = test_key();
        let cipher = login_cipher_with_password(&key, "old-pass");
        let body = build_update_cipher_body(
            &login_input_with_password("new-pass"),
            &key,
            &cipher,
            "2026-08-03T10:00:00.000Z",
        )
        .unwrap();

        let history = body["passwordHistory"].as_array().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0]["lastUsedDate"], "2026-08-03T10:00:00.000Z");
        assert_eq!(
            decrypt_name(history[0]["password"].as_str().unwrap(), &key).unwrap(),
            "old-pass",
            "the entry records the password being replaced, not the new one"
        );
    }

    #[test]
    fn update_body_ignores_a_re_encrypted_but_identical_password() {
        // Every write draws a fresh IV, so the ciphertext of an unchanged
        // password differs every time. Comparing ciphertext here would push
        // a history entry on every save until the cap flushed the real ones.
        let key = test_key();
        let cipher = login_cipher_with_password(&key, "steady");
        let body = build_update_cipher_body(
            &login_input_with_password("steady"),
            &key,
            &cipher,
            "2026-08-03T10:00:00.000Z",
        )
        .unwrap();
        assert!(body["passwordHistory"].as_array().unwrap().is_empty());
    }

    #[test]
    fn update_body_caps_the_history_at_five_entries() {
        let key = test_key();
        let mut cipher = login_cipher_with_password(&key, "current");
        cipher.password_history = Some(
            (0..5)
                .map(|i| CipherPasswordHistory {
                    last_used_date: Some(format!("2024-01-0{}T00:00:00.000Z", i + 1)),
                    password: Some(encrypt_string(&format!("old-{i}"), &key).unwrap()),
                })
                .collect(),
        );

        let body = build_update_cipher_body(
            &login_input_with_password("rotated"),
            &key,
            &cipher,
            "2026-08-03T10:00:00.000Z",
        )
        .unwrap();

        let history = body["passwordHistory"].as_array().unwrap();
        assert_eq!(history.len(), 5);
        // Newest first: the just-replaced password leads, and the oldest
        // entry is the one that falls off.
        assert_eq!(
            decrypt_name(history[0]["password"].as_str().unwrap(), &key).unwrap(),
            "current"
        );
        assert_eq!(
            decrypt_name(history[4]["password"].as_str().unwrap(), &key).unwrap(),
            "old-3"
        );
    }

    #[test]
    fn update_body_keeps_custom_fields_from_the_input() {
        let key = test_key();
        let cipher = login_cipher_with_password(&key, "same");
        let mut input = login_input_with_password("same");
        input.fields = vec![CustomFieldInput {
            kind: 0,
            name: Some("PIN".into()),
            value: Some("4242".into()),
            linked_id: None,
        }];
        let body =
            build_update_cipher_body(&input, &key, &cipher, "2026-08-03T10:00:00.000Z").unwrap();
        assert_eq!(
            decrypt_name(body["fields"][0]["value"].as_str().unwrap(), &key).unwrap(),
            "4242"
        );
    }

    // ============ cipher_to_create_input ============

    #[test]
    fn create_input_round_trips_a_login_through_decryption() {
        let key = test_key();
        let mut cipher = login_cipher_with_password(&key, "hunter2");
        cipher.notes = Some(encrypt_string("line one\nline two", &key).unwrap());
        cipher.favorite = true;
        cipher.reprompt = Some(1);
        cipher.fields = Some(vec![CipherField {
            kind: Some(1),
            name: Some(encrypt_string("Recovery", &key).unwrap()),
            value: Some(encrypt_string("code-123", &key).unwrap()),
            linked_id: None,
        }]);

        let input = cipher_to_create_input(&cipher, &key).unwrap();
        assert_eq!(input.name, "My item");
        assert_eq!(input.notes.as_deref(), Some("line one\nline two"));
        assert!(input.favorite);
        assert!(input.reprompt);
        assert_eq!(input.cipher_type, 1);
        assert_eq!(
            input.login.as_ref().unwrap().password.as_deref(),
            Some("hunter2")
        );
        assert_eq!(input.fields[0].kind, 1);
        assert_eq!(input.fields[0].value.as_deref(), Some("code-123"));
    }

    #[test]
    fn create_input_drops_the_password_history() {
        // A copy starts its own timeline: the original's rotations say
        // nothing about the new item.
        let key = test_key();
        let mut cipher = login_cipher_with_password(&key, "hunter2");
        cipher.password_history = Some(vec![CipherPasswordHistory {
            last_used_date: Some("2024-01-01T00:00:00.000Z".into()),
            password: Some(encrypt_string("ancient", &key).unwrap()),
        }]);

        let input = cipher_to_create_input(&cipher, &key).unwrap();
        let body = build_cipher_body(&input, &key).unwrap();
        assert!(body.get("passwordHistory").is_none());
    }

    #[test]
    fn create_input_survives_a_field_it_cannot_decrypt() {
        let key = test_key();
        let stranger = other_test_key();
        let mut cipher = login_cipher_with_password(&key, "hunter2");
        // A note encrypted under a key we do not hold — the copy must
        // still be creatable, minus that one value.
        cipher.notes = Some(encrypt_string("unreadable", &stranger).unwrap());

        let input = cipher_to_create_input(&cipher, &key).unwrap();
        assert_eq!(input.notes, None);
        assert_eq!(input.login.unwrap().password.as_deref(), Some("hunter2"));
    }
}
