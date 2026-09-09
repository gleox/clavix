use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::oneshot;

use crate::ssh_agent::{self, SignGuard, SignPolicy, SignRequest};
use crate::state::AppState;
use clavix_core::crypto::decrypt_name;
use clavix_core::error::{Error, Result};
use clavix_core::models::CipherType;

/// Payload emitted to the frontend when a signature needs approval.
/// The dialog shows the key and answers via `respond_ssh_agent_confirm`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmRequest {
    pub id: u64,
    pub comment: String,
    pub algorithm: String,
    pub fingerprint: String,
    /// Process name of the requesting client, when it could be resolved.
    /// Advisory only — see `ssh_agent::CallerInfo` for why this must not
    /// drive a trust decision.
    pub caller_name: Option<String>,
    /// Pid of the requesting client, when it could be resolved.
    pub caller_pid: Option<u32>,
}

/// Turn one SSH-key cipher into either agent-loadable material
/// (`(id, name, pem)`) or a `SkippedKey` explaining the refusal.
///
/// Total by construction: there is no third outcome, which is what keeps
/// the agent's key count reconcilable with the vault's SSH-key count.
fn classify_ssh_cipher(
    c: &clavix_core::models::Cipher,
    key: &clavix_core::crypto::SymmetricKey,
) -> std::result::Result<(String, String, String), SkippedKey> {
    // The name is itself vault ciphertext and can fail to decrypt. Fall
    // back to the cipher id so the row stays identifiable — an unnamed
    // entry the user can't locate is barely better than no entry at all.
    let name =
        decrypt_name(&c.name, key).unwrap_or_else(|_| format!("(unreadable name — item {})", c.id));

    let Some(ssh) = c.ssh_key.as_ref() else {
        return Err(SkippedKey {
            name,
            reason: "item is typed as an SSH key but carries no SSH key data".into(),
        });
    };
    let Some(pk_enc) = ssh.private_key.as_deref() else {
        return Err(SkippedKey {
            name,
            reason: "no private key stored on this item — only a public key".into(),
        });
    };
    let Ok(pem) = decrypt_name(pk_enc, key) else {
        return Err(SkippedKey {
            name,
            reason: "could not decrypt the private key with this vault's keys".into(),
        });
    };
    Ok((c.id.clone(), name, pem))
}

fn parse_sign_policy(policy: &str) -> SignPolicy {
    match policy {
        "always" => SignPolicy::Always,
        "session" => SignPolicy::PerSession,
        // Unknown / "never" → sign silently (historical default).
        _ => SignPolicy::Never,
    }
}

/// Ask the user (via the confirmation dialog) to approve one signature.
/// Runs inside the agent task; parks a `oneshot` in `AppState`, surfaces
/// the window, emits the request, and waits — denying on timeout so a
/// missed prompt can't hang an `ssh`/`git` invocation forever.
async fn request_confirmation(app: &AppHandle, req: SignRequest) -> bool {
    let state = app.state::<AppState>();
    let id = {
        let mut seq = state.ssh_confirm_seq.lock();
        *seq = seq.wrapping_add(1);
        *seq
    };
    let (tx, rx) = oneshot::channel();
    state.ssh_confirms.lock().insert(id, tx);

    // Signing usually happens while Clavix sits in the tray, so bring the
    // window forward or the prompt would never be seen.
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
    }

    let payload = ConfirmRequest {
        id,
        comment: req.key.comment,
        algorithm: req.key.algorithm,
        fingerprint: req.key.fingerprint,
        caller_name: req.caller.as_ref().and_then(|c| c.name.clone()),
        caller_pid: req.caller.as_ref().map(|c| c.pid),
    };
    if app.emit("ssh-agent-confirm", &payload).is_err() {
        state.ssh_confirms.lock().remove(&id);
        return false;
    }

    match tokio::time::timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(approved)) => approved,
        // Timed out, or the sender was dropped — deny and clean up.
        _ => {
            state.ssh_confirms.lock().remove(&id);
            false
        }
    }
}

/// Resolve a pending signature confirmation. Called by the dialog with
/// the user's decision; a no-op if the request already timed out.
#[tauri::command]
pub fn respond_ssh_agent_confirm(
    state: State<'_, AppState>,
    id: u64,
    approved: bool,
) -> Result<()> {
    if let Some(tx) = state.ssh_confirms.lock().remove(&id) {
        let _ = tx.send(approved);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedKey {
    /// Comment field of the OpenSSH key — falls back to the cipher name
    /// when the key's own comment is empty.
    pub comment: String,
    /// Wire-format algorithm name, e.g. `"ssh-ed25519"` / `"ssh-rsa"`.
    pub algorithm: String,
    /// Same `"SHA256:…"` format `ssh-add -l` prints.
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedKey {
    /// Cipher name (or key comment if cipher decryption failed).
    pub name: String,
    /// Human-readable reason — surfaced to the user so they know whether
    /// the key was skipped because of an unsupported algorithm
    /// (ECDSA / DSA), a leftover passphrase-encrypted PEM that pre-dates
    /// the import-time decrypt flow, or a malformed key.
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAgentStatus {
    pub running: bool,
    pub socket_path: Option<String>,
    pub keys: Vec<ExposedKey>,
    /// Keys the last start could not load. Carried by `ssh_agent_status`
    /// too (replayed from `AppState`, not recomputed), so reopening the
    /// settings dialog still explains a key count that looks short.
    pub skipped: Vec<SkippedKey>,
}

/// Deny every pending signature confirmation: send `false` down each
/// parked oneshot. Call before stopping the agent so a confirmation the
/// user can no longer see (the prompt is gone, the dialog is closing)
/// does not keep a serve task — or the Pageant window thread — parked
/// for the full 30-second confirm timeout.
fn deny_pending_confirmations(state: &AppState) {
    let pending = std::mem::take(&mut *state.ssh_confirms.lock());
    for (_, tx) in pending {
        let _ = tx.send(false);
    }
}

#[tauri::command]
pub async fn start_ssh_agent(
    state: State<'_, AppState>,
    app: AppHandle,
    policy: String,
) -> Result<SshAgentStatus> {
    // Stop any previous instance first — simpler than reconciling state.
    let previous = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = previous {
        deny_pending_confirmations(&state);
        h.stop().await;
    }

    // Decrypt every SSH key item from the current vault, inside the lock.
    //
    // Every SSH-key cipher must come out of this loop as either a decrypted
    // entry or a `SkippedKey`. Dropping one silently (as an earlier
    // `filter_map` did) makes the agent's key count disagree with the
    // vault's SSH-key count with nothing anywhere to explain the gap.
    let mut skipped: Vec<SkippedKey> = Vec::new();
    let decrypted: Vec<(String, String, String)> = {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;
        let mut out = Vec::new();
        for c in vault
            .ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none())
            .filter(|c| matches!(c.kind, CipherType::SshKey))
        {
            let owner =
                clavix_core::services::cipher::owning_key(c, &session.user_key, &session.org_keys);
            let item = clavix_core::services::cipher::item_key(c, owner);
            let key = item.as_ref().unwrap_or(owner);
            match classify_ssh_cipher(c, key) {
                Ok(entry) => out.push(entry),
                Err(s) => skipped.push(s),
            }
        }
        out
    };

    let socket_path = ssh_agent::default_socket_path()?;

    let mut agent_keys = Vec::new();
    for (_id, name, pem) in &decrypted {
        match ssh_agent::try_load_agent_key(pem, name) {
            Ok(Some(k)) => agent_keys.push(k),
            Ok(None) => skipped.push(SkippedKey {
                name: name.clone(),
                reason: "unsupported algorithm (only Ed25519 and RSA load into the agent today)"
                    .into(),
            }),
            Err(Error::Crypto { reason }) => {
                // The most common case here is the legacy "passphrase-protected"
                // marker from before the import-time decrypt flow shipped.
                // Surface the underlying message verbatim so the user
                // understands what to do (re-open the cipher to decrypt it,
                // or fix a malformed PEM).
                // Don't log the decrypted item name — it's vault-content
                // metadata that would land in stderr/journald. The name still
                // reaches the user via the returned `SkippedKey` list.
                eprintln!("[clavix agent] skipping a key: {reason}");
                skipped.push(SkippedKey {
                    name: name.clone(),
                    reason,
                });
            }
            Err(e) => {
                eprintln!("[clavix agent] skipping a key: {e}");
                skipped.push(SkippedKey {
                    name: name.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    // Wire the signature-approval policy. `Never` needs no callback and
    // keeps the fast silent path; the confirming policies get a callback
    // that drives the front-end dialog through `AppState`.
    let sign_policy = parse_sign_policy(&policy);
    let confirm: Option<ssh_agent::ConfirmFn> = if matches!(sign_policy, SignPolicy::Never) {
        None
    } else {
        let app = app.clone();
        Some(Arc::new(move |req: SignRequest| {
            let app = app.clone();
            Box::pin(async move { request_confirmation(&app, req).await })
                as std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        }))
    };
    let guard = SignGuard::new(sign_policy, confirm);

    let handle = ssh_agent::start_agent(socket_path.clone(), agent_keys, guard).await?;
    let exposed: Vec<ExposedKey> = handle
        .keys
        .iter()
        .map(|k| ExposedKey {
            comment: k.comment.clone(),
            algorithm: k.algorithm.clone(),
            fingerprint: k.fingerprint.clone(),
        })
        .collect();
    let status = SshAgentStatus {
        running: true,
        socket_path: Some(handle.socket_path.to_string_lossy().into_owned()),
        keys: exposed,
        skipped: skipped.clone(),
    };

    // Remember why keys were left out so `ssh_agent_status` can answer the
    // "why does it say 8 when I have 9?" question on any later poll, not
    // just in this reply.
    *state.ssh_skipped.lock() = skipped;

    {
        let mut slot = state.ssh_agent.lock();
        *slot = Some(handle);
    }
    Ok(status)
}

#[tauri::command]
pub async fn stop_ssh_agent(state: State<'_, AppState>) -> Result<()> {
    let handle = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = handle {
        deny_pending_confirmations(&state);
        h.stop().await;
    }
    // The skip list describes a load that no longer has a running agent
    // behind it — drop it rather than let it resurface on a later start
    // that skipped nothing.
    state.ssh_skipped.lock().clear();
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedSshKey {
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

/// Parse an OpenSSH private key, decrypt it with `passphrase` if needed,
/// and return the canonical unencrypted PEM together with the SSH public-key
/// line and SHA-256 fingerprint. Mirrors the import-time UX of Bitwarden
/// Desktop: the passphrase is consumed once, never stored.
#[tauri::command]
pub fn decrypt_ssh_private_key(
    private_key: String,
    passphrase: Option<String>,
) -> Result<DecryptedSshKey> {
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let mut pk = PrivateKey::from_openssh(&private_key).map_err(|e| Error::Crypto {
        reason: format!("ssh key parse: {e}"),
    })?;

    // Check the algorithm BEFORE prompting for or consuming a passphrase.
    // The algorithm header is in the unencrypted portion of the OpenSSH
    // format, so we can reject ECDSA / DSA up front instead of having the
    // user type a passphrase that turns out to be useless.
    match pk.algorithm() {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } => {}
        other => {
            return Err(Error::Crypto {
                reason: format!(
                    "unsupported SSH algorithm: {other} — only Ed25519 and RSA can be loaded into the agent"
                ),
            });
        }
    }

    if pk.is_encrypted() {
        let pass = passphrase.ok_or(Error::SshPassphraseRequired)?;
        pk = pk
            .decrypt(pass.as_bytes())
            .map_err(|_| Error::SshWrongPassphrase)?;
    }

    let private_pem = pk
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Crypto {
            reason: format!("ssh key re-encode: {e}"),
        })?
        .to_string();
    let public_pem = pk.public_key().to_openssh().map_err(|e| Error::Crypto {
        reason: format!("ssh public encode: {e}"),
    })?;
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    Ok(DecryptedSshKey {
        private_key: private_pem,
        public_key: public_pem,
        key_fingerprint: fingerprint,
    })
}

/// Generate a fresh Ed25519 SSH keypair, returning the canonical
/// OpenSSH-format private key, the public-key line, and the SHA-256
/// fingerprint. Same shape as `decrypt_ssh_private_key` so the editor
/// can drop the result straight into its sshKey state.
///
/// Ed25519 only for now: it's the modern default (`ssh-keygen` picks
/// it by default since OpenSSH 9.5), 256-bit equivalent security with
/// 32-byte keys, generation is essentially instantaneous. RSA support
/// can ship later as a separate algorithm parameter — until then,
/// users with infra that requires RSA can paste an existing key.
#[tauri::command]
pub fn generate_ssh_key() -> Result<DecryptedSshKey> {
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let mut rng = rand::thread_rng();
    let pk = PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(|e| Error::Crypto {
        reason: format!("generate ed25519 ssh key: {e}"),
    })?;

    let private_pem = pk
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Crypto {
            reason: format!("encode generated private key: {e}"),
        })?
        .to_string();
    let public_pem = pk.public_key().to_openssh().map_err(|e| Error::Crypto {
        reason: format!("encode generated public key: {e}"),
    })?;
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    Ok(DecryptedSshKey {
        private_key: private_pem,
        public_key: public_pem,
        key_fingerprint: fingerprint,
    })
}

#[cfg(test)]
mod decrypt_tests {
    use super::*;

    #[test]
    fn rejects_non_pem_garbage() {
        let res = decrypt_ssh_private_key("this is definitely not an OpenSSH key".into(), None);
        match res {
            Err(Error::Crypto { reason }) => assert!(reason.starts_with("ssh key parse:")),
            other => panic!("expected Crypto parse error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_input() {
        let res = decrypt_ssh_private_key(String::new(), None);
        assert!(matches!(res, Err(Error::Crypto { .. })));
    }

    #[test]
    fn rejects_truncated_pem_header() {
        // Truncated mid-header — must not panic, must return parse error.
        let res = decrypt_ssh_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\n".into(), None);
        assert!(matches!(res, Err(Error::Crypto { .. })));
    }
}

/// Every SSH-key cipher must leave `classify_ssh_cipher` accounted for —
/// either loadable or explicitly skipped. A silent third outcome is what
/// made the agent report fewer keys than the vault held, with no
/// explanation anywhere.
#[cfg(test)]
mod classify_tests {
    use super::*;
    use clavix_core::crypto::{encrypt_string, SymmetricKey};
    use clavix_core::models::{Cipher, CipherSshKey};

    fn test_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn foreign_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(47);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn ssh_cipher(key: &SymmetricKey, ssh_key: Option<CipherSshKey>) -> Cipher {
        Cipher {
            id: "ssh-cipher-id".into(),
            kind: CipherType::SshKey,
            key: None,
            name: encrypt_string("my-server-key", key).unwrap(),
            notes: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            revision_date: None,
            deleted_date: None,
            favorite: false,
            login: None,
            card: None,
            identity: None,
            ssh_key,
            fields: None,
            password_history: None,
            reprompt: None,
            attachments: None,
        }
    }

    #[test]
    fn loadable_key_round_trips_name_and_pem() {
        let key = test_key();
        let c = ssh_cipher(
            &key,
            Some(CipherSshKey {
                private_key: Some(encrypt_string("PEM-BODY", &key).unwrap()),
                public_key: None,
                key_fingerprint: None,
            }),
        );
        let (id, name, pem) = classify_ssh_cipher(&c, &key).expect("should load");
        assert_eq!(id, "ssh-cipher-id");
        assert_eq!(name, "my-server-key");
        assert_eq!(pem, "PEM-BODY");
    }

    #[test]
    fn missing_ssh_payload_is_reported_not_dropped() {
        let key = test_key();
        let c = ssh_cipher(&key, None);
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert_eq!(s.name, "my-server-key");
        assert!(s.reason.contains("no SSH key data"), "{}", s.reason);
    }

    #[test]
    fn public_key_only_item_is_reported_not_dropped() {
        let key = test_key();
        let c = ssh_cipher(
            &key,
            Some(CipherSshKey {
                private_key: None,
                public_key: Some("ssh-ed25519 AAAA…".into()),
                key_fingerprint: None,
            }),
        );
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert!(s.reason.contains("no private key"), "{}", s.reason);
    }

    #[test]
    fn undecryptable_private_key_is_reported_not_dropped() {
        let key = test_key();
        // Encrypted under a key this vault doesn't hold.
        let c = ssh_cipher(
            &key,
            Some(CipherSshKey {
                private_key: Some(encrypt_string("PEM-BODY", &foreign_key()).unwrap()),
                public_key: None,
                key_fingerprint: None,
            }),
        );
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert!(s.reason.contains("could not decrypt"), "{}", s.reason);
    }

    /// An unreadable name must still produce a locatable row rather than
    /// an anonymous one — the id is the only handle left.
    #[test]
    fn undecryptable_name_falls_back_to_the_cipher_id() {
        let key = test_key();
        let mut c = ssh_cipher(&key, None);
        c.name = encrypt_string("my-server-key", &foreign_key()).unwrap();
        let s = classify_ssh_cipher(&c, &key).expect_err("should be skipped");
        assert!(s.name.contains("ssh-cipher-id"), "{}", s.name);
    }
}

#[cfg(test)]
mod generate_tests {
    use super::*;

    #[test]
    fn generated_key_round_trips_through_decrypt_command() {
        // Fresh Ed25519 → returned PEM is unencrypted, so feeding it
        // back through decrypt_ssh_private_key (no passphrase) gives
        // a stable result. Catches regressions where the encoder and
        // parser disagree on the wire format.
        let gen = generate_ssh_key().expect("generate ed25519");
        assert!(gen.public_key.starts_with("ssh-ed25519 "));
        assert!(gen.key_fingerprint.starts_with("SHA256:"));
        assert!(gen.private_key.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!gen.private_key.contains("ENCRYPTED"));

        let parsed = decrypt_ssh_private_key(gen.private_key.clone(), None)
            .expect("freshly generated key parses back");
        assert_eq!(parsed.public_key, gen.public_key);
        assert_eq!(parsed.key_fingerprint, gen.key_fingerprint);
    }

    #[test]
    fn two_calls_produce_different_keys() {
        // Sanity check that the RNG is actually being consumed —
        // a wedged generator that returned a constant key would
        // be a serious zero-day (and a hilarious test failure).
        let a = generate_ssh_key().unwrap();
        let b = generate_ssh_key().unwrap();
        assert_ne!(a.key_fingerprint, b.key_fingerprint);
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
    }
}

#[tauri::command]
pub fn ssh_agent_status(state: State<'_, AppState>) -> Result<SshAgentStatus> {
    let slot = state.ssh_agent.lock();
    // Replayed from the last start, never recomputed: this command must not
    // touch the vault. An agent that isn't running has nothing to explain,
    // so the list stays empty there.
    Ok(match slot.as_ref() {
        Some(h) => SshAgentStatus {
            running: true,
            socket_path: Some(h.socket_path.to_string_lossy().into_owned()),
            keys: h
                .keys
                .iter()
                .map(|k| ExposedKey {
                    comment: k.comment.clone(),
                    algorithm: k.algorithm.clone(),
                    fingerprint: k.fingerprint.clone(),
                })
                .collect(),
            skipped: state.ssh_skipped.lock().clone(),
        },
        None => SshAgentStatus {
            running: false,
            socket_path: None,
            keys: Vec::new(),
            skipped: Vec::new(),
        },
    })
}

/// Returns whatever `SSH_AUTH_SOCK` was set to in the process
/// environment when Clavix launched. Used by the agent UI to tell the
/// user whether the variable already points at our socket or whether
/// they still need to export it. Reads only this single variable, no
/// arbitrary env access.
#[tauri::command]
pub fn ssh_auth_sock() -> Option<String> {
    std::env::var("SSH_AUTH_SOCK").ok()
}
