use std::collections::HashMap;
use std::time::Instant;

use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use crate::session::{
    clear_pending_two_factor, set_pending_two_factor, store_session, store_standalone_session,
    with_pending_two_factor,
};
use crate::state::{AppState, AutoLockSetting, AutoLockTrigger};
use crate::yubikey_unlock;
use clavix_core::api::VaultwardenClient;
use clavix_core::cache;
use clavix_core::crypto::{
    decrypt_private_key, decrypt_user_key, derive_master_key, encrypt_string, SymmetricKey,
};
use clavix_core::error::{Error, Result};
use clavix_core::models::{LoginOk, LoginOutcome, LoginResult, Prelogin, TwoFactorProvider};
use clavix_core::services::auth::{
    device_info, extract_session_keys, persist_session, prepare_credentials, recover_refresh_token,
};
use clavix_core::session::{PendingTwoFactor, SessionOrigin};
use clavix_core::store;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAccount {
    pub server_url: String,
    pub email: String,
}

#[tauri::command]
pub fn stored_account() -> Result<Option<StoredAccount>> {
    Ok(store::load_session()?.map(|s| StoredAccount {
        server_url: s.server_url,
        email: s.email,
    }))
}

/// Pin pre-auth entry points to the active session's server. `prelogin`/`login`
/// build a fresh `VaultwardenClient` from a renderer-supplied `server_url` with
/// no session context, so a compromised WebView could point them at an
/// attacker host to smuggle data out over the native (reqwest) side or probe
/// internal https services (SSRF). While a vault session is active the server
/// is fixed, so any first-factor call to a *different* host is illegitimate —
/// reject it. When logged out (no session) any server is allowed, which is the
/// normal sign-in / account-switch path.
fn ensure_server_matches_active_session(state: &AppState, server_url: &str) -> Result<()> {
    let guard = state.session.lock();
    if let Some(session) = guard.as_ref() {
        // A standalone session pins no server at all, so there is
        // nothing to compare against — and no legitimate reason for it
        // to be making first-factor calls anywhere. Refuse outright
        // rather than fall through to "any host is fine", which is what
        // an `if let Some(client)` would have done.
        let Some(client) = session.client.as_ref() else {
            return Err(Error::AuthFailed {
                message: "close the standalone vault before signing in to a server".into(),
            });
        };
        let requested = VaultwardenClient::new(server_url)?;
        if requested.base_url() != client.base_url() {
            return Err(Error::AuthFailed {
                message: "refusing to contact a different server while a vault session is active"
                    .into(),
            });
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn prelogin(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
) -> Result<Prelogin> {
    ensure_server_matches_active_session(&state, &server_url)?;
    let client = VaultwardenClient::new(&server_url)?;
    client.prelogin(&email).await
}

#[tauri::command]
pub async fn login(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<LoginOutcome> {
    ensure_server_matches_active_session(&state, &server_url)?;
    let password: SecretString = password.into();
    let (client, pre, master_key, hash) =
        prepare_credentials(&server_url, &email, &password).await?;
    let device = device_info()?;
    let result = client.login(&email, &hash, &device).await?;

    match result {
        LoginResult::Success(tokens) => {
            // Single-factor login won — drop any leftover pending slot
            // (e.g. a previous attempt that needed 2FA but never
            // finished) before opening the new session.
            clear_pending_two_factor(&state);
            let (user_key, private_key) = extract_session_keys(&master_key, &tokens)?;
            persist_session(&server_url, &email, &pre, &tokens, &user_key)?;
            store_session(&state, client, tokens, user_key, private_key);
            Ok(LoginOutcome::Success(LoginOk {
                email,
                origin: SessionOrigin::Server,
            }))
        }
        LoginResult::TwoFactorRequired {
            providers,
            webauthn_challenge,
        } => {
            // Park the derived material so `webauthn_sign_challenge`
            // and `login_with_two_factor` can read from a Rust-owned
            // slot rather than re-receiving it from the renderer. The
            // renderer never needs to send back the server URL, the
            // email, or the password again — closes the gap where a
            // compromised JS could swap any of those between the two
            // IPC calls.
            set_pending_two_factor(
                &state,
                PendingTwoFactor {
                    server_url,
                    email,
                    master_key,
                    password_hash: hash,
                    prelogin: pre,
                    client,
                    created_at: Instant::now(),
                },
            );
            Ok(LoginOutcome::TwoFactorRequired {
                providers,
                webauthn_challenge,
            })
        }
    }
}

#[tauri::command]
pub async fn login_with_two_factor(
    state: State<'_, AppState>,
    code: String,
    provider: u8,
) -> Result<LoginOk> {
    let typed_provider = TwoFactorProvider::try_from(provider)
        .map_err(|_| Error::TwoFactorProviderUnsupported { provider })?;

    // Pull the pending slot's contents out under the lock, then drop
    // it so the secrets are zeroized as soon as the await below
    // finishes — success or failure.
    let (server_url, email, hash, master_key, prelogin, client) =
        with_pending_two_factor(&state, |p| {
            Ok((
                p.server_url.clone(),
                p.email.clone(),
                p.password_hash.clone(),
                p.master_key.clone(),
                p.prelogin.clone(),
                p.client.clone(),
            ))
        })?;

    let device = device_info()?;
    let tokens = match client
        .login_with_two_factor(&email, &hash, &device, typed_provider, &code)
        .await
    {
        Ok(tokens) => tokens,
        Err(err) => {
            // Wrong code: keep the pending slot alive so the user can
            // retry without redoing the Argon2id round. Other errors
            // (network, malformed response) clear the slot to be safe.
            if !matches!(err, Error::AuthFailed { .. }) {
                clear_pending_two_factor(&state);
            }
            return Err(err);
        }
    };

    let (user_key, private_key) = extract_session_keys(&master_key, &tokens)?;
    persist_session(&server_url, &email, &prelogin, &tokens, &user_key)?;
    store_session(&state, client, tokens, user_key, private_key);
    clear_pending_two_factor(&state);
    Ok(LoginOk {
        email,
        origin: SessionOrigin::Server,
    })
}

/// Drop the parked 2FA login slot. Called by the frontend when the
/// user clicks "Annuler" on the 2FA screen, and as a defensive
/// cleanup whenever the session is reset.
#[tauri::command]
pub fn cancel_two_factor(state: State<'_, AppState>) -> Result<()> {
    clear_pending_two_factor(&state);
    Ok(())
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, password: String) -> Result<LoginOk> {
    let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to unlock".into(),
    })?;

    let password: SecretString = password.into();
    let master_key = derive_master_key(
        &password,
        &persisted.email,
        persisted.kdf,
        persisted.kdf_iterations,
        persisted.kdf_memory,
        persisted.kdf_parallelism,
    )?;

    let user_key = decrypt_user_key(&master_key, &persisted.encrypted_user_key)?;
    let private_key = persisted
        .encrypted_private_key
        .as_deref()
        .map(|pk| decrypt_private_key(&user_key, pk))
        .transpose()?;

    // Decrypt refresh token (or fall back to legacy clear-text for sessions
    // written before encryption landed; those are migrated below).
    let refresh_token_plain = recover_refresh_token(&persisted, &user_key)?;

    let client = VaultwardenClient::new(&persisted.server_url)?;
    let device = device_info()?;
    let email = persisted.email.clone();

    // Nothing above this line needed the network: deriving the master
    // key, unwrapping the user key and decrypting the refresh token are
    // all local. The call below only fetches an *access token*, and it
    // used to be an unconditional `?` — so a server that was merely
    // unreachable threw away a user key that had already been recovered
    // successfully, and left the user stuck on the unlock screen with
    // an encrypted cache they could not reach.
    //
    // Only a transport failure falls through to standalone. A server
    // that answers and rejects the refresh token (expired, revoked)
    // means the account really does need signing in again, and saying
    // "you're offline" there would be a lie.
    let mut tokens = match client.refresh_token(&refresh_token_plain, &device).await {
        Ok(tokens) => tokens,
        Err(Error::Network { source }) => {
            eprintln!("[clavix] unlock: server unreachable ({source}) — opening the cached vault read-only");
            store_standalone_session(
                &state,
                SessionOrigin::OfflineCache,
                user_key,
                private_key,
                HashMap::new(),
                None,
            );
            crate::state::mark_activity(&state);
            return Ok(LoginOk {
                email,
                origin: SessionOrigin::OfflineCache,
            });
        }
        Err(e) => return Err(e),
    };

    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = refresh_token_plain.clone();
    }

    // Re-encrypt and drop any legacy clear-text field.
    let encrypted_refresh = encrypt_string(&tokens.refresh_token, &user_key)?;
    let mut updated = persisted.clone();
    updated.refresh_token = None;
    updated.encrypted_refresh_token = Some(encrypted_refresh);
    store::save_session(&updated)?;

    store_session(&state, client, tokens, user_key, private_key);
    crate::state::mark_activity(&state);
    Ok(LoginOk {
        email,
        origin: SessionOrigin::Server,
    })
}

/// Check a master password without touching the session.
///
/// Backs the per-item "ask again" (reprompt) gate. Purely local: the
/// password is run through the stored KDF parameters and used to unwrap
/// the stored user key, which only succeeds — MAC verification — for the
/// right password. No network call, no session mutation, nothing written.
///
/// Returns false on a wrong password rather than an error: a mistyped
/// password is an expected answer here, not a failure.
#[tauri::command]
pub async fn verify_master_password(state: State<'_, AppState>, password: String) -> Result<bool> {
    crate::state::mark_activity(&state);
    let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to verify against".into(),
    })?;

    let password: SecretString = password.into();
    let master_key = derive_master_key(
        &password,
        &persisted.email,
        persisted.kdf,
        persisted.kdf_iterations,
        persisted.kdf_memory,
        persisted.kdf_parallelism,
    )?;
    Ok(decrypt_user_key(&master_key, &persisted.encrypted_user_key).is_ok())
}

/// Perform a WebAuthn / FIDO2 assertion against the user's USB security
/// key, for a Bitwarden-style challenge. Returns the JSON string that
/// must be sent back to the server as `twoFactorToken` with provider=7.
///
/// The rpId anchor used by `validate_rp_id` is read from the parked
/// `PendingTwoFactor` slot — the same `server_url` the user typed at
/// the start of `login()`. The renderer no longer passes it back: a
/// compromised JS layer could otherwise swap the anchor between the
/// `login` and `webauthn_sign_challenge` calls.
///
/// Blocking CTAP2 I/O is offloaded to the async runtime's blocking pool
/// so the Tauri main loop stays responsive while the user taps their key.
#[tauri::command]
pub async fn webauthn_sign_challenge(
    state: State<'_, AppState>,
    challenge_json: String,
) -> Result<String> {
    let server_url = with_pending_two_factor(&state, |p| Ok(p.server_url.clone()))?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::webauthn::sign_bitwarden_challenge(&challenge_json, &server_url)
    })
    .await
    .map_err(|e| Error::Crypto {
        reason: format!("webauthn blocking task panicked: {e}"),
    })?
}

/// Shape returned by [`yubikey_unlock_state`]. Hand-mirrored in
/// `src/lib/types.ts` (like `SshAgentStatus`) — not a ts-rs type.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YubikeyUnlockInfo {
    /// A Yubikey wrap is present on disk → show the "Toucher la Yubikey"
    /// button on the unlock view.
    pub enrolled: bool,
    /// The wrap was created with the token's PIN → the unlock view must
    /// show the PIN field (hmac-secret is UV-mode-bound). `true` for
    /// pre-`requires_pin` blocks as the safe default; meaningless when
    /// not enrolled (reported `false`).
    pub requires_pin: bool,
}

/// State of the persisted Yubikey wrap: whether one exists, and whether
/// unlocking it needs the PIN. Drives the unlock view without asking the
/// user to configure anything. Returns `enrolled: false` (rather than an
/// error) when no session is stored yet, so the caller can ignore it
/// during onboarding.
#[tauri::command]
pub fn yubikey_unlock_state() -> Result<YubikeyUnlockInfo> {
    let block = store::load_session()?.and_then(|s| s.yubikey_unlock);
    Ok(YubikeyUnlockInfo {
        enrolled: block.is_some(),
        // Unknown (old block) → assume a PIN is needed: showing the field
        // is harmless for a PIN-less wrap (leave it empty) but hiding it
        // for a PIN-bound wrap breaks unlock.
        requires_pin: block
            .map(|b| b.requires_pin.unwrap_or(true))
            .unwrap_or(false),
    })
}

/// Wrap the in-memory user key under a freshly-enrolled FIDO2
/// credential and persist the resulting block. Requires an unlocked
/// session (the wrap target is the live user key — we never re-derive
/// it from the master password here, which keeps this command
/// password-free by construction). The blocking CTAP I/O is offloaded
/// to the runtime's blocking pool so the Tauri main loop stays
/// responsive while the user taps their key.
#[tauri::command]
pub async fn enroll_yubikey_unlock(state: State<'_, AppState>, pin: Option<String>) -> Result<()> {
    crate::state::mark_activity(&state);

    let user_key = clone_user_key(&state)?;

    let block = tauri::async_runtime::spawn_blocking(move || {
        yubikey_unlock::enroll(
            &yubikey_unlock::CtapHidDevice,
            yubikey_unlock::DEFAULT_RP_ID,
            pin.as_deref(),
            &user_key,
        )
    })
    .await
    .map_err(|e| Error::Crypto {
        reason: format!("yubikey enrol task panicked: {e}"),
    })??;

    let mut persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session — yubikey enrolment requires a previous master-password sign-in"
            .into(),
    })?;
    persisted.yubikey_unlock = Some(block);
    store::save_session(&persisted)?;
    Ok(())
}

/// Drop the on-disk Yubikey wrap. Requires the master password to
/// avoid the "logged-in laptop briefly unattended → attacker
/// disenrols silently" scenario from the threat model. We validate
/// the password by deriving and decrypting the existing
/// `encrypted_user_key`; that proves possession without contacting
/// the server.
///
/// The credential remains on the token. Removing it from the
/// authenticator requires a separate FIDO2 management flow we don't
/// run — `ykman fido credentials` is the user's tool for that.
#[tauri::command]
pub async fn disenroll_yubikey_unlock(state: State<'_, AppState>, password: String) -> Result<()> {
    crate::state::mark_activity(&state);

    let mut persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to disenrol from".into(),
    })?;

    let password: SecretString = password.into();
    let master_key = derive_master_key(
        &password,
        &persisted.email,
        persisted.kdf,
        persisted.kdf_iterations,
        persisted.kdf_memory,
        persisted.kdf_parallelism,
    )?;
    // Probe: if the password is wrong this errors out before we touch
    // the on-disk block, so a wrong-password call is a no-op rather
    // than a silent disenrolment. A decrypt failure here means the
    // master password was wrong — surface that plainly rather than a
    // raw "MAC verification failed", since this field is easy to
    // confuse with the Yubikey PIN.
    let _ = decrypt_user_key(&master_key, &persisted.encrypted_user_key)
        .map_err(|_| Error::InvalidMasterPassword)?;

    persisted.yubikey_unlock = None;
    store::save_session(&persisted)?;
    Ok(())
}

/// Release the cached user key by replaying the stored salt against
/// the registered FIDO2 credential. Drops the wrap and surfaces
/// `YubikeyStaleWrap` if the master password was rotated on another
/// client (detected via the user-key fingerprint). Beyond the
/// user-key recovery, the rest of the flow mirrors `unlock` byte-
/// for-byte: refresh the access token, re-encrypt the rotated
/// refresh token under the user key, restore the session.
#[tauri::command]
pub async fn unlock_with_yubikey(
    state: State<'_, AppState>,
    pin: Option<String>,
) -> Result<LoginOk> {
    let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to unlock".into(),
    })?;
    let block = persisted
        .yubikey_unlock
        .clone()
        .ok_or_else(|| Error::Storage {
            reason: "no yubikey wrap stored — enrol after a master-password unlock first".into(),
        })?;

    let unwrap_result = tauri::async_runtime::spawn_blocking(move || {
        yubikey_unlock::unwrap_user_key(&yubikey_unlock::CtapHidDevice, &block, pin.as_deref())
    })
    .await
    .map_err(|e| Error::Crypto {
        reason: format!("yubikey unlock task panicked: {e}"),
    })?;

    let user_key_bytes = match unwrap_result {
        Ok(bytes) => bytes,
        Err(Error::YubikeyStaleWrap) => {
            // The wrap on disk no longer matches the server's user
            // key (master password rotated elsewhere). Drop it so the
            // unlock view stops offering the Yubikey button until a
            // fresh enrolment after master-password sign-in.
            if let Ok(Some(mut updated)) = store::load_session() {
                updated.yubikey_unlock = None;
                let _ = store::save_session(&updated);
            }
            return Err(Error::YubikeyStaleWrap);
        }
        Err(other) => return Err(other),
    };

    let user_key = SymmetricKey::from_bytes(user_key_bytes.as_slice())?;
    let private_key = persisted
        .encrypted_private_key
        .as_deref()
        .map(|pk| decrypt_private_key(&user_key, pk))
        .transpose()?;
    let refresh_token_plain = recover_refresh_token(&persisted, &user_key)?;

    let client = VaultwardenClient::new(&persisted.server_url)?;
    let device = device_info()?;
    let email = persisted.email.clone();

    // Same fallback as the master-password unlock: the Yubikey has
    // already yielded the user key locally, so an unreachable server
    // must not throw it away. See the comment in `unlock`.
    let mut tokens = match client.refresh_token(&refresh_token_plain, &device).await {
        Ok(tokens) => tokens,
        Err(Error::Network { source }) => {
            eprintln!("[clavix] yubikey unlock: server unreachable ({source}) — opening the cached vault read-only");
            store_standalone_session(
                &state,
                SessionOrigin::OfflineCache,
                user_key,
                private_key,
                HashMap::new(),
                None,
            );
            crate::state::mark_activity(&state);
            return Ok(LoginOk {
                email,
                origin: SessionOrigin::OfflineCache,
            });
        }
        Err(e) => return Err(e),
    };
    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = refresh_token_plain.clone();
    }

    let encrypted_refresh = encrypt_string(&tokens.refresh_token, &user_key)?;
    let mut updated = persisted.clone();
    updated.refresh_token = None;
    updated.encrypted_refresh_token = Some(encrypted_refresh);
    store::save_session(&updated)?;

    store_session(&state, client, tokens, user_key, private_key);
    crate::state::mark_activity(&state);
    Ok(LoginOk {
        email,
        origin: SessionOrigin::Server,
    })
}

/// Clone the unlocked user key out of the session lock for use by a
/// blocking CTAP task. Errors out (rather than silently failing) if
/// no session is open, so a frontend that calls enrol from the
/// unlock view by mistake gets a clean "not authenticated" message.
fn clone_user_key(state: &AppState) -> Result<SymmetricKey> {
    let guard = state.session.lock();
    let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
    // SymmetricKey is not Clone — round-trip through the 64-byte
    // representation, the same shape `from_bytes` already validates.
    let bytes = session.user_key.to_bytes();
    SymmetricKey::from_bytes(bytes.as_slice())
}

/// Mirrors the renderer's auto-lock preference into `AppState`. Called on
/// bootstrap and on every change to the setting.
#[tauri::command]
pub fn set_auto_lock(
    state: State<'_, AppState>,
    trigger: AutoLockTrigger,
    minutes: f64,
) -> Result<()> {
    let minutes = if minutes.is_finite() && minutes > 0.0 {
        minutes
    } else {
        0.0
    };
    // An idle window of zero is the old encoding of "Jamais" — the E2E
    // suite and any pre-0.14 localStorage still speak it. Normalise here
    // so the watchdog only ever sees a coherent pair.
    let trigger = match trigger {
        AutoLockTrigger::Idle if minutes <= 0.0 => AutoLockTrigger::Off,
        other => other,
    };

    let previous = {
        let mut guard = state.auto_lock.lock();
        let previous = *guard;
        *guard = AutoLockSetting { trigger, minutes };
        previous
    };
    // Switching triggers must not inherit the other mode's countdown: a
    // screen-lock observation made while the setting was something else
    // would make the new window expire early — possibly instantly.
    if previous.trigger != trigger {
        *state.screen_locked_since.lock() = None;
    }
    Ok(())
}

/// Whether this desktop session can report its lock state at all, so the
/// settings dialog can warn instead of silently offering a trigger that
/// would never fire. Probes for real rather than checking `cfg!` — the
/// answer depends on the running session (D-Bus screensaver name present,
/// GUI session attached), not on the target we compiled for.
#[tauri::command]
pub async fn screen_lock_available() -> bool {
    crate::screen_lock::probe().await.is_some()
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<()> {
    crate::commands::ssh::stop_agent_sync(&state);
    {
        let mut guard = state.session.lock();
        *guard = None;
    }
    // A pending 2FA slot only matters for an in-flight login; once the
    // session is locked there is no scenario where we want to keep
    // those secrets around.
    clear_pending_two_factor(&state);
    Ok(())
}

#[tauri::command]
pub fn logout(state: State<'_, AppState>) -> Result<()> {
    crate::commands::ssh::stop_agent_sync(&state);
    {
        let mut guard = state.session.lock();
        *guard = None;
    }
    clear_pending_two_factor(&state);
    store::clear_session()?;
    if let Err(e) = cache::clear_all() {
        eprintln!("[clavix] vault cache clear failed: {e}");
    }
    Ok(())
}
