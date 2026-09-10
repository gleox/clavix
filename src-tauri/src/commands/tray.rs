//! System-tray wiring (issue #38).
//!
//! Four responsibilities:
//!   - `build_tray` constructs the tray icon, its right-click menu,
//!     and the left-click toggle. Called once from `lib.rs::run`
//!     setup. Initial build uses French labels to match the
//!     codebase default; the renderer follows up with
//!     `set_tray_locale` once `prefs.bootstrap()` has read the user
//!     locale from `localStorage`.
//!   - `handle_window_event` interprets `WindowEvent::CloseRequested`
//!     against the user's `close_to_tray` preference, and
//!     `WindowEvent::Resized` against `minimize_to_tray`.
//!   - `set_close_to_tray` / `set_minimize_to_tray` are the IPCs
//!     the renderer calls every time the matching preference
//!     changes (and on bootstrap, to hydrate the Rust mirror).
//!   - `set_tray_locale` rebuilds the menu strings without
//!     recreating the tray, so changing the language in Préférences
//!     swaps the labels live.

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};

use crate::state::AppState;
use clavix_core::error::Result;

const TRAY_ID: &str = "clavix-tray";
const ITEM_OPEN: &str = "tray.open";
const ITEM_LOCK: &str = "tray.lock";
const ITEM_QUIT: &str = "tray.quit";
/// Renderer-side listener (see `+page.svelte`) flips the auth phase
/// to `unlock` and clears the vault when this fires, so the UI
/// catches up with the session that the tray menu just dropped on
/// the Rust side. Payload-less; the event itself is the signal.
pub(crate) const EVENT_SESSION_LOCKED: &str = "clavix:session-locked";
// Tauri 2 assigns label "main" to a window declared in tauri.conf.json
// without an explicit `label` field — see tauri-utils
// `default_window_label`. The capability in
// `capabilities/default.json` is scoped to `["main"]` for the same
// reason. Keep this in sync if a label is ever added to the config.
const MAIN_WINDOW: &str = "main";

/// Native tray menu labels per locale. Native menus don't go through
/// Paraglide, so the renderer hands the locale code over IPC and we
/// pick the matching strings here. Anything we don't recognise falls
/// back to French — same default the rest of the app uses.
struct TrayStrings {
    open: &'static str,
    lock: &'static str,
    quit: &'static str,
}

fn tray_strings(locale: &str) -> TrayStrings {
    match locale {
        "en" => TrayStrings {
            open: "Open Clavix",
            lock: "Lock now",
            quit: "Quit",
        },
        // "fr" and any unknown locale share the French default.
        _ => TrayStrings {
            open: "Ouvrir Clavix",
            lock: "Verrouiller maintenant",
            quit: "Quitter",
        },
    }
}

/// Renderer-driven flag that decides what the X button does.
/// Mirrors `prefs.closeToTray` in `src/lib/prefs.svelte.ts`. The
/// renderer calls this on bootstrap (to hydrate the Rust mirror)
/// and again every time the user toggles the preference.
#[tauri::command]
pub fn set_close_to_tray(state: State<'_, AppState>, value: bool) -> Result<()> {
    state
        .close_to_tray
        .store(value, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Sibling of `set_close_to_tray` for the `_` minimise button.
/// Decides whether minimising hides into the tray (true, default)
/// or sends the window to the taskbar (false). Same hydration
/// pattern from the renderer.
#[tauri::command]
pub fn set_minimize_to_tray(state: State<'_, AppState>, value: bool) -> Result<()> {
    state
        .minimize_to_tray
        .store(value, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Renderer-driven flag for the "also drop the dock entry when
/// hidden into the tray" preference. When true, the hide path adds
/// `set_skip_taskbar(true)` so the dock loses the icon and only the
/// tray remains; `raise_main_window` clears it again on restore.
/// Off by default — users who don't have a working tray would
/// otherwise lose all visible affordances. Same hydration pattern
/// as the other tray toggles.
#[tauri::command]
pub fn set_hide_dock_on_tray(state: State<'_, AppState>, value: bool) -> Result<()> {
    state
        .hide_dock_on_tray
        .store(value, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Wire the tray icon onto an `AppHandle`. Failure is non-fatal: a
/// CI runner or a Linux desktop without a system tray (xvfb, plain
/// Sway without `waybar` etc.) just gets a working app without the
/// tray entry. Logs the reason so it's traceable in the dev console.
pub fn build_tray(app: &AppHandle) {
    // Don't reuse `default_window_icon()`: on Linux it picks an entry
    // from `bundle.icon` and feeds it to `TrayIconBuilder` as raw RGBA.
    // Our `icons/32x32.png` ships as 16-bit RGBA — Tauri keeps the
    // declared 32×32 dimensions but the buffer is 8 bytes/pixel, so
    // `TrayIconBuilder::build` rejects it with
    // `wrong data size, expected 4096 got 8192` and the tray is never
    // registered with the StatusNotifierWatcher (error lands in
    // `journalctl --user` since clavix launches from gnome-shell).
    // Decode the PNG ourselves into 8-bit RGBA — `image` is already
    // transitively in our build via arboard, so this is free.
    let icon = match decode_tray_icon() {
        Ok(image) => image,
        Err(e) => {
            eprintln!("[clavix] tray icon setup skipped: {e}");
            return;
        }
    };

    let result = (|| -> tauri::Result<()> {
        let menu = build_menu(app, "fr")?;

        TrayIconBuilder::with_id(TRAY_ID)
            .icon(icon)
            .tooltip("Clavix")
            .menu(&menu)
            .on_menu_event(|app, event| match event.id.as_ref() {
                ITEM_OPEN => show_main_window(app),
                ITEM_LOCK => lock_session(app),
                ITEM_QUIT => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                // Left-click toggles. Right-click opens the menu
                // (handled by the menu wiring above) so we ignore it
                // here. Match on `Up` so the toggle fires once per
                // click rather than twice (Down + Up).
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    toggle_main_window(tray.app_handle());
                }
            })
            .build(app)?;
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("[clavix] tray icon setup failed (non-fatal): {e}");
    }
}

/// Decode the bundled tray PNG into the 8-bit RGBA buffer that
/// `tauri::image::Image::new_owned` expects, regardless of the source
/// file's bit depth. `include_bytes!` bakes the asset into the binary
/// so there is no runtime I/O.
fn decode_tray_icon() -> std::result::Result<tauri::image::Image<'static>, image::ImageError> {
    let bytes: &[u8] = include_bytes!("../../icons/32x32.png");
    let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)?.to_rgba8();
    let (w, h) = img.dimensions();
    Ok(tauri::image::Image::new_owned(img.into_raw(), w, h))
}

fn build_menu(app: &AppHandle, locale: &str) -> tauri::Result<Menu<tauri::Wry>> {
    let s = tray_strings(locale);
    let open = MenuItem::with_id(app, ITEM_OPEN, s.open, true, None::<&str>)?;
    let lock = MenuItem::with_id(app, ITEM_LOCK, s.lock, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, ITEM_QUIT, s.quit, true, None::<&str>)?;
    Menu::with_items(app, &[&open, &lock, &quit])
}

/// Swap the tray menu strings to match the user's locale.
///
/// Called by the renderer on bootstrap (after `prefs.bootstrap()`
/// reads `clavix.locale` from `localStorage`) and on every locale
/// change. The whole locale-change flow already does a window
/// reload, but `setup()` only runs once, so without this IPC the
/// tray would stay in the language it was built with at process
/// start. Failure is non-fatal: a tray that's gone (no system
/// tray on this WM, build_tray skipped earlier) just no-ops.
#[tauri::command]
pub fn set_tray_locale(app: AppHandle, locale: String) -> Result<()> {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return Ok(());
    };
    match build_menu(&app, &locale) {
        Ok(menu) => {
            if let Err(e) = tray.set_menu(Some(menu)) {
                eprintln!("[clavix] tray set_menu failed (non-fatal): {e}");
            }
        }
        Err(e) => eprintln!("[clavix] tray menu rebuild failed (non-fatal): {e}"),
    }
    Ok(())
}

/// Raise the main window and give it focus. Used by the tray
/// (Ouvrir / left-click) and by the single-instance callback in
/// `lib.rs`, where a second launch is answered by surfacing the
/// window the user already has. Two GNOME/X11 quirks stack here:
///
///   1. `tao`'s Linux backend forwards every window op
///      (`show`, `unminimize`, `set_focus`, …) through a glib
///      channel that's only drained once the current callback
///      returns. Worse, `set_focus` short-circuits when
///      `get_visible()` is false — and the visible flag stays
///      false until `show`'s queued request actually runs.
///      Called inline from a tray-menu handler, the Focus
///      request is silently dropped and the window stays buried
///      (or, on Mutter, doesn't appear at all because the
///      always-on-top dance below also needs a Focus to land).
///      `tauri::AppHandle::run_on_main_thread` does *not* fix
///      this: when invoked from the main thread it dispatches
///      synchronously, same problem.
///
///   2. Even with a Focus request queued, Mutter drops focus
///      requests from tray clicks as focus-stealing prevention.
///      Toggling always-on-top forces the WM to raise the
///      window; `set_focus` (which maps to `present_with_time`
///      under the hood) then succeeds.
///
/// Strategy: do the synchronous bring-back-into-visibility ops
/// inline, then hand the focus dance off to the tokio runtime so
/// it bounces back through `run_on_main_thread` from a *non*-main
/// thread. That path uses the tao event proxy, which yields the
/// main loop long enough for the queued show/unminimize to drain
/// and `get_visible()` to return true. No-op on Windows/macOS
/// where `set_focus()` alone already raises — the deferred dance
/// is harmless there.
pub(crate) fn raise_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        // Clear any skip-taskbar hint set on the way down by the
        // hide_dock_on_tray path. Safe to call unconditionally: a
        // no-op when the hint was already false.
        let _ = window.set_skip_taskbar(false);
        let _ = window.unminimize();
        let _ = window.show();

        // Hand off the focus dance to a tokio task so the
        // subsequent `run_on_main_thread` call comes from a
        // worker thread and goes through the tao event proxy
        // rather than the synchronous main-thread fast path.
        // Yielding once is enough on the WMs tested; the sleep
        // is belt-and-braces for slow Mutter under load.
        let win = window.clone();
        let app_handle = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let _ = app_handle.run_on_main_thread(move || {
                let _ = win.set_always_on_top(true);
                let _ = win.set_focus();
                let _ = win.set_always_on_top(false);
            });
        });
    }
}

fn show_main_window(app: &AppHandle) {
    raise_main_window(app);
}

fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        match window.is_visible() {
            Ok(true) => {
                let _ = window.hide();
            }
            Ok(false) | Err(_) => {
                raise_main_window(app);
            }
        }
    }
}

fn lock_session(app: &AppHandle) {
    let state = app.state::<AppState>();
    // Same teardown as `commands::auth::lock`. Inlined rather than
    // calling the Tauri command directly because we hold an
    // `AppHandle`, not the `State<'_, AppState>` shape Tauri's
    // dispatcher would hand us — and we don't need a return value.
    crate::commands::ssh::stop_agent_sync(&state);
    {
        let mut guard = state.session.lock();
        *guard = None;
    }
    crate::session::clear_pending_two_factor(&state);

    // Tell the renderer the session is gone. Without this the UI
    // would happily keep showing the vault until the next IPC call
    // forces a session check — confusing if the window was hidden
    // (close-to-tray) at lock time and the user reopens it later.
    if let Err(e) = app.emit(EVENT_SESSION_LOCKED, ()) {
        eprintln!("[clavix] emit {EVENT_SESSION_LOCKED} failed (non-fatal): {e}");
    }
}

/// Window-event hook. On `CloseRequested`: if `close_to_tray` is set,
/// hide the window and call `prevent_close()` so Tauri leaves the
/// process up. On `Resized` *or* `Focused(false)`: if the window is
/// now minimised and `minimize_to_tray` is set, unminimise + hide so
/// the window lives in the tray rather than the taskbar. Both
/// minimise branches no-op when the preference is off, and the
/// `is_minimized()` guard means clicking through to another window
/// (which also fires `Focused(false)`) is a no-op.
/// Why two minimise triggers: on Windows and most Linux WMs `Resized`
/// fires on every minimise path so `is_minimized()` confirms cleanly.
/// On GNOME Mutter the minimise button is observed *not* to emit
/// `Resized` — Mutter sends focus loss + an `_NET_WM_STATE_HIDDEN`
/// change instead. `Focused(false)` catches that path. macOS minimise
/// (cmd-M to dock) is still best-effort: neither signal is reliable
/// there until upstream tao exposes a dedicated minimise event.
pub fn handle_window_event(app: &AppHandle, event: &WindowEvent) {
    match event {
        WindowEvent::CloseRequested { api, .. } => {
            let state = app.state::<AppState>();
            if !state
                .close_to_tray
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                if state
                    .hide_dock_on_tray
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    let _ = window.set_skip_taskbar(true);
                }
                let _ = window.hide();
            }
            api.prevent_close();
        }
        WindowEvent::Resized(_) | WindowEvent::Focused(false) => {
            let state = app.state::<AppState>();
            if !state
                .minimize_to_tray
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                if matches!(window.is_minimized(), Ok(true)) {
                    // Unminimise first so `hide()` doesn't have to
                    // race the OS minimise animation. Cheap on
                    // Windows; a brief flicker on Linux WMs that
                    // animate minimise is acceptable for the
                    // intended UX (the window disappears into the
                    // tray, not the taskbar).
                    let _ = window.unminimize();
                    if state
                        .hide_dock_on_tray
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        let _ = window.set_skip_taskbar(true);
                    }
                    let _ = window.hide();
                }
            }
        }
        _ => {}
    }
}
