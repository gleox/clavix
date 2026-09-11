# Clavix

[![CI](https://github.com/Upellift99/clavix/actions/workflows/ci.yml/badge.svg)](https://github.com/Upellift99/clavix/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Upellift99/clavix/actions/workflows/codeql.yml/badge.svg)](https://github.com/Upellift99/clavix/actions/workflows/codeql.yml)
[![Latest release](https://img.shields.io/github/v/release/Upellift99/clavix?include_prereleases&sort=semver)](https://github.com/Upellift99/clavix/releases)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](https://github.com/Upellift99/clavix/releases)
[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri%202-24C8DB?logo=tauri&logoColor=white)](https://tauri.app)
[![Website](https://img.shields.io/badge/website-clavix.org-175ddc)](https://clavix.org)

🌐 **Website: [clavix.org](https://clavix.org)**

> ⚠️ **Alpha software.** Do not use with a real Vaultwarden vault yet.
> The cryptography has not been independently audited, no stable release
> has shipped, and a significant portion of the code was produced with
> AI assistance under human review. See [DISCLAIMER.md](DISCLAIMER.md)
> for the full picture before you clone.

**A modern desktop client for Vaultwarden and Bitwarden.**

Clavix is an alternative to the official Bitwarden client and Keyguard,
built for the self-hosted Vaultwarden community. The goal: finally
provide a comfortable tree-based vault with drag & drop, the way
KeePassXC has offered for years.

**Status: alpha, read+write** — item create/edit, full 2FA, an embedded
SSH agent, KeePassXC import and a security audit all work today.

## What Clavix can do today

Against a real Vaultwarden instance, Clavix:

- **signs you in** (email + master password, PBKDF2 and Argon2id
  KDFs), with full **2FA support**: TOTP, YubiKey OTP, and **WebAuthn
  / FIDO2** — Clavix drives the hardware key over CTAP2/HID itself
  so it works even though the desktop app doesn't run under the
  vault's domain;
- **persists the session locally** under `~/.local/share/clavix/` —
  restart lands on an *Unlock* screen that only asks for the master
  password; the access token auto-refreshes 60 s before expiry and the
  refresh token on disk is encrypted under the user key;
- **unlocks with a Yubikey** (optional) — after enrolment, touching a
  registered FIDO2 token releases the cached user key without the master
  password (CTAP2 `hmac-secret`, like Bitwarden Web's "PRF Unlock"). The
  master password stays accepted as fallback, and rotating it on another
  client invalidates the wrap instead of producing wrong decrypts;
- syncs the full vault (items, folders, collections, organizations),
  **encrypting and decrypting everything client-side** (AES-256-CBC +
  HMAC-SHA256 personal, RSA-OAEP-SHA1 org keys), on unlock, on demand,
  and **every 30 min in the background** (cadence configurable in
  Préférences, down to off);
- **creates, edits and deletes items** (logins, secure notes, cards,
  identities, SSH keys) in your personal vault or inside an organization
  you belong to;
- **auto-locks** after your idle window, with a tokio watchdog that drops
  the in-memory session even if the WebView freezes;
- **lives in the system tray**: the X and `_` buttons hide into the tray
  by default (KeePassXC / Bitwarden Desktop semantics); switch either to
  quit / minimise-to-taskbar in Préférences;
- **generates TOTP codes** live from the stored secret (`otpauth://` URIs
  with custom period, digits, hash), and **scans QR codes** through the
  camera to fill the TOTP field;
- **rates password strength** where you choose one — the generator shows
  exact entropy in bits (it reacts when you drop a character class,
  which a guessability score cannot), the editor and the item view show
  a zxcvbn score. Scoring happens in Rust, so the item view can show the
  strength of a password that is **still masked** and never crossed the
  IPC boundary, and so the editor can never contradict the audit;
- keeps an **encrypted SQLite cache**, so the next unlock shows the vault
  instantly; when the server is unreachable the unlock falls back to that
  cache and opens the vault **read-only** (standalone mode);
- **exports an encrypted backup** protected by a password of your choosing
  (Argon2id, every item type), and can reopen one **with no server and no
  account** — the emergency-restore path;
- shows all items with live substring search and **favicons** for logins
  (emoji fallback per type when unavailable);
- navigates a hierarchical **TreeView** from the Bitwarden `/` naming
  convention (personal folders + org collections), with a draggable
  splitter to resize it;
- shows item details with masked fields, one-click copy, and **clipboard
  clearing after 30 seconds**;
- **drag & drops items** onto folders or org collections — including
  personal → org (automatic share + re-encryption), cross-org transfer,
  and all cipher types — and **whole folders** to rearrange the tree,
  cascade-renaming sub-folders on the server;
- **right-click any folder** to rename or delete it (Vaultwarden's web UI
  has no delete control today), including the synthetic path-only parents
  the tree builds from `parent/child` names; both cascade through every
  descendant, so deleting `work` also drops `work/projects`. Same-name
  server folders stay separate instead of being merged;
- runs a **security audit** (🛡) combining HIBP k-anonymity lookups with
  local **reused** and **weak** password detection (zxcvbn ≤ 2);
- **imports a KeePassXC CSV or KDBX export**, creating a folder per
  *Group* on the fly (📥), and reads back its own encrypted backups —
  cards, identities and SSH keys included, which the CSV schema cannot
  carry;
- embeds an **SSH agent** on every platform: exposes the Ed25519 and RSA
  keys from your vault so `ssh`, `git`, `scp`, … use them without the
  private keys ever touching disk — over a Unix socket on Linux and
  macOS, over the `openssh-ssh-agent` named pipe and PuTTY's Pageant
  IPC on Windows.

The master password never hits the server nor the disk: only derived
values are exchanged (master password hash for authentication, master
key for local decryption). Every sensitive key (`MasterKey`,
`SymmetricKey`) derives `ZeroizeOnDrop` to wipe its memory on
destruction.

---

## Using the SSH agent persistently

### Linux / macOS

The agent listens on `$XDG_RUNTIME_DIR/clavix/agent.sock` — usually
`/run/user/<uid>/clavix/agent.sock`. The *Infos* dialog shows the exact
path. Nothing points to it by default, so set it up once:

**For `ssh`, `git`, and GUI apps** — add a drop-in to your SSH config
(`~/.ssh/config`, or a file included from it):

```
Host *
    IdentityAgent /run/user/%i/clavix/agent.sock
```

`%i` expands to your UID. This is the more robust of the two: it also
covers GUI apps launched from the desktop menu, which don't read your
shell startup files.

**For everything else** — export the variable in `~/.bashrc` (or
`~/.zshrc`):

```sh
export SSH_AUTH_SOCK="/run/user/$(id -u)/clavix/agent.sock"
```

Doing both is a good idea. `ssh-add` in particular ignores
`~/.ssh/config` entirely and only reads `$SSH_AUTH_SOCK`, so without the
export `ssh-add -l` reports "The agent has no identities" even when
`ssh` is happily using Clavix.

The socket lives under `/run`, so it disappears on reboot and is
recreated when Clavix starts. A `Connection refused` on that path means
Clavix isn't running, not that your config is wrong.

### Windows

Nothing to set up: there is no `SSH_AUTH_SOCK` story here, and no
environment variable of any kind is involved. Unlocking the vault
exposes the keys on the two endpoints Windows clients already look for:

- `\\.\pipe\openssh-ssh-agent` — the named pipe `ssh.exe`, `ssh-add`
  and Git for Windows probe on their own;
- PuTTY's **Pageant** IPC, so `plink`, `pscp` and `putty` (`-agent`)
  reach the same keys.

`ssh-add -l` is the check that settles it, and the *Infos* dialog has a
button to copy it. Only one agent can own the pipe: if the Windows
OpenSSH `ssh-agent` service (or another compatible agent) already holds
it, Clavix says so rather than starting half-working — stop that
service, or use Pageant-side clients. A real Pageant already running is
not a conflict; Clavix skips its own Pageant window and leaves it alone.

---

## Why this project

The official Bitwarden client (Electron) has a dated UX and does not
offer real tree-drag-and-drop. Keyguard, the most serious alternative,
is read-only without a premium subscription and handles deep
hierarchies poorly. Clavix aims to fill that gap for the self-hosted
community.

## Tech stack

- **Framework** — [Tauri 2](https://tauri.app) (Rust + native WebView)
- **Frontend** — [Svelte 5](https://svelte.dev) + TypeScript + Vite
- **Backend** — Rust (Bitwarden crypto inspired by [rbw](https://github.com/doy/rbw))
- **Drag & drop** — native HTML5 (svelte-dnd-action only if sortable
  lists become needed later)
- **Local session** — JSON files under `~/.local/share/clavix/` with
  0600 permissions (cross-platform via the `dirs` crate)
- **Offline cache** — SQLite (`rusqlite` bundled) with the whole
  `SyncResponse` encrypted by the user key before being stored

> Clavix does **not** use the official Bitwarden SDK (ambiguous
> license). The crypto is reimplemented in-project, under GPL-3.0.

## Roadmap

Everything through read+write is shipped — login and 2FA, the tree view,
drag & drop (including personal → org and cross-org), full item CRUD, the
SSH agent, the security audit and KeePassXC import. See the feature list
above, or [CHANGELOG.md](CHANGELOG.md) for what landed in each version.

### Planned

- 🛂 **ECDSA / DSA** SSH keys in the agent.
- 🌐 **Server-side error translation** (`data.message` from the
  Vaultwarden API is still returned as-is).
- 📦 **Flatpak / Flathub** packaging.
- ✅ **Code signing** for macOS and Windows builds.
- 🗄️ **KDBX** (direct native KeePass file) import.

### Out of scope (for now)

Attachments, Sends, passkeys (storing them in the vault), browser
autofill.

## Development requirements

- **Rust** ≥ 1.85 (edition 2024 required by deps)
- **Node.js** ≥ 20 and **pnpm** ≥ 10

### Ubuntu / Debian

```bash
sudo apt install \
  libwebkit2gtk-4.1-dev \
  libjavascriptcoregtk-4.1-dev \
  libsoup-3.0-dev \
  libxdo-dev \
  libssl-dev \
  librsvg2-dev \
  libayatana-appindicator3-dev \
  libudev-dev \
  build-essential pkg-config curl wget file
```

> `libudev-dev` is pulled in by `hidapi` (used by the FIDO2
> WebAuthn path). Without it, `cargo build` errors out on the
> `hidapi` sys crate.

### Other platforms

See the [Tauri prerequisites](https://tauri.app/start/prerequisites/).

## Run the app in development

```bash
pnpm install
pnpm tauri dev
```

The first Rust compilation takes a few minutes (full Tauri dependency
graph). Subsequent compiles are incremental thanks to the `target/`
cache.

## End-to-end tests (optional)

The WebdriverIO suite (`pnpm test:e2e`) drives the real Tauri binary
against a disposable Vaultwarden container. On top of the base
requirements above, you need:

- **`tauri-driver`** — installed via Cargo into `~/.cargo/bin/`:

  ```bash
  cargo install tauri-driver --locked
  ```

- **WebKitWebDriver + a virtual display** on Linux:

  ```bash
  sudo apt install webkit2gtk-driver xvfb
  ```

- **Docker** + **Docker Compose plugin** — the suite boots a
  Vaultwarden container from `tests/e2e/docker-compose.yml` and tears
  it down on exit. Set `E2E_SKIP_DOCKER=1` to reuse an
  externally-managed instance.

Then build the debug binary once and run the suite under `xvfb-run`:

```bash
pnpm tauri build --debug --no-bundle
xvfb-run -a pnpm test:e2e
```

## Repository layout

```
clavix/
├── src-tauri/        Rust: the desktop app (crate `clavix`), which is
│   │                 also the Cargo workspace root
│   ├── core/         The vault engine (crate `clavix-core`) — no UI
│   │   └── src/      toolkit, no IPC, no Tauri. Buildable on its own,
│   │       │         which is the point: a second front end depends on
│   │       │         this rather than reimplementing it.
│   │       ├── api.rs       Vaultwarden HTTP client
│   │       ├── crypto.rs    Key derivation, EncString (AES / RSA),
│   │       │                encrypt / re-encrypt for server updates
│   │       ├── models.rs    API types and DTOs sent to the UI
│   │       ├── services/    Vault logic (auth token refresh, cipher
│   │       │                body builder, vault summary projection)
│   │       ├── session.rs   Session + pending-2FA material
│   │       ├── store.rs     On-disk session persistence
│   │       ├── cache.rs     Encrypted SQLite vault cache + op-log
│   │       ├── audit.rs     HIBP k-anonymity + reused/weak detection
│   │       ├── totp.rs      RFC 6238 TOTP
│   │       └── error.rs     Unified Error type, serialized as
│   │                        { code, message, data }
│   └── src/          What needs a desktop
│       ├── main.rs         Binary entry point
│       ├── lib.rs          Tauri setup + command registry
│       ├── commands/       Tauri commands, one module per domain
│       │                   (auth, vault, cipher, move_share, ssh,
│       │                   audit)
│       ├── session.rs      Binds AppState to the engine's session slots
│       ├── state.rs        AppState (session, ssh agent handle,
│       │                   tray flags, auto-lock timestamps)
│       ├── ssh_agent.rs    SSH agent (Ed25519 + RSA): Unix socket,
│       │                   Windows pipe + Pageant
│       ├── webauthn.rs     CTAP2 / HID WebAuthn path for 2FA
│       ├── yubikey_unlock.rs  hmac-secret unlock via a FIDO2 key
│       ├── auto_lock.rs    Idle + screen-lock watchdog
│       └── screen_lock.rs  Per-platform session-lock probe
├── src/              SvelteKit frontend (static output, no SSR)
│   ├── app.html
│   ├── lib/
│   │   ├── *.svelte        One component per UI area (AuthGate,
│   │   │                   VaultSidebar, CipherList, CipherDetail,
│   │   │                   CipherEditor, ImportDialog, QrScanner,
│   │   │                   TotpField, …)
│   │   ├── *.svelte.ts     Runes-based controllers
│   │   │                   (auth, vault, prefs, clipboard, drag)
│   │   ├── api.ts          Typed wrappers around Tauri commands
│   │   ├── types.ts        Shared TS types
│   │   ├── totp.ts         RFC 6238 TOTP generator (Web Crypto)
│   │   ├── csv.ts          KeePassXC CSV parser
│   │   └── paraglide/      Compiled i18n (gitignored)
│   └── routes/
│       ├── +layout.svelte  Global styles + locale bootstrap
│       └── +page.svelte    Orchestrates the controllers + layout
├── messages/{fr,en}.json   i18n source strings (paraglide-js)
├── .github/workflows/
│   ├── ci.yml              fmt + clippy + audit + svelte-check +
│   │                       vitest + cargo test
│   ├── codeql.yml          CodeQL scan
│   └── release.yml         Multi-OS release bundles
└── CHANGELOG.md            Per-version notes
```

## Security

- The master password and every derived symmetric key (`MasterKey`,
  `SymmetricKey`) derive `ZeroizeOnDrop`: their memory is wiped on
  scope exit. The password travels through `SecretString` (`secrecy`
  crate), which prevents `Debug` from leaking it into logs.
- All decryption happens **client-side**; the server never sees any
  secret in clear text.
- HMAC verification of AES-CBC ciphertext runs in **constant time**
  (`hmac::Mac::verify_slice`) before decryption.
- The clipboard is automatically cleared **30 seconds** after a copy,
  with a banner counting down.
- The session is persisted to `~/.local/share/clavix/session.json`
  (0600 permissions on Unix). Sensitive fields (`Key`, `PrivateKey`)
  stay encrypted by the stretched master key, and the OAuth2 refresh
  token is itself encrypted under the user key. Clavix still assumes
  your user disk is under your control; full-disk encryption such as
  LUKS is recommended.
- Clavix is primarily tested against **Vaultwarden**, and also works
  with **self-hosted Bitwarden** (same single-domain `/api` + `/identity`
  layout) and **Bitwarden's cloud** (bitwarden.com / bitwarden.eu) — pick
  the region from the **Server** dropdown on the login screen and Clavix
  targets the cloud's split `api.` / `identity.` endpoints. Cloud login,
  sync and item creation are verified, but it remains alpha: Vaultwarden
  is the primary target and gets the most testing.
- Security review notes live in [SECURITY.md](SECURITY.md),
  [THREAT_MODEL.md](THREAT_MODEL.md), [CRYPTO.md](CRYPTO.md), and
  [AUDIT_SCOPE.md](AUDIT_SCOPE.md).

Vulnerabilities should be reported privately to the maintainer before
any public disclosure.

## Quality / CI

Every push and pull request against `master` triggers a GitHub
Actions workflow that runs:

- `cargo fmt --check` — Rust style.
- `cargo clippy --all-targets -- -D warnings` — strict lint.
- `cargo test` — Rust unit tests on crypto, audit, ssh agent,
  webauthn challenge parsing, cipher body builder, and the API
  helpers (`extract_*`, `normalize_base_url`).
- `cargo audit` — vulnerability scan on dependencies
  (RUSTSEC-2023-0071 on the `rsa` crate is ignored, see the comment
  in `.github/workflows/ci.yml`).
- `pnpm check` (svelte-check) — TypeScript / Svelte typing.
- `pnpm test` (vitest) — unit tests on the pure TS helpers (tree,
  filter, drag, format, generator, CSV).
- CodeQL analysis (`javascript-typescript`) on a separate workflow.

Tauri system libraries are installed on every run; the `target/`
cache is handled by `Swatinem/rust-cache`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the setup, code style,
and PR conventions. Security-sensitive changes (`crypto.rs`,
`webauthn.rs`, `ssh_agent.rs`, session storage) should come with
matching tests.

## License

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).
