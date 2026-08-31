# Changelog

All notable changes to Clavix are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.19.3](https://github.com/Upellift99/clavix/compare/v0.19.2...v0.19.3) (2026-08-31)

A maintenance release. Nothing here changes what the application does —
no IPC, storage or vault format changes — so 0.19.3 behaves exactly like
0.19.2 in daily use.

**Unlike 0.19.2, it carries no security fix at all.** Not one of the
updates below closes an advisory: `cargo audit` and `pnpm audit` report
exactly what they reported before, down to the same single ignored
`extract-zip` entry. If you update by pulling manually, this one can
wait for whenever you were going to update anyway.

What prompted it was housekeeping. `chacha20` 0.10.1 was yanked upstream
on 2026-08-27, which tripped the yanked-crates gate on `master` and on
all eight open dependency PRs at the same moment — the same shape of
breakage as 0.19.2's advisories, a red gate with no commit to cause it.
0.10.2 is the published successor and reaches Clavix through `keepass`
and `rand`, so the fix is a lockfile bump. The bug upstream is a
correctness one, not a cryptographic one: the SSE2 backend of the RNG and
64-bit-counter variants emitted an SSE4.1 instruction, so a CPU with SSE2
but without SSE4.1 would take an illegal instruction. That is pre-2008
x86_64, and only where the AVX2 backend is not selected. Nothing was at
risk — a yanked crate simply has no business sitting in the lockfile.

The rest is the usual tree refresh, batched rather than merged one PR at
a time. On the Rust side `argon2` 0.5.3 to 0.6.0, `uuid` 1.24.1 to
1.26.0, `keepass` 0.13.21 to 0.13.25 and `rand` 0.8.7 to 0.8.8; on the
Node side Paraglide 2.25.0, `@types/node` 26.4.0 and the WebdriverIO pair
at 9.31.5, all build- or test-time only and none of them inside the
shipped binary. CI moves `taiki-e/install-action` to 2.87.0, and release
builds stop being uploaded twice — once to the Release and once as a
workflow artifact — which was quietly eating the artifact storage quota.

One change deserves naming, because from the outside it looks like
nothing. `argon2` is a major bump, and it sits on the path that derives
your master key from your password. It compiled clean and passed the
whole test suite — which proved nothing, because until this release
there was **no known-answer test on the Argon2id path at all**, only
checks that weak KDF parameters get refused. A dependency that quietly
changed what the KDF produces would have made every existing Argon2id
vault undecryptable, with the build fully green and nothing to warn us.

So a vector computed with the reference C implementation went in ahead of
the bump, pinning the parts that are ours rather than the crate's: the
SHA-256-of-normalised-email salt, the trim and lower-casing that feeds
it, and the 32-byte output. The derived bytes are identical on 0.5.3 and
on 0.6.0. Your vault unlocks exactly as it did — and from now on that is
something the test suite will notice rather than something we hope for.

## [0.19.2](https://github.com/Upellift99/clavix/compare/v0.19.1...v0.19.2) (2026-08-24)

A dependency release. Nothing here changes what the application does —
no IPC, storage or vault format changes — so 0.19.2 behaves exactly like
0.19.1 in daily use.

**It does carry a security fix, but a small one.** `h2`, the HTTP/2
implementation underneath `reqwest`, moves 0.4.15 to 0.4.18 for
[RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258):
before 0.4.16 it accepted and queued empty DATA frames without limit, so
a peer sending them continuously could push memory up without bound, or
trip a panic if the length overflowed. RustSec rates it low, and the
shape of the bug matters here — Clavix is an HTTP/2 *client*, so the only
peer that can send it those frames is the Vaultwarden server you pointed
it at. Reaching it needs a hostile or compromised server, not a passing
attacker on the network. Worth taking on your next update; not worth an
emergency pull.

The other advisory in this release is **not** a reason to redeploy, and
is named only so it does not resurface as a surprise. `deepmerge-ts`
gains a floor of 8.0.0 for GHSA-ggr8-5vv4-36mx, a stack exhaustion when
merging recursive object graphs. It is a devDependency of the WebdriverIO
test runner: `pnpm audit --prod` is clean before and after, no copy has
ever been inside the shipped binary, and the objects being merged are our
own test configuration. Nothing that runs on your machine was affected.

Both advisories were published after 0.19.1 was tagged, so the two audit
gates went red on `master` without a commit to cause it — which had the
side effect of blocking every open dependency PR until the fix landed.

The rest is the usual tree refresh, none of it user-visible: Svelte
5.56.10 and SvelteKit 2.70.3, Paraglide 2.24.1, WebdriverIO 9.31.2, Vite
8.2.2, Vitest 4.1.11, and `taiki-e/install-action` 2.86.5 in CI. The wdio
bump drops `puppeteer-core` from the tree entirely. Both advisory
suppressions in `pnpm-workspace.yaml` were re-checked against the result
rather than assumed still valid, and both are still load-bearing.

## [0.19.1](https://github.com/Upellift99/clavix/compare/v0.19.0...v0.19.1) (2026-08-17)

A maintenance release: nothing here changes what the application does.
Everything user-facing is identical to 0.19.0 — no IPC, storage or vault
format changes — so there is no reason to hurry an upgrade.

What it carries is the dependency tree. The Tauri runtime moves 2.11.2 to
2.11.5 with the npm `@tauri-apps/*` side bumped in step, 140 transitive
crates are refreshed, and five Rust dependencies land (thiserror, zbus,
futures, rusqlite, ctap-hid-fido2). The tree gets smaller rather than
larger: 38 crates leave with no replacement, because tauri-utils 2.9.3
drops an HTML-parsing stack it no longer needs. It also holds no yanked
crate for the first time, `spin` having moved to an unyanked 0.9.9.

**Not a security release.** `cargo audit` and `pnpm audit` were clean
before and after, so nothing here is a fix for a known vulnerability and
no fleet needs an urgent pull.

One thing to watch on Linux: the tray backend (`tray-icon`) moves 0.23.1
to 0.24.2 as part of the Tauri bump. Nothing the application calls changed
shape, but the tray is not something CI can observe — if the icon
misbehaves in your session, that is the first place to look.


### Miscellaneous Chores

* **deps:** bump Tauri on both sides, cargo and npm together ([#272](https://github.com/Upellift99/clavix/issues/272)) ([d0d204a](https://github.com/Upellift99/clavix/commit/d0d204ad2f40e2f8c1de280bbe9b7ad5cea73bbb))

## [0.19.0](https://github.com/Upellift99/clavix/compare/v0.18.0...v0.19.0) (2026-08-06)


### Features

* password strength, encrypted export, and standalone read-only mode ([#247](https://github.com/Upellift99/clavix/issues/247)) ([eae9922](https://github.com/Upellift99/clavix/commit/eae99224afd2f99d776ba9e795a52ba9708b99e3))

## [0.18.0](https://github.com/Upellift99/clavix/compare/v0.17.0...v0.18.0) (2026-08-03)


### Features

* attachments, custom fields, bulk actions, per-item reprompt ([#241](https://github.com/Upellift99/clavix/issues/241)) ([390850b](https://github.com/Upellift99/clavix/commit/390850b0cadd4a4450e127e9f346acc98966bc78))

## [0.17.0](https://github.com/Upellift99/clavix/compare/v0.16.0...v0.17.0) (2026-08-01)


### Features

* URL on its label's line, double-click to edit, editor keeps your typing ([#231](https://github.com/Upellift99/clavix/issues/231)) ([53b285f](https://github.com/Upellift99/clavix/commit/53b285f654cc0a439a4142931ca042f30df3c52d))

## [0.16.0](https://github.com/Upellift99/clavix/compare/v0.15.0...v0.16.0) (2026-07-31)


### Features

* centred toolbar option, background auto-sync, aligned URL rows ([#229](https://github.com/Upellift99/clavix/issues/229)) ([10ddaa0](https://github.com/Upellift99/clavix/commit/10ddaa0631bab96d63a352458f357e7cd0d91ea6))

## [0.15.0](https://github.com/Upellift99/clavix/compare/v0.14.1...v0.15.0) (2026-07-31)


### Features

* one Clavix per session, and Entrée on the SSH consent prompt ([#227](https://github.com/Upellift99/clavix/issues/227)) ([c69f096](https://github.com/Upellift99/clavix/commit/c69f096c0493c4276ab9cb291c32a81d2daf37b1))

## [0.14.1](https://github.com/Upellift99/clavix/compare/v0.14.0...v0.14.1) (2026-07-30)


### Bug Fixes

* **search:** keep the query when switching folders ([#225](https://github.com/Upellift99/clavix/issues/225)) ([02238c0](https://github.com/Upellift99/clavix/commit/02238c03640df5b6b7b0f96b834b2b29f79abc32))

## [0.14.0](https://github.com/Upellift99/clavix/compare/v0.13.2...v0.14.0) (2026-07-28)


### Features

* **auto-lock:** lock N minutes after the desktop session locks ([#223](https://github.com/Upellift99/clavix/issues/223)) ([be0813d](https://github.com/Upellift99/clavix/commit/be0813d84cc8dd636cc787b5770df22a038089b5))


### Bug Fixes

* **auto-lock:** stop the TOTP poll from defeating the idle watchdog ([#222](https://github.com/Upellift99/clavix/issues/222)) ([b33f976](https://github.com/Upellift99/clavix/commit/b33f976ac6fca0ea180da1a760f8782c7a8a32fe))

## [0.13.2](https://github.com/Upellift99/clavix/compare/v0.13.1...v0.13.2) (2026-07-27)


### Miscellaneous Chores

* cut 0.13.2 ([0c269b9](https://github.com/Upellift99/clavix/commit/0c269b9f096d7f7027342c4d523dba61acb4ebe2))

## [0.13.1](https://github.com/Upellift99/clavix/compare/v0.13.0...v0.13.1) (2026-07-20)


### Bug Fixes

* **import:** learn the server's rate limit instead of guessing it ([#207](https://github.com/Upellift99/clavix/issues/207)) ([036f723](https://github.com/Upellift99/clavix/commit/036f7238c08ff69f4f27f6ea2fad4811a7f9b000))

## [0.13.0](https://github.com/Upellift99/clavix/compare/v0.12.0...v0.13.0) (2026-07-20)


### Features

* **ssh-agent:** show the full fingerprint in the signing prompt ([#204](https://github.com/Upellift99/clavix/issues/204)) ([b3b86c5](https://github.com/Upellift99/clavix/commit/b3b86c51adf77142bb77cb3fc7597ce5eaac7859))


### Bug Fixes

* **import:** back off instead of hammering a server that says no ([#205](https://github.com/Upellift99/clavix/issues/205)) ([d90d43f](https://github.com/Upellift99/clavix/commit/d90d43f6a443657556f24399b5a9bc3575d0f435))

## [0.12.0](https://github.com/Upellift99/clavix/compare/v0.11.2...v0.12.0) (2026-07-20)


### Features

* **ssh-agent:** show full key fingerprints ([#202](https://github.com/Upellift99/clavix/issues/202)) ([924dd88](https://github.com/Upellift99/clavix/commit/924dd88b8f2159b41bb1d33ea8a2f9e9446b2fac))

## [0.11.2](https://github.com/Upellift99/clavix/compare/v0.11.1...v0.11.2) (2026-07-20)


### Bug Fixes

* **ssh-agent:** close the gap in the key list ([#200](https://github.com/Upellift99/clavix/issues/200)) ([41cba2a](https://github.com/Upellift99/clavix/commit/41cba2a188213fa1616ebe881d71a27848ae94bc))

## [0.11.1](https://github.com/Upellift99/clavix/compare/v0.11.0...v0.11.1) (2026-07-20)


### Bug Fixes

* **stats:** exclude trashed items from the counts, widen the dialog ([#198](https://github.com/Upellift99/clavix/issues/198)) ([ca62844](https://github.com/Upellift99/clavix/commit/ca6284429d976cad6167ee2dc2985427a38520d5))

## [0.11.0](https://github.com/Upellift99/clavix/compare/v0.10.0...v0.11.0) (2026-07-20)


### Features

* **ssh-agent:** confirm-before-signing policy + clearer SSH_AUTH_SOCK setup ([#180](https://github.com/Upellift99/clavix/issues/180)) ([75348f7](https://github.com/Upellift99/clavix/commit/75348f772a97d71ad2e76b53eca4e90a824c8a2b))
* **ssh-agent:** optionally restart the agent after an unlock ([#196](https://github.com/Upellift99/clavix/issues/196)) ([3ed5a14](https://github.com/Upellift99/clavix/commit/3ed5a147ab432a9d3ea1daceed946511e0ef301f))
* **ssh-agent:** show the requesting process in the signing prompt ([#194](https://github.com/Upellift99/clavix/issues/194)) ([a0d9627](https://github.com/Upellift99/clavix/commit/a0d9627e163b932d200676c1188d452535a976ec))


### Bug Fixes

* **ssh-agent:** never drop an SSH key without saying why ([#195](https://github.com/Upellift99/clavix/issues/195)) ([8f54c76](https://github.com/Upellift99/clavix/commit/8f54c7684f3bb0b2c4648bbda46390f4f58f0175))
* **ssh-agent:** stop claiming SSH_AUTH_SOCK is misconfigured ([#197](https://github.com/Upellift99/clavix/issues/197)) ([8f0c2d8](https://github.com/Upellift99/clavix/commit/8f0c2d8df22b44a514d03b703725f7afb4b79c6b))

## [0.10.0](https://github.com/Upellift99/clavix/compare/v0.9.3...v0.10.0) (2026-07-17)


### Features

* **login:** Bitwarden cloud region selector (US / EU) ([#177](https://github.com/Upellift99/clavix/issues/177)) ([1ce6d83](https://github.com/Upellift99/clavix/commit/1ce6d83b16405852acf9f774d031f16ea6d3648b))

## [0.9.3](https://github.com/Upellift99/clavix/compare/v0.9.2...v0.9.3) (2026-07-17)


### Bug Fixes

* **yubikey:** auto-detect PIN mode at unlock; clearer enrol/disenrol errors ([#174](https://github.com/Upellift99/clavix/issues/174)) ([9f72406](https://github.com/Upellift99/clavix/commit/9f724063b16bb4ce6096b3875917490bebebe622))

## [0.9.2](https://github.com/Upellift99/clavix/compare/v0.9.1...v0.9.2) (2026-07-17)


### Bug Fixes

* **yubikey:** clear error on unlock key-mismatch; warn on PIN-less option ([#172](https://github.com/Upellift99/clavix/issues/172)) ([33ce9cb](https://github.com/Upellift99/clavix/commit/33ce9cbfaddfca9a18f5f332762a3a4ad856b570))

## [0.9.1](https://github.com/Upellift99/clavix/compare/v0.9.0...v0.9.1) (2026-07-17)


### Bug Fixes

* **sync:** send Bitwarden-Client-Version header so SSH keys sync ([#170](https://github.com/Upellift99/clavix/issues/170)) ([d982315](https://github.com/Upellift99/clavix/commit/d982315448ed89eb8c08bdf97c16780f17744c06))

## [0.9.0](https://github.com/Upellift99/clavix/compare/v0.8.2...v0.9.0) (2026-07-17)


### Features

* **unlock:** reveal toggle + optional PIN prompt for Yubikey, version/link on auth screen ([#168](https://github.com/Upellift99/clavix/issues/168)) ([6aecc3a](https://github.com/Upellift99/clavix/commit/6aecc3a6893fba01a5e21b6f035b4af010b9a7c9))

## [0.8.2](https://github.com/Upellift99/clavix/compare/v0.8.1...v0.8.2) (2026-07-16)


### Bug Fixes

* **import:** stop the preview's horizontal scrollbar overlapping the last checkbox ([#166](https://github.com/Upellift99/clavix/issues/166)) ([8db6a77](https://github.com/Upellift99/clavix/commit/8db6a77499cd69112cd48ae9bfc4d10e3ba84cd7))

## [0.8.1](https://github.com/Upellift99/clavix/compare/v0.8.0...v0.8.1) (2026-07-16)


### Bug Fixes

* **import:** widen preview, fix sticky-header overlap, clarify oversized notes ([#164](https://github.com/Upellift99/clavix/issues/164)) ([a9e806a](https://github.com/Upellift99/clavix/commit/a9e806a265a7b8ea0affa51e0cf93b54c6d64d46))

## [0.8.0](https://github.com/Upellift99/clavix/compare/v0.7.0...v0.8.0) (2026-07-16)


### Features

* **import:** selectable preview of new entries + Enter to unlock with Yubikey ([#162](https://github.com/Upellift99/clavix/issues/162)) ([865517b](https://github.com/Upellift99/clavix/commit/865517b1646a6d3cf01cd00a906f328823e1c03e))

## [0.7.0](https://github.com/Upellift99/clavix/compare/v0.6.0...v0.7.0) (2026-07-16)


### Features

* **ui:** link clavix.org from the About dialog ([#160](https://github.com/Upellift99/clavix/issues/160)) ([9ae9534](https://github.com/Upellift99/clavix/commit/9ae9534fda0d7ec92991d8ecc3430930a172d50c))

## [0.6.0](https://github.com/Upellift99/clavix/compare/v0.5.0...v0.6.0) (2026-07-16)


### Features

* **ui:** About dialog — show version + check for updates manually ([#158](https://github.com/Upellift99/clavix/issues/158)) ([12b76f8](https://github.com/Upellift99/clavix/commit/12b76f8a30eec1f23fccd9fa4b423e2b68d2954a))

## [0.5.0](https://github.com/Upellift99/clavix/compare/v0.4.0...v0.5.0) (2026-07-16)


### Features

* **import:** choose an organization + collection as the import destination ([#146](https://github.com/Upellift99/clavix/issues/146)) ([5f9bedf](https://github.com/Upellift99/clavix/commit/5f9bedf705d11e76982fef85212f77f75d3a266e))
* **ipc:** generate the WebView's types from the Rust ones ([#130](https://github.com/Upellift99/clavix/issues/130)) ([5b8b642](https://github.com/Upellift99/clavix/commit/5b8b64240b9932a47e56374bb3a8d84b5ca7eae3))
* **list:** show the keyboard shortcut on each context-menu action ([#143](https://github.com/Upellift99/clavix/issues/143)) ([8325a8f](https://github.com/Upellift99/clavix/commit/8325a8f1666c4152f89d0594ec2f8a444f045295))
* **update:** notify when a newer version is available, with a link ([#156](https://github.com/Upellift99/clavix/issues/156)) ([f83ea9b](https://github.com/Upellift99/clavix/commit/f83ea9b892f7bc343ab5ff1b42e4ae8083d45c07))


### Bug Fixes

* **ci:** restore withGlobalTauri for the E2E build only ([#157](https://github.com/Upellift99/clavix/issues/157)) ([2263db4](https://github.com/Upellift99/clavix/commit/2263db4acb9924ad34e8ade44e56638099f58258))
* **security:** compute TOTP in Rust, keep the seed out of the WebView (M4) ([726c938](https://github.com/Upellift99/clavix/commit/726c9386c6b62d01234a73bad5f4c1cef975b4ef))
* **security:** floor server KDF params, pin login to the active server, add KAT vectors ([#149](https://github.com/Upellift99/clavix/issues/149)) ([b4a4346](https://github.com/Upellift99/clavix/commit/b4a43469fc46a513c6057615ae4ed9edf70693ce))
* **security:** keep password/card/CVV/SSN out of the WebView, reveal on demand (L1b) ([98655eb](https://github.com/Upellift99/clavix/commit/98655eb70921a429fe50d83f22fd14611cba89cf))
* **security:** keep the SSH private key out of the WebView, reveal on demand (L1a) ([10b652d](https://github.com/Upellift99/clavix/commit/10b652d4378d3615ae2f0051cf89071f956071bd))
* **security:** password/card/CVV/SSN out of the WebView, reveal-on-demand (L1b) ([3957918](https://github.com/Upellift99/clavix/commit/3957918acb987e55cd00b64d53a2bd6c9aa29f56))
* **security:** session/at-rest hygiene batch (M5, L4, L5, L6, L8) ([#150](https://github.com/Upellift99/clavix/issues/150)) ([014ad92](https://github.com/Upellift99/clavix/commit/014ad9212c08406ca7445c844b9444121ecc61d6))
* **security:** share-body fields (L7) + parse_kdbx cap (L2) + RSA advisory (L3) ([#151](https://github.com/Upellift99/clavix/issues/151)) ([ffbdd6e](https://github.com/Upellift99/clavix/commit/ffbdd6e958463dd67468df801fb14e2c6fe23089))
* **security:** tighten CSP connect-src to close the WebView exfil channel ([#148](https://github.com/Upellift99/clavix/issues/148)) ([035e801](https://github.com/Upellift99/clavix/commit/035e8017ecfe5552684fd0c336771f539aa1aa4f))

## [0.4.0](https://github.com/Upellift99/clavix/compare/v0.3.6...v0.4.0) (2026-07-15)


### Features

* KeePassXC shortcuts (Ctrl+T) + right-click context menu; fix reveal-eye overflow ([#132](https://github.com/Upellift99/clavix/issues/132)) ([8b2a6c5](https://github.com/Upellift99/clavix/commit/8b2a6c56cc48fb227209ce74562b282ac62fee9c))

## [0.3.6](https://github.com/Upellift99/clavix/compare/v0.3.5...v0.3.6) (2026-07-15)


### Bug Fixes

* **auth:** stop double-hashing clientDataJSON for the FIDO2 assertion ([#140](https://github.com/Upellift99/clavix/issues/140)) ([57c7e21](https://github.com/Upellift99/clavix/commit/57c7e2135e9e2b64ced8f9f90248f8ad5907d1d5))

## [0.3.5](https://github.com/Upellift99/clavix/compare/v0.3.4...v0.3.5) (2026-07-15)


### Bug Fixes

* **auth:** match the browser's WebAuthn assertion shape (omit userHandle, echo appid) ([#138](https://github.com/Upellift99/clavix/issues/138)) ([f81a98b](https://github.com/Upellift99/clavix/commit/f81a98b6934290d53c9e18ebb57d151f4f2535b2))

## [0.3.4](https://github.com/Upellift99/clavix/compare/v0.3.3...v0.3.4) (2026-07-15)


### Bug Fixes

* **auth:** echo the requested credential id when the key omits it ([#136](https://github.com/Upellift99/clavix/issues/136)) ([2647816](https://github.com/Upellift99/clavix/commit/26478163ee206491f655dc3bb452b99259b36416))

## [0.3.3](https://github.com/Upellift99/clavix/compare/v0.3.2...v0.3.3) (2026-07-15)


### Bug Fixes

* **auth:** honour the WebAuthn AppID extension for U2F-enrolled keys ([#134](https://github.com/Upellift99/clavix/issues/134)) ([a98a22a](https://github.com/Upellift99/clavix/commit/a98a22aa836fdd855227cc76afe2b4bc726649dc))

## [0.3.2](https://github.com/Upellift99/clavix/compare/v0.3.1...v0.3.2) (2026-07-15)


### Bug Fixes

* YubiKey 2FA login (CTAP2 uv option) + notify UI on backend auto-lock ([#131](https://github.com/Upellift99/clavix/issues/131)) ([a5efa61](https://github.com/Upellift99/clavix/commit/a5efa617e5931492e507c2acca2c2b3694c3397f))

## [0.3.1](https://github.com/Upellift99/clavix/compare/v0.3.0...v0.3.1) (2026-07-14)


### Bug Fixes

* **auth:** send the WebAuthn challenge to the WebView under the name it reads ([a963ced](https://github.com/Upellift99/clavix/commit/a963ceda4217c9c056b082530452e339a06476af))
* **ui:** reveal toggle on password entry, and drop the stray space in the item count ([e1f16d1](https://github.com/Upellift99/clavix/commit/e1f16d1febd748259857f65c5399b12d8a8c94cb))
* WebAuthn 2FA never received its challenge, password reveal, stray space in item count ([6cdbabf](https://github.com/Upellift99/clavix/commit/6cdbabf34de308b1c7f7f75c86b90a20bfe7c43e))

## [0.3.0](https://github.com/Upellift99/clavix/compare/v0.2.9...v0.3.0) (2026-07-14)


### Features

* **vault:** term-based search, gated startup view, idempotent re-import ([0669801](https://github.com/Upellift99/clavix/commit/066980186c8b4090b57b222726f99e5473da8ea2))


### Bug Fixes

* cipher key encryption, import losses, search, and release automation ([7e23c7d](https://github.com/Upellift99/clavix/commit/7e23c7d994bd0ca4c51f19dc638638c164eb353b))
* **crypto:** support Bitwarden cipher key encryption ([361dd74](https://github.com/Upellift99/clavix/commit/361dd7417f1e828da402207eb5737b41bf615c3c))
* **import:** surface the entries the server rejects instead of dropping them ([f2e0c0f](https://github.com/Upellift99/clavix/commit/f2e0c0ffc63bc3662232293df129bd868a99bedb))

## [0.2.9] — 2026-07-14

Ships the TOTP freeze fix, which had been sitting on `master`
unreleased since 0.2.8: every 0.2.x build in the wild still hangs
the whole window as soon as a login with a TOTP secret is
displayed. Also carries three dependency security fixes. Patch
bump, no IPC or storage changes.

### Fixed
- **Displaying a TOTP code no longer freezes the entire app.**
  `TotpField`'s `$effect` both wrote `config` and — through the
  `tick()` call in its body — read it back, the textbook
  "effect reads and writes the same piece of state" cycle that
  sends Svelte 5 into an unbounded update loop. Symptom was a
  fully wedged window: the code stayed on its `…` placeholder,
  the item list stopped responding to clicks, and the process had
  to be killed. Config and parse errors are now `$derived` from
  `source`, so the timer effect only ever writes state it does
  not read.
- **Security: quick-xml DoS advisories** (RUSTSEC-2026-0194,
  RUSTSEC-2026-0195).
- **Security: quinn-proto** bumped to 0.11.15 (RUSTSEC-2026-0185).
- **Security: pnpm overrides** migrated to `pnpm-workspace.yaml`
  so they are actually applied to the dependency tree.

## [0.2.8] — 2026-05-23

Follow-up tray fixes — once 0.2.7 made the window label match and
the tray hooks finally fired, two latent issues surfaced under
real-session testing on GNOME/X11. Plus a vault-navigation
papercut where the search filter persisted across folder clicks,
making the sidebar appear unresponsive. Patch bump, no IPC or
storage changes.

### Fixed
- **Tray menu "Ouvrir Clavix" actually restores the window now.**
  After 0.2.7 unblocked the close-to-tray path, the open-from-tray
  recipe (`show` + `unminimize` + always-on-top dance +
  `set_focus`) still left the window buried — symptom: clicking
  "Ouvrir Clavix" produced no visible change. Root cause was a
  race in `tao`'s Linux backend: every window op the recipe
  queues goes through a glib channel that's only drained after
  the current callback returns, and `set_focus` short-circuits
  when `get_visible()` is still false. The Focus request (which
  maps to `gtk_window_present_with_time`, the all-in-one show +
  raise + focus GTK call) was therefore never sent. Fix bounces
  the focus dance through a tokio task so the subsequent
  `run_on_main_thread` call comes from a worker thread and goes
  through the tao event proxy rather than the synchronous
  main-thread fast path — that yields the loop long enough for
  the queued `show()` to commit before `set_focus` runs.

- **Tray menu "Verrouiller maintenant" updates the UI immediately.**
  The menu handler tore the session down on the Rust side
  (SSH-agent handle, in-memory session, pending two-factor slot)
  but emitted nothing toward the renderer, so the WebView kept
  showing the vault until the next IPC call hit a "no session"
  error — and a window that was closed-to-tray at lock time came
  back open on the vault when the user reopened it from the tray.
  Lock now emits `clavix:session-locked` after the teardown; the
  renderer listens in `+page.svelte` and reuses the existing
  `lockAndReset` helper to flip the auth phase to `unlock` and
  drop the cached vault.

- **Sidebar navigation no longer feels frozen after a search.**
  Clicking a folder or quick-filter (Tous, Favoris, Corbeille,
  Types…) now clears the search input. Previously
  `selectQuickFilter` and `selectNode` only touched `selectedKey`
  / `quickFilter`, leaving `searchDebounced` in place;
  `applyVaultFilters` then ANDed the stale query against the
  newly selected node and typically filtered the list to zero
  results — symptom: the click "did nothing." Both methods now
  also reset `search` and `searchDebounced` synchronously, so the
  filter recomputes on the same tick instead of after the 150 ms
  debounce window (which would have reproduced the same
  dead-click feel).

### Maintenance
- Dependency refresh: `keepass` 0.12.5 → 0.12.9, `tokio` bump,
  `ctap-hid-fido2` 3.5.9 → 3.5.10, `vite` 8.0.10 → 8.0.14,
  `@inlang/paraglide-js` bump, `@types/node` 25.6.0 → 25.9.0.
  Plus a pinned `kysely` 0.28.17 pnpm override to keep the
  transitive resolution stable.

## [0.2.7] — 2026-05-19

Bug-fix release. Three tray preferences shipped over the last two
versions never actually took effect on the close / minimise / dock
paths — chasing the runtime diagnostics flagged in 0.2.6 turned up
the mismatch instantly. Patch bump, no IPC or storage changes.

### Fixed
- **Close-to-tray, minimize-to-tray and hide-dock-on-tray now apply.**
  `commands::tray` looked the main window up by label `"clavix"`, but
  `tauri.conf.json` declares the window without an explicit `label`,
  so Tauri 2 assigned it the default label `"main"` (see tauri-utils
  `default_window_label`; the capability in
  `capabilities/default.json` was already correctly scoped to
  `["main"]`). Every `app.get_webview_window("clavix")` returned
  `None`, so the close / minimise / tray-click branches silently
  skipped their `hide()` / `set_skip_taskbar()` / `unminimize()`
  calls. CloseRequested still called `prevent_close()`, so the X
  button appeared to do nothing instead of hiding to the tray —
  matches the "X-button-doesn't-hide" symptom deferred in the 0.2.6
  notes. Fix is a one-line constant change with a doc-comment
  pinning the invariant to the capability scope so a future
  config tweak surfaces this again.

## [0.2.6] — 2026-05-18

Three UX-quality wins driven by feedback after 0.2.5 landed. Patch
bump because no IPC contract changes (the new tray IPC is additive)
and `session.json` from 0.2.5 unlocks unchanged. The X-button-doesn't-
hide bug reported alongside is not addressed here — needs runtime
diagnostics on Tauri 2.11 + WebKitGTK first.

### Added
- **"Hide dock when in tray" preference**. New toggle in Préférences
  next to the existing close- / minimize-to-tray dropdowns. When on,
  the dock / taskbar entry vanishes the moment the window is hidden
  into the tray (`set_skip_taskbar(true)` on hide,
  `set_skip_taskbar(false)` on restore), so the tray icon becomes the
  only visible affordance. Off by default on every platform — users
  who don't have a working tray would otherwise lose all entry points
  to the running app. Same `set_*` IPC + AtomicBool mirror shape as
  the other two tray prefs.

### Changed
- **Vault remembers the last selected folder and quick-filter across
  sessions**. Landing on "Tous les éléments" every launch was noisy
  for vaults with many ciphers. `selectedKey` and `quickFilter` now
  persist to localStorage on every change once a vault is loaded, and
  are restored in the `VaultController` constructor. The persist hook
  is gated by `summary != null` so locking (which calls `reset()`)
  doesn't erase the stored selection. Quick-filter is validated on
  restore — `all` / `favorites` / `trash` literal, or `type:<digits>`
  for cipher kinds — so garbage in localStorage doesn't poison state.
- **Auth screens (login / unlock / 2FA / onboarding) use Atkinson
  Hyperlegible at ~10% larger sizing**. The accessibility-tuned font
  was already loaded in the bundle for cipher detail values for the
  same reason — disambiguating ambiguous characters (g/q, b/d, 1/I/l)
  matters most where misreading a master password costs the most. A
  `.auth-screen` wrapper added in `+page.svelte` scopes the change to
  the pre-login surfaces; the vault UI stays in Inter at default
  sizes. Zero KB cost since the font was already shipped.

## [0.2.5] — 2026-05-18

The other half of the Linux tray story: 0.2.4 finally got the icon
shape past `TrayIconBuilder`, but two further GNOME-specific issues
hid behind it. Plus a Tauri security bump. Patch bump because no IPC
contract changes and `session.json` from 0.2.4 unlocks unchanged.

### Fixed
- **Tray icon now actually renders and the click menu actually
  responds on Ubuntu GNOME**. With Tauri 2.10 / `tray-icon` 0.21 the
  icon arrived at the `StatusNotifierWatcher` (0.2.4 fix) but rendered
  as a black square and absorbed clicks without dispatching them.
  Bumping Tauri to 2.11.2 pulls in `tray-icon` 0.23.1, where the
  pixmap encoding and click-event plumbing for AppIndicator-on-X11
  are repaired.
- **"Ouvrir Clavix" from the tray menu raises the window**. The
  standard `show()` + `unminimize()` + `set_focus()` recipe lands on
  X11/GNOME but Mutter silently drops the focus request as
  focus-stealing prevention — the window comes back from hidden but
  stays buried behind whatever was on top. A brief
  `set_always_on_top(true)` / `set_always_on_top(false)` toggle
  around the focus call forces the WM to put the window above its
  siblings; releasing the constraint lets normal stacking resume.
  Same fix applies to the left-click toggle on the tray icon
  (Windows / macOS path unchanged, `set_focus` already raises there).
- **`_` minimise button now respects `minimize_to_tray` on GNOME**.
  The handler watched `WindowEvent::Resized` which fires on minimise
  on Windows and most Linux WMs, but Mutter goes straight to focus
  loss without synthesising a resize. Hook `Focused(false)` as a
  second trigger, guarded by the same `is_minimized()` check so
  ordinary click-away on another window stays a no-op.

### Security
- **`tauri` 2.10.3 → 2.11.2 (cargo + npm, lockstep)**. Picks up
  GHSA-7gmj-67g7-phm9: Origin Confusion lets a remote page in the
  webview invoke local-only `#[tauri::command]` handlers. Clavix has
  30+ such handlers covering auth, ssh-agent and session unlock — not
  a class of bug to carry on a password manager. Bumped by hand per
  `f4e6a28`: tauri-action rejects builds when the Cargo `tauri` and
  the npm `@tauri-apps/*` resolved versions drift on major / minor,
  so Dependabot is configured to ignore both sides and these bumps
  move together by hand.

## [0.2.4] — 2026-05-18

A single-fix patch for the Linux tray icon that 0.2.3 advertised but
never managed to draw on stock Ubuntu GNOME, even with the
AppIndicators extension active. Patch bump because no IPC contract
changes and `session.json` from 0.2.3 unlocks unchanged.

### Fixed
- **Tray icon now actually appears in the GNOME top bar when
  AppIndicators is active**. `build_tray` reused
  `app.default_window_icon()`, which on Linux resolves to an entry
  from `bundle.icon` that Tauri hands to `TrayIconBuilder` as raw
  RGBA. Our `icons/32x32.png` ships as 16-bit RGBA (8 bytes per pixel)
  so the buffer is 8192 bytes for declared 32×32 dimensions, and
  Tauri's `TrayIconBuilder::build` rejects the image with
  `wrong data size, expected 4096 got 8192`. The error landed silently
  in `journalctl --user` since clavix launches from gnome-shell, the
  tray was never registered with the `StatusNotifierWatcher`, and the
  `close_to_tray` / `minimize_to_tray` toggles in Préférences had
  nothing to fall back on regardless of how they were set. The builder
  now decodes `icons/32x32.png` itself via the `image` crate (already
  in the build graph through `arboard`, no new transitive dep),
  coercing to 8-bit RGBA regardless of the source file's bit depth.
  Visible result: on a GNOME session with AppIndicators active, the
  Clavix icon appears next to the clock with the same Ouvrir /
  Verrouiller / Quitter menu it always had, and left-click toggles
  the main window. The 0.2.3 default-off behaviour for `close_to_tray`
  on Linux is unchanged — users who explicitly opt in now get a tray
  that exists.

## [0.2.3] — 2026-05-10

A single-fix patch for a Linux desktop trap shipped in 0.2.2: clicking
the X button could leave the window invisible with no way back. Patch
bump because no IPC contract changes and `session.json` from 0.2.2
unlocks unchanged.

### Fixed
- **X button no longer strands the window into an invisible tray on
  Linux**. `close_to_tray` and `minimize_to_tray` defaulted to `true`
  on every platform so the window would hide into the system tray on
  close/minimise — fine on Windows / macOS, broken on Linux. On stock
  Ubuntu GNOME the `ubuntu-appindicators` extension can sit
  *enabled-but-INACTIVE* at runtime; Tauri's `TrayIconBuilder`
  succeeds and `tray_by_id()` returns `Some`, but GNOME draws nothing
  in the panel. Result: clicking X hid the window into a tray that
  didn't exist visually, the process kept running, and the user had
  no way to bring the window back. Both the Rust mirror
  (`src-tauri/src/state.rs`) and the renderer default
  (`src/lib/prefs.svelte.ts`) now key the default off the platform —
  Linux defaults to *quit*, Windows / macOS keep the hide-to-tray
  behaviour. Linux users with a working tray (KDE Plasma, a healthy
  AppIndicator extension) can still flip both toggles on in
  Préférences and the choice persists. The bootstrap also now honours
  an explicit `"true"` in `localStorage`, not just `"false"` —
  required so a Linux user who opted in actually keeps hide-to-tray
  across restarts.

## [0.2.2] — 2026-05-09

A pure bug-fix release that lands a session of UI testing — every
visible anomaly the user could find without leaving the main flow.
Patch bump because no IPC contract changes and `session.json` from
0.2.1 unlocks unchanged.

### Fixed
- **Native context menu no longer leaks outside text fields**. Right-
  clicking anywhere except a folder in the sidebar used to surface
  WebKitGTK's default menu (Reload / Back / Forward / Inspect Element)
  on top of the app — wrong for a packaged password manager. A global
  `oncontextmenu` on the root layout now suppresses the native menu
  except inside `<input>`, `<textarea>` or contenteditable surfaces, so
  Paste / Copy / Spell-check still work where it matters. The folder
  right-click menu in `VaultSidebar` is unaffected — its handler runs
  in bubble phase first and is idempotent w.r.t. preventDefault.
- **Folder context menu clamps inside the viewport**. Right-clicking
  a folder near the bottom or right edge used to paint the
  Renommer / Supprimer menu past the viewport edge, clipping the
  Supprimer row. We measure the menu after layout and tug
  `menuX` / `menuY` back inside with an 8 px inset; re-clamps when the
  user right-clicks a different folder while the menu is already open.
- **Escape closes custom dialogs from inside the panel**. CipherEditor,
  ImportDialog, ExportDialog and QrScanner all use a backdrop+panel
  layout where the panel calls `e.stopPropagation()` on keydown to
  keep editing keystrokes from triggering the global vault shortcuts.
  But that swallowed Escape too, so pressing it while focused on any
  input inside one of those dialogs did *nothing* — only the native
  `<dialog>`-based ones (Audit / Generator / Stats) closed because the
  browser handles Escape there. Each panel now calls `onCancel()` on
  Escape itself before stopping propagation; non-Escape keystrokes
  still don't escape the panel.
- **Force-dark theme stops painting every styled button primary
  blue**. The user-toggled dark theme rules in `base.css` were written
  as `:root.force-dark <tag>` (specificity 0,2,1), higher than
  Svelte-scoped overrides like `.tb-btn { background: transparent }`
  (0,2,0). System dark mode worked because `@media`-wrapped rules stay
  at 0,0,1 and lose to scoped classes — the bug only surfaced when
  toggling the theme to "Dark" inside the app. Every styled `<button>`
  — toolbar, cipher rows, column headers, sidebar nodes, detail
  copy/eye icons — got painted in the global primary blue (#396cd8).
  Wrap the ancestor in `:where(...)` so all force-dark rules collapse
  to the same specificity as their `@media` counterparts and scoped
  overrides win the cascade exactly as they do in light mode.
- **Dialog checkbox rows on a single line**. `base.css` sets `label
  { flex-direction: column }` (correct for the auth/login forms whose
  inputs sit below their text), but the dialog checkbox rows reused
  the same `<label>` wrapping with only `display: flex` overridden.
  That stacked the checkbox above its label text in GeneratorDialog
  (5 checkboxes — Majuscules / Minuscules / Chiffres / Symboles /
  Éviter ambigus), ImportDialog ("Créer dossiers manquants") and
  ExportDialog ("Inclure logins" / "Inclure notes"). Force
  `flex-direction: row` on each definition; ExportDialog had no scoped
  `.checkbox-row` style at all and silently fell back to base — fixed
  there too.
- **Settings dialog scrolls inside its frame instead of spilling
  beyond the viewport**. Native `<dialog>` elements have a UA-default
  max-height (~viewport - 1 rem) but their default overflow is
  visible, so the long Settings dialog (Coffre + Préférences + SSH
  agent + YubiKey unlock) silently spilled past the bottom edge of the
  window on shorter screens. Cap `.stats-dialog` at
  `calc(100vh - 2rem)` and add `overflow-y: auto`. Audit and Generator
  inherit harmless behaviour — their content is short and their inner
  lists already had their own `max-height`.
- **ClipboardToast through paraglide**. The clipboard countdown toast
  (*Presse-papier (titulaire) effacé dans 30s*) and its *Effacer
  maintenant* button were hardcoded in French, so users on the English
  locale saw French strings whenever a copy timer was active. Both
  keys (`clipboard_toast`, `action_clear_now`) already existed in
  `messages/fr.json` and `messages/en.json` — the toast just never
  migrated to paraglide.
- **KDBX password label associated with its input**. The label sat
  above the password input row inside the KDBX import flow but had
  no `for=` attribute, so screen readers couldn't follow the
  label-to-control link and clicking the label didn't focus the
  field. Wired with `id="import-kdbx-password"` / `for=`.

## [0.2.1] — 2026-04-28

### Added
- **Native KDBX import** alongside the existing CSV path (#50). The
  📥 dialog now accepts `.kdbx` next to `.csv`. KeePass / KeePassXC
  databases come in directly with master password, group hierarchy,
  notes and the KeePassXC `otp` custom field intact — better
  fidelity than the CSV round-trip, which loses the otpauth URI
  and the deep group nesting. Backed by the `keepass` crate (v0.12)
  on the Rust side; the renderer's existing import loop replays both
  sources uniformly. Limitations: no keyfile auth, no
  challenge-response auth, no attachments. File a request if you
  hit one of those.
- **Localised tray menus** (#51). Native menus don't go through
  Paraglide, so the strings stayed hard-coded in French regardless
  of the language picked in Préférences. They now switch live: the
  renderer hands the locale code over via a new `set_tray_locale`
  IPC and Rust rebuilds the menu via `tray.set_menu(...)`. English
  and French wired today; unknown locales fall back to French.

### Changed
- **Localised Vaultwarden auth-error messages** (#49). Until now
  the server's `data.message` flowed through to the UI in English
  (or whatever Vaultwarden's locale was). The Rust side now
  classifies five known auth-error patterns into a stable `reason`
  code attached to the serialised `AuthFailed` payload, and the
  renderer switches on it to pick a Paraglide string. Reasons
  covered: `invalid_credentials`, `two_factor_invalid`,
  `refresh_expired`, `captcha_required`, `user_not_found`. The
  classifier is purely additive — an unknown server message still
  surfaces verbatim. App-internal `AuthFailed` strings (move-share
  guards, etc.) deliberately don't match any pattern; they keep
  their existing copy.

## [0.2.0] — 2026-04-28

### Added
- **System-tray integration** (#38). Tray icon visible while the
  app runs. Right-click menu (Ouvrir Clavix / Verrouiller maintenant
  / Quitter); left-click toggles the main window between hidden and
  shown. Native menu strings stay French because Paraglide doesn't
  reach native menus — documented inline. The X button now hides
  into the tray by default instead of quitting (KeePassXC and
  Bitwarden Desktop semantics); the same shape applies to the `_`
  minimise button. Both behaviours are configurable from
  Préférences (`Bouton Fermer` and `Bouton Réduire` dropdowns) — the
  renderer mirrors each toggle into an `AtomicBool` on `AppState`
  via `set_close_to_tray` / `set_minimize_to_tray` so the
  window-event hook always sees the latest value without a mutex on
  the main loop. Tray setup is non-fatal: a CI runner under xvfb or
  a Linux WM without a system tray launches the app fine, just
  without the tray entry. Lock-from-tray inlines the same teardown
  as `commands::auth::lock` (ssh-agent stop, session drop,
  pending-2FA clear) since the menu handler holds an `AppHandle`,
  not the `State<'_, AppState>` shape Tauri's dispatcher provides.
  macOS minimise (cmd-M to dock) is best-effort: tao does not
  expose a dedicated minimise event, so the `Resized` + `is_minimised()`
  detection that works on Windows and most Linux WMs may not fire
  on every macOS minimise path.
- **Cascade folder rename + delete from the sidebar** (#39).
  Vaultwarden has no real folder hierarchy on the server: a folder
  named `work/projects` and a folder named `work` are two
  independent rows. The sidebar paints them as a tree by splitting
  on `/`, which means `work` can show up as a *synthetic* parent —
  a path container the UI made up. Right-click did nothing on those
  nodes, and deleting a real `work` orphaned its `work/...`
  children. Right-click now opens the menu on any folder node, real
  or synthetic; both Rename and Delete cascade through every folder
  whose path equals or sits under the clicked node. Delete reuses
  `delete_folder` in a loop after collecting descendant ids via
  `collectFolderIds`; rename calls a new `rename_folder_path` Tauri
  command that reuses the same `plan_folder_renames` machinery as
  `move_folder_path`, so the rename batch is atomic on the Rust
  side. Confirmation dialog now reports the sub-folder count when
  more than one folder is going to be deleted. New E2E spec
  `folder-rename-delete-path.spec.mjs` covers cascade rename of a
  real parent with two levels of descendants, cascade rename of a
  synthetic parent (no row on the server, only `parent/leaf`), and
  cascade delete of a parent + multiple descendants.

### Internal
- **Integration test for `ensure_fresh_tokens` orchestration** (#46,
  closes #24). Closes the orchestration gap left by the existing
  two integration tests: `refresh_token_endpoint.rs` proves the
  HTTP contract, `persisted_session_disk.rs` proves the disk
  round-trip, and now `token_refresh_lifecycle.rs` exercises the
  in-memory `Session` mutation, the re-encryption under the user
  key, and the rewrite of `session.json` in lockstep. Three
  scenarios: rotation when the on-disk session is already in the
  post-migration shape, legacy migration when `refresh_token` is
  set in plaintext (the load-bearing security claim against a
  stolen disk image), and a no-op when `expires_at` is comfortably
  ahead of the safety margin. Reachable from `tests/` because
  `ensure_fresh_tokens` was rewritten to take `&AppState` directly
  — production call sites still pass `&State<'_, AppState>` and
  the `State<'r, T>: Deref<Target = T>` impl makes the coercion
  free, so no command needed to change. CI now runs `cargo test
  --tests` instead of `--lib`, which also picks up the two
  pre-existing integration tests that had been silently uncovered.
- **Dependabot ignore lists for the upstream-blocked majors.**
  `rsa` stable is still 0.9.x (0.10 is RC), which pins the
  codebase to `rand_core 0.6` and `digest 0.10`. Any major bump of
  `rand`, `sha2`, `sha1`, `hmac`, `hkdf`, `pbkdf2`, `aes`, or `cbc`
  fails to link against `rsa`; PR #31 (rust-crypto group) and #35
  (rand 0.9) just cycled red on this. The ignore lives in
  `.github/dependabot.yml` and is annotated with the unblock
  condition. Same shape for `@wdio/*`: the runtime plugin loader
  enforces matching majors across cli / local-runner /
  mocha-framework / spec-reporter, so a single-package major
  always lands E2E red (PR #43). Added a `wdio` group so future
  coordinated bumps land as one PR, plus a semver-major ignore so
  isolated majors stop being filed.

### Changed
- npm minor + patch bumps that landed clean: `vite` 6→8 (#44),
  `vitest` 4.1.4→4.1.5 (#45), `@inlang/paraglide-js` 2.16→2.17
  (#42), the `svelte` group (#41).

## [0.1.20] — 2026-04-27

### Added
- **Yubikey re-unlock with FIDO2 hmac-secret.** After a normal
  master-password sign-in, the user can release the cached user key
  by touching a registered FIDO2 token instead of re-typing the
  password. Conceptually the same flow as Bitwarden Web's "PRF
  Unlock"; under the hood we register a non-resident credential
  with the CTAP2 `hmac-secret` extension turned on, derive a wrap
  key via HKDF-SHA256 from the per-credential PRF output, and wrap
  the 64-byte user key under it using the existing AES-256-CBC +
  HMAC-SHA256 EncString primitive (same code path the rest of the
  app already runs through). The wrap, the per-credential salt, the
  credential id and a 16-byte HKDF fingerprint of the user key live
  in `session.json`; the wrap key never touches disk. Stale-wrap
  detection: rotating the master password on another client
  invalidates the fingerprint, the unlock command drops the wrap
  and surfaces a clear "re-enrol after sign-in" message instead of
  handing back a key the server no longer accepts. Three new Tauri
  commands (`enroll_yubikey_unlock`, `unlock_with_yubikey`,
  `disenroll_yubikey_unlock`) plus `yubikey_unlock_state` for the
  unlock view to know whether to render the touch button. UI lives
  in Préférences (enrol / disenrol with explicit threat-model
  warning, master-password confirmation required to disenrol) and
  on the unlock view (touch button next to the password field, PIN
  input for tokens with one set). The full design + threat-model
  addendum landed in `YUBIKEY_UNLOCK.md` and `THREAT_MODEL.md`
  ahead of any code; CTAP I/O sits behind a `FidoDevice` trait so
  the crypto path is fully covered by unit + property tests
  without a real authenticator on the runner.
- **Right-click delete + rename on personal folders.** Vaultwarden's
  web UI doesn't expose a folder-delete control today (upstream
  Bitwarden does — looks like a regression), so for users with
  cluttered or duplicate folders Clavix is now the only path. Right-
  click on a folder leaf in the sidebar pops up a small menu with
  Rename and Delete; rename is an inline editable input, delete
  confirms before firing and matches Bitwarden semantics (ciphers
  detach to "no folder", they are not cascade-deleted). Two new
  Tauri commands (`delete_folder`, `rename_folder`) wrap the
  pre-existing HTTP layer in `api.rs`; both update the in-memory
  vault in lockstep so the sidebar reflects the change without a
  full re-sync. New E2E spec `folder-rename-delete.spec.mjs`
  exercises both commands through the IPC layer (mirrors the
  cascade spec — synthetic right-click under WebDriver is too
  brittle, the menu's only job is to call these handlers anyway).
- **"Mon coffre" header** above the personal folder tree, mirroring
  the existing "Organisations" h4 — clearly separates personal
  items from shared org items at a glance.

### Fixed
- **Same-name folders no longer collapse into one sidebar entry.**
  `insertIntoTree` matched leaves by label, so two server-side
  folders named "Finance" merged into a single node and the second
  silently rewrote the first's `folderId` — every cipher in folder
  #1 disappeared from the tree (the count was still right under
  "All items", but you couldn't filter to it). The fix keeps merging
  *synthetic-parent* nodes (so "work/a" and "work/b" still hang
  under one shared "work" ancestor) but creates a sibling when two
  real folders share a path. Disambiguator suffix on the colliding
  React-style key keeps Svelte happy without polluting the natural
  path key for the common single-folder case;
  `folderPathFromKey` strips the suffix back so drag-drop and
  `move_folder_path` continue working unchanged. New tests cover
  the duplicate cases.

## [0.1.19] — 2026-04-26

### Added
- **CSV export** matching Bitwarden Desktop's column set
  (`folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`),
  so the resulting file imports directly back into Bitwarden if you
  decide to migrate elsewhere. Toolbar gets a new upload-arrow button
  next to import; the dialog shows live counts per type, lets you
  toggle Logins / Secure Notes independently, displays a warning
  banner about plaintext-on-disk, and triggers the download via a
  Blob URL named `clavix-export-YYYY-MM-DD.csv`. Cards, Identities,
  SSH keys and trashed items are skipped — same as Bitwarden's own
  CSV export — since the column schema doesn't carry their fields.
  New `csv.ts` helpers: `escapeCsvField` and `serializeBitwardenCsv`,
  both covered by vitest including a CSV roundtrip via `parseCsv`.
- **Generate an Ed25519 SSH key from the cipher editor.** When you
  open a new SSH-key cipher and the private-key field is still empty,
  a "Générer une clé Ed25519" button shows up above the textarea —
  one click runs `ssh_key::PrivateKey::random` server-side and fills
  privateKey + publicKey + keyFingerprint with a fresh OpenSSH PEM,
  ssh-ed25519 line and SHA-256 fingerprint. The key is generated
  in the Rust process, never touches disk, and lands directly in
  the cipher (which is then encrypted under the master key like any
  other field). RSA generation can come later as an algorithm
  parameter; users with infra requiring RSA can paste an existing
  key for now. New Tauri command `generate_ssh_key`.
- **Detailed SSH agent panel.** The agent section in Préférences now
  lists every exposed key by comment + algorithm + truncated SHA-256
  fingerprint (full hash on hover via `title`), so you can tell at a
  glance which keys `ssh-add -l` will surface. Below it, a
  `<details>` summary shows skipped keys with a per-key reason —
  ECDSA/DSA unsupported algorithm, leftover passphrase-encrypted PEM
  pre-dating the import-time decrypt flow, malformed key, etc. A new
  `ssh_auth_sock` Tauri command reads the `SSH_AUTH_SOCK` env var so
  the dialog can show "✓ pointe sur Clavix", "pointe ailleurs" or
  "non définie" inline next to the socket path. The `SshAgentStatus`
  shape now carries `keys: ExposedKey[]` and `skipped: SkippedKey[]`
  instead of the previous opaque counts.

## [0.1.18] — 2026-04-26

### Added
- **SSH passphrase prompt at cipher import.** When you paste a
  passphrase-protected OpenSSH private key into the cipher editor,
  Clavix now asks for the passphrase, decrypts the PEM client-side,
  and stores the cleartext key inside the cipher (which itself stays
  encrypted at rest under the master key). Same model as Bitwarden
  Desktop's `import_key`: the passphrase is consumed once and never
  stored. Public key and SHA-256 fingerprint are auto-filled when
  empty. ECDSA / DSA inputs are rejected up front before any
  passphrase prompt, so you don't type a passphrase for nothing.
  New Tauri command `decrypt_ssh_private_key` with typed errors
  `ssh_passphrase_required` and `ssh_wrong_passphrase`. Closes the
  silent-skip behaviour where `start_ssh_agent` would just bump
  `skipped_count` for any encrypted key in the vault.

### Tests
- **End-to-end SSH passphrase import spec**
  (`tests/e2e/specs/ssh-passphrase-import.spec.mjs`). Drives the new
  prompt through the real Tauri WebView: generates a fresh
  passphrase-protected ed25519 key (and a no-passphrase ECDSA key)
  via `ssh-keygen` in the `before` hook, opens the cipher editor,
  asserts the passphrase prompt appears, that a wrong passphrase
  surfaces "Phrase de passe incorrecte." inline without closing
  the editor, that the correct passphrase saves a cipher whose
  `keyFingerprint` is auto-filled with `SHA256:…` and whose
  `privateKey` is the cleartext PEM (no `ENCRYPTED` marker), and
  that an ECDSA paste fails fast in the main editor error line
  without ever rendering the passphrase prompt.

## [0.1.17] — 2026-04-25

### Fixed
- **No more global window scroll.** The default user-agent
  `<body>` margin (8 px top + 8 px bottom) was overflowing every
  `100vh` layout by exactly 16 px, producing a permanent vertical
  scrollbar regardless of window size or content. Reset
  `html`/`body` margins to 0, locked `body { overflow: hidden }`,
  and switched `.container.wide` from `100vh` to `100%`. Inner
  panes (folder tree, cipher list, detail panel, dialogs) keep
  their own `overflow: auto`, so long content still scrolls
  inside its panel — only the chrome can no longer scroll.

### Changed
- **Cleaner main view chrome.** Removed the redundant
  `<h1>{m.app_name()}</h1>` page title — the OS window chrome
  already shows the app name, and the duplicate was wasting
  vertical space on the 800×600 default window.
- **Tighter cipher detail values.** `.value` rows now use
  `flex: 0 1 auto` instead of `flex: 1 1 auto` so action buttons
  (copy / show / hide) sit snug against the value text instead
  of being pushed to the panel's right edge.

### Tests
- **TOTP 2FA spec stability.** `login-totp.spec` now waits one
  extra step before submitting the 2FA code, eliminating a race
  where the form was being submitted before the WebView had
  finished swapping to the 2FA prompt.
- **Smoke spec re-anchored to `main.container`.** Following the
  `<h1>` removal above, `tests/e2e/specs/smoke.spec.mjs` now
  asserts on the Svelte-injected `<main class="container">`
  element. Same anti-blank-window guarantee (the static
  `app.html` body is an empty wrapper, so this node only exists
  post-hydration), no app-code change needed.

### Tooling
- **Manual Linux dev-build workflow.**
  `.github/workflows/dev-build.yml`, triggered via
  `workflow_dispatch`, builds an `.AppImage` on a GitHub runner
  and uploads it as a 14-day artifact. Lets contributors test
  changes on a real Tauri build without running `tauri dev`
  locally — the parallel Rust + Vite + WebView pipeline is too
  heavy on lower-RAM machines.

## [0.1.16] — 2026-04-25

### Added
- **Project logo.** Replaces the Tauri default with a Clavix mark
  — a wide white "C" whose right-hand opening carries two short
  horizontal teeth (a key bow), painted on a Bitwarden-blue
  rounded square that matches the in-app accent. Source SVG
  lives at `assets/clavix-logo.svg`; `scripts/regen-icons.sh`
  rasters every PNG / ICO / ICNS Tauri ships with.
- **Inline SVG icons** across the toolbar, cipher list, sidebar
  and detail panel, replacing the previous emoji set. Lucide-
  style geometry, monochrome, inheriting `currentColor`. Fixes
  the rendering inconsistency between Linux GTK / macOS / Windows
  emoji stacks.
- **Restructured `CipherDetail` panel.** Fields are now grouped
  into typed sections (Identifiants / URLs / Sécurité / Carte
  bancaire / Identité / Clé SSH / Notes) with small uppercase
  headers and a consistent label-vs-value grid. Verbose
  Copier / Afficher / Masquer word buttons collapse into icon-
  only marks (copy / eye / eye-off) with title + aria-label, same
  hit area as the toolbar buttons.
- **Empty states** with a large icon, title, body and CTA, on the
  cipher list (no search match → "Effacer la recherche" button;
  empty folder → guidance to create or import).
- **Subtle motion**: 100 ms fade on cipher-row hover/selection
  (no more snap-flash) and 140 ms fade-up on the detail panel
  when it mounts.

### Security
- **In-flight 2FA login state is parked Rust-side.** New
  `PendingTwoFactor` slot in `AppState` carrying server_url,
  email, master_key, password_hash, prelogin and client. Derives
  `ZeroizeOnDrop`. `webauthn_sign_challenge` and
  `login_with_two_factor` now read from this slot rather than
  re-receiving the same values from the renderer between calls.
  A compromised JS layer can no longer swap the rpId anchor or
  the master key between `login()` and the second-factor IPC.
  5-minute TTL on the slot. Closes the gap noted in #21.

### Tests
- **TOTP 2FA E2E spec** (`login-totp.spec`) walks the full second-
  factor login against the seeded `e2e-2fa@clavix.test` account.
  Pure-Node RFC 6238 helper (~25 lines, no `otplib` dep).
- **Rust integration tests** for the session-lifecycle pieces
  that don't fit a WDIO spec: `refresh_token_endpoint.rs` mocks
  `/identity/connect/token` and asserts the form payload + the
  400 → AuthFailed mapping; `persisted_session_disk.rs` covers
  the save / load / clear round-trip and the legacy-plaintext
  refresh-token recovery in an XDG_DATA_HOME tempdir.
- Six new E2E specs are now actively running again after #25
  landed: cipher-types, delete-restore, edit-cipher, folder-
  cascade, logout, permanent-delete. The suite stands at 13
  specs.

### Changed
- **Per-spec Vaultwarden reset** in `wdio.conf.mjs` (gated
  behind `E2E_PER_SPEC_RESET=1`, set in CI). docker-compose-down
  + up + reseed before each spec so cumulative state can't make
  late-position specs hang in `socket hang up`. Adds ~3 minutes
  to the suite, removes the position-dependent flake entirely.
- **Strict-exact-match WebAuthn rpId** (continued from 0.1.12 —
  the 0.1.11 implementation accepted any DNS suffix).
- `delete_folder` was added to `VaultwardenClient` for future
  per-account teardown helpers.

### Tooling
- `mockito`, `tempfile`, `tokio` (test feature) added as Rust
  dev-dependencies for the new integration suite.

## [0.1.15] — 2026-04-25

### Added
- **Trash bucket workflow.** `soft_delete_cipher` (PUT
  `/api/ciphers/{id}/delete`) sends a cipher to the server's trash
  with `deletedDate` stamped; `restore_cipher` clears it again. The
  cipher detail panel now shows a "Supprimer" button on a normal
  item (alongside "Éditer"); a trashed item still gets the existing
  "Restaurer" / "Supprimer définitivement" pair. Before this
  release Clavix could only hard-delete (DELETE) — items only ever
  reached the trash if a different client put them there.
- **User-pickable visible columns on the cipher list.** The
  Identifiant and URL columns are now hideable per user preference
  (Type icon and Name stay always-on). Choice is persisted in
  `localStorage` under `clavix.visibleColumns`. Native
  `<details>/<summary>` popover anchored to the leftmost header
  cell — click-outside-to-close, ESC-to-close and tab-trapping
  come for free without a popover library.

### Changed
- **Cipher list polish**:
  - Searching no longer leaves a tall blank band at the top of the
    virtualised list. Filter shrinks `items.length`, scrollTop is
    clamped to the new content range so the rendered slice stays
    within the viewport.
  - Rows paint flush edge-to-edge: the `<li>` is `align-items:
    stretch`, the `<button>` is `height: 100%`, no more thin white
    sliver above and below each row.
  - Hover and selected states pulled up two notches in saturation
    so they're clearly distinct from the zebra background. Same
    treatment in dark mode and on the tree view.
  - Identifiant and URL columns rendered at `0.82em`, smaller than
    the name column. Bump them (and the name) so all three text
    columns read at roughly the same size.

### Tests
- Three new E2E specs: `logout.spec` (asserts session.json
  cleared, AuthGate re-renders the login form not the unlock
  form), `edit-cipher.spec` (UI-driven rename round-trip), and
  `delete-restore.spec` (soft delete → trash → restore). Brings
  the E2E suite from 6 specs to 9.

### Internal
- The previous CI run shipped a self-inflicted regression where
  `delete-restore.spec` called `delete_cipher` (hard delete)
  thinking it was soft, wiping the seed for every spec that ran
  after it (six in a row failed). The new soft-delete plumbing
  fixes the root cause; the spec now uses `soft_delete_cipher`
  with a comment that calls out the trap explicitly.

## [0.1.14] — 2026-04-25

### Fixed
- **Blank window on Linux desktops where the running user is not in
  the `render` group.** Ubuntu 24.04 ships WebKit2GTK 4.1 with the
  DMABUF renderer enabled by default; that renderer needs to allocate
  GBM buffers through `/dev/dri/*`, which fresh installs gate behind
  the `render` (or sometimes `video`) group. Users who weren't added
  to that group saw exactly one symptom: a blank window. The
  underlying message
  `KMS: DRM_IOCTL_MODE_CREATE_DUMB failed: Permission denied` only
  showed up when launching from a terminal — invisible to anyone
  starting Clavix from the desktop launcher.

  This was the actual cause behind the 0.1.11/0.1.12/0.1.13 "blank
  window" reports. The CSP fixes in 0.1.12/0.1.13 were correct and
  necessary on their own merits but they were chasing the wrong
  bug — the .deb didn't paint anything regardless of the policy.

  Set `WEBKIT_DISABLE_DMABUF_RENDERER=1` from `main.rs` before
  starting the Tauri runtime so WebKit falls back to the non-DMABUF
  compositor. The fallback's perf cost is negligible for a CSS-only
  UI like Clavix's (no canvas, no animation). Power users with a
  working DMABUF stack can opt back in by exporting
  `WEBKIT_DISABLE_DMABUF_RENDERER=0` before launching.

## [0.1.13] — 2026-04-25

### Fixed
- **Blank window in `0.1.12.deb` (and 0.1.11.deb).** The
  `'unsafe-inline'` mitigation in 0.1.12 was a non-fix: Tauri 2
  injects its own nonce into `script-src` at runtime (the
  `__TAURI_SCRIPT_NONCE__` placeholder is visible in the binary
  strings), and CSP3 says the presence of a nonce in a directive
  causes `'unsafe-inline'` to be ignored. So the SvelteKit
  bootstrap (which has neither nonce nor hash) was still blocked.
  Cause was identified by inspecting the actual `.deb` and the
  CSP3 spec — there was nothing wrong with the build.

  The real fix is hash-based: `svelte.config.js` now uses
  `kit.csp.mode = "hash"`, which makes SvelteKit emit a
  `<meta http-equiv="content-security-policy">` listing the
  exact SHA-256 of every inline script it generated. The CSP
  permits exactly that script and nothing else inline. Hashes
  are recomputed on every build so chunk-name churn is
  invisible. `tauri.conf.json` sets `"csp": null` so Tauri does
  not re-inject its own conflicting policy.

### CI
- **`smoke-release` job** rebuilds in release and runs only
  `smoke.spec` against the production binary. v0.1.11/0.1.12
  shipped blank-window `.deb`s because the existing E2E job runs
  `pnpm tauri build --debug`, where the release CSP isn't
  enforced. The new job (cached separately, `key: release`) is
  the floor: any future CSP / hydration regression that would
  ship a blank `.deb` now turns CI red on the PR.
- **`smoke.spec`** no longer asserts on "body has any text" — that
  was a false positive on the 0.1.11/0.1.12 case because the
  inline `<script>` and `<link rel=modulepreload>` tags can
  register as text under some WebDriver implementations even when
  the JS never runs. It now checks the post-hydration
  `<h1>Clavix</h1>`, which only exists if Svelte actually
  rendered.
- **`wdio.conf.mjs`** is now parametric: `E2E_BUILD_PROFILE`
  picks `target/debug` vs `target/release`, `E2E_SKIP_SEED=1`
  skips Vaultwarden Docker + the Rust seed for jobs that don't
  need them. Default behaviour unchanged.

### Documentation
- The `MANUAL_VALIDATION.md` rpId-mismatch step quotes the new
  strict-match error message text.

## [0.1.12] — 2026-04-25

### Fixed
- **Blank window in the `0.1.11.deb` (and earlier release builds).**
  `index.html` produced by `adapter-static` boots the app via an
  inline `<script>` that imports the SvelteKit entry chunks; the
  previous CSP `script-src 'self'` blocked it silently in release
  builds, leaving an empty body. The CI E2E suite never noticed
  because it runs `pnpm tauri build --debug` (Tauri does not
  enforce the same CSP in debug). Loosen `script-src` to
  `'self' 'unsafe-inline'`. The downgrade is bounded in this
  codebase: bundled HTML, no `{@html}` anywhere in `src/`, Svelte 5
  always escapes interpolations. Tighter hash/nonce-based CSP
  tracked separately as a follow-up.

### Security
- **Strict-exact-match WebAuthn rpId.** `0.1.11` accepted both
  `host == rp_id` and `host.ends_with(".{rp_id}")`. The second
  branch was a textual DNS suffix, which is too loose: `rpId="com"`
  matched any `*.com` host. A hostile or MITM'd Vaultwarden could
  exploit that. Drop the suffix branch entirely; only exact host
  match passes. The rare apex-with-subdomain case is now rejected
  and should come back, if at all, behind an explicit per-account
  opt-in.
- **HTTPS required for the Vaultwarden URL** (with an allow-list
  of `localhost` / `127.0.0.1` / `::1` for local dev with Docker
  Vaultwarden over plain HTTP). `normalize_base_url` used to swallow
  any scheme `Url::parse` could parse — `http://`, `file://`,
  `javascript:`, `ftp://`, … — and just appended a trailing slash.
  Posting a master-password hash over plaintext on a hostile WiFi
  was one config-import or copy-paste away.

### Documentation
- **Three corrections in `MANUAL_VALIDATION.md`** flagged by external
  review:
  - The rpId-mismatch failure path now quotes the new strict-match
    error message.
  - The SSH-agent "expected" line no longer claims keys are wiped
    "immediately after" each signature — the lifecycle is the
    agent's, not the individual sign call's. Keys are never on
    disk and disappear on stop / lock / logout / quit.
  - The socket-permissions check now expects `srw-------` (0600)
    to match what `ssh_agent.rs` actually sets.

### CI
- **Discord webhook** posts a release notification once all three
  platform builds succeed (silently no-ops without
  `DISCORD_RELEASE_WEBHOOK_URL`). Pulls highlights for the freshly-
  tagged version out of `CHANGELOG.md`, capped at 80 lines so we
  stay under Discord's 4096-char description limit. Embed colour is
  the Bitwarden brand blue (`0x175DDC`). `allowed_mentions:
  { parse: [] }` is set on the payload so a stray `@everyone` in a
  future CHANGELOG entry can't ping the entire Discord server.

## [0.1.11] — 2026-04-25

### Security
- **WebAuthn rpId validation.** The 2FA WebAuthn path used to trust
  whatever `rpId` Vaultwarden sent in the challenge and feed it into
  the `clientDataJSON` we hand to the FIDO2 token. A hostile or
  MITM'd server could pick `rpId="other-service.com"` and walk away
  with a valid assertion for that origin. We now reject any rpId that
  is not the configured `server_url`'s host or a registrable suffix
  of it (with a strict dot-boundary check so `example.com.attacker.com`
  is rejected). The `server_url` is plumbed from the user's typed
  login form value through the Tauri command, so the comparison is
  anchored on user input rather than anything the server controls.
- **Tokens no longer cross the IPC boundary.** `login`,
  `login_with_two_factor` and `unlock` used to return the full
  `TokenSet` (access + refresh tokens, encrypted user key, encrypted
  private key) to the WebView — useful as a "yes we got something"
  signal during early bring-up, irrelevant now. They now return
  `LoginOk { email }` (or a similar `LoginOutcome` for the 2FA branch)
  and the Rust `AppState` is the single owner of every session secret.
  The frontend cannot accidentally log, persist, or post a token it
  doesn't have.
- **9 Dependabot alerts cleared** in 0.1.10's tail (`rustls-webpki`
  CVE on the Rust side, plus `tar-fs`, `ws`, `serialize-javascript`,
  `minimatch`, `tmp`, … pulled transitively by `@wdio/*` v7 — fixed
  via `pnpm.overrides` rather than a wdio major bump). One additional
  `uuid < 14.0.0` advisory closed shortly after.

### Added
- **KeePassXC-style top toolbar.** Action buttons used to live in two
  places: the SessionBar under the title (Sync / Lock / Logout) and
  the bottom of the VaultSidebar (Add / Import / Generator / Audit /
  Stats). They are now grouped into a single horizontal toolbar with
  three vertical-divider-separated sections. Buttons are icon-only
  with `title` + `aria-label` for tooltip / a11y; the live session-
  freshness dot and "il y a N min" label are tucked to the right
  edge of the bar.
- **Zebra-striped cipher list** with the Bitwarden / Vaultwarden blue
  palette (`#eaf2fc` / `#cfe0f5` / `#a8c8f0` in light mode, navy
  equivalents in dark). Stripes are driven by absolute row index
  rather than `:nth-child(even)` so they stay stable as the user
  scrolls the virtualised list.
- **Property-based tests on `EncString` parsing** (proptest, 64
  cases per property): the parser must never panic on arbitrary
  input, encrypt/parse/decrypt is the identity for any 0..512 byte
  payload, and any single-bit flip in IV / ciphertext / MAC must be
  caught by the HMAC. `proptest` is dev-only; release artefacts are
  unchanged.
- **E2E fixture matrix.** The seed binary now covers the canonical
  test matrix (more cipher types, folders, organisations) and
  provisions a secondary 2FA-enabled account so future 2FA-aware
  specs have something to log into.

### Changed
- **Recovery snapshots / op-log honesty.** `CRYPTO.md`,
  `THREAT_MODEL.md` and `AUDIT_SCOPE.md` used to describe the
  per-cipher pre-modification snapshots and folder-rename op-log
  written around destructive flows as a "crash recovery" mechanism,
  but nothing in the running app actually replays them: they are
  inserted, marked completed, and dropped on logout. The four
  mentions are now reworded as a write-only forensic trail useful
  for post-mortem analysis, with the gap called out explicitly so
  reviewers don't treat it as a mitigation.

### Internal
- E2E `lock-unlock` spec switched its lock-button selector from
  text-content match (`button=Verrouiller`) to `button[aria-label=
  'Verrouiller']`, since the toolbar button is now icon-only. More
  robust against future label changes too.
- Removed `truncate` and `formatExpiry` helpers (and their tests):
  they only existed to format the pre-alpha access-token / expiry
  debug strip in the SessionBar, which is gone.

## [0.1.10] — 2026-04-21

### Added
- **End-to-end test suite** driving the real Tauri binary via
  `tauri-driver` + WebdriverIO against a disposable Vaultwarden
  (Docker). Six specs cover the smoke pipeline, login with auto-sync,
  cipher creation, share-to-organization, lock/unlock round-trip, and
  idle auto-lock. Seed is a standalone Rust binary
  (`src-tauri/examples/e2e_seed.rs`) that reuses the production crypto
  (RSA-2048 keypair, AES-CBC+HMAC, HKDF) so any regression surfaces in
  the seed before hitting the UI tests. Wired into CI as a blocking
  check.
- **Post-login auto-sync** (Bitwarden-style): `loadCached()` paints
  the UI instantly from the encrypted local cache, then a background
  `sync()` reconciles against the server. A fresh profile used to land
  on an empty vault until the user hit *Sync* manually — now the
  ciphers appear on their own.
- **Session freshness indicator** in the session bar. Five states
  (`fresh`, `stale`, `syncing`, `offline`, `unknown`) with a live
  relative-time label that refreshes itself every minute. Logic
  extracted as a pure `computeSessionStatus` helper and covered by
  vitest.
- Root **`Makefile`** wrapping the CI checks so a single
  `make check-full` reproduces fmt + clippy + cargo test +
  svelte-check + vitest + the full E2E suite locally.
- **Security documentation** stack: `SECURITY.md`, `THREAT_MODEL.md`,
  `CRYPTO.md`, `AUDIT_SCOPE.md`. Report channels, disclosure
  expectations, assets and attacker model, crypto primitives and
  review checklist, prioritised scope for a future external audit.

### Changed
- The session lock primitives moved from `std::sync::Mutex` to
  `parking_lot::Mutex`. A panic inside one command handler used to
  poison the session mutex and make every subsequent command panic
  too, effectively locking the app until relaunch — the new primitive
  has no poisoning, so isolated failures stay isolated.
- The vault sidebar toolbar (`＋`, import, password generator, audit,
  stats) is now always visible. Previously it was gated behind "user
  has at least one folder or organization", which made it impossible
  to create a new item on a brand-new vault with only personal
  ciphers.
- `set_auto_lock_minutes` now accepts `f64` instead of `u32`, keeping
  the backend watchdog and the front-end `parseFloat`ed pref in sync
  for sub-minute values. Filtering uses `is_finite() && > 0` so NaN
  and infinities map to "disabled".
- HTML window title changed from the default SvelteKit template to
  *Clavix* — visible in the OS window chrome and task bar.

### Internal
- `build_share_cipher_body`, `validate_move_to_collection`, and
  `plan_folder_renames` extracted out of `commands/move_share.rs`
  orchestration and unit-tested. Rust test count rose from 71 to 101.
- `recover_refresh_token`, `compute_expires_at`, and
  `build_sync_summary` gained explicit coverage against their key
  selection and fallback rules.
- `setupAutoLock` extracted as a reusable Svelte 5 helper so the JS
  timer and the backend mirror no longer live inline in
  `+page.svelte` (332 → 303 lines).
- Vitest bumped 2.1.9 → 4.1.4, `@sveltejs/vite-plugin-svelte`
  5.1.1 → 7.0.0 (had to go together — vitest 2 could not consume
  plugin-svelte 7), `actions/upload-artifact` 4 → 7.

## [0.1.9] — 2026-04-19

### Added
- **WebAuthn / FIDO2 in 2FA** (provider 7). Clavix now drives a
  hardware security key directly over CTAP2/HID (YubiKey, SoloKey,
  …) — no browser involved. The `clientDataJSON` is built in Rust
  with `origin = https://{rpId}` so the authenticator's signature
  is accepted by Vaultwarden even though the app itself doesn't run
  under the vault's domain. Activates automatically when the server
  offers WebAuthn as a 2FA method. Closes the SSH-agent companion
  of issue #1.
- **Create and edit in an organization / collection**. The cipher
  editor gained an *Owner* selector (Personal / any org you belong
  to) and, for org items, a *Collection* picker. Backend splits
  into `POST /ciphers/create` (with org key and `collectionIds`)
  vs the existing `POST /ciphers` for personal items. Edits pick
  the right key from the item's current owner — changing owner in
  the editor is blocked, the share command handles that.
- **Import from KeePassXC** (CSV export). `📥` button in the tree
  toolbar opens a modal that parses the standard KeePassXC CSV
  columns (Title / Username / Password / URL / Notes / TOTP /
  Group), previews the first 15 rows, and imports the lot with an
  option to auto-create a folder per *Group* value.

### Security / CI
- `libudev-dev` added to the Ubuntu CI and release pipelines
  (needed by `hidapi` → `ctap-hid-fido2` on Linux). Previous
  `cargo clippy` failures were caused by this missing dep.
- Bumped `github/codeql-action` from v3 to v4: clears the
  deprecation warning for Node.js 20 and gets ahead of the CodeQL
  Action v3 deprecation scheduled for December 2026.

## [0.1.8] — 2026-04-19

### Added
- **SSH agent now signs RSA keys** (SHA-256 and SHA-512) on top of
  Ed25519. Vault-stored RSA private keys are parsed via `ssh-key` and
  signatures are produced with `rsa::pkcs1v15` under the right hash
  depending on the SSH agent `flags` field. ECDSA and DSA remain
  skipped for now.
- **Create and edit every cipher type** (Login, Secure Note, Card,
  Identity, SSH Key) from a single `CipherEditor` modal, with a
  cipher-type selector in create mode. Backend dispatches on
  `cipherType` via a unified `create_cipher` / `update_cipher` pair.
- **TOTP QR scanner** inside `CipherEditor`: a 📷 button opens the
  camera via `navigator.mediaDevices.getUserMedia` and fills in the
  TOTP field as soon as jsQR detects an `otpauth://` URI.
- **UI density pass**: bumped base font size back up, stopped
  truncating cipher list cells, and the detail panel is now
  resizable against the list via a vertical splitter (position
  persisted in `localStorage`).

### Security
- **Refresh token is encrypted at rest** under `user_key` (AES-CBC +
  HMAC-SHA256). A stolen `session.json` no longer hands an attacker a
  reusable OAuth2 credential without the master password. The legacy
  plaintext field is still read on unlock for a silent migration,
  then purged on the next save.
- **Backend auto-lock watchdog**: a tokio task polls every 30 s and
  drops the session + SSH agent once inactivity exceeds
  `auto_lock_minutes`. Safety net for when the JS timer is disabled
  or the WebView is frozen.
- **Share / folder-rename operation log** (`cipher_snapshots` +
  `folder_op_log` tables in the SQLite cache). A cipher is
  snapshotted before a cross-org share and marked completed on
  success; folder-rename batches log each row. Groundwork for a
  future replay / recovery flow.

### CI
- Rust fmt / clippy / audit re-enforced after the big refactor —
  caught formatting drift in `commands/cipher.rs` and `crypto.rs`.

## [0.1.7] — 2026-04-19

### Changed
- **Compact visual redesign**: reduced base font size (13.5 px),
  tighter paddings, flatter vault cards (hairline borders instead
  of box-shadow), alternating row stripes in the cipher list,
  inline single-line SessionBar. Inter for UI text; Atkinson
  Hyperlegible for data fields (inputs, passwords, URIs) so
  `0/O` and `l/1/I` are unambiguous.
- **Large refactor**: `+page.svelte` dropped from 3631 → 262 lines
  and `lib.rs` from 1310 → 47 lines. Domain code is now split into
  Svelte components (AuthLoginForm, UnlockForm, TwoFactorForm,
  SessionBar, VaultSidebar, CipherList, CipherDetail, *Dialog,
  ClipboardToast), `auth/vault/prefs` controllers in
  `.svelte.ts` files, and Rust modules under
  `src-tauri/src/{commands,services}/`.
- Styles moved to `src/styles/*.css`, imported from `+layout.svelte`.
- Vitest tests added for the pure TS helpers, plus Rust tests for
  folder-tree logic, both wired into CI.

### Performance
- Smoother folder-tree hover: `contain: content` on `.tree-pane`
  isolates repaints; removed an inherited global `filter:
  brightness` that was triggering tree-wide paints on hover.

### Security
- `esbuild` transitive dep pinned to `>= 0.25.0` via pnpm override,
  which clears GHSA-67mh-4wv8-2f99 (esbuild dev-server CORS). Only
  affects local `pnpm tauri dev`, never the shipped binary.

### CI
- Bumped `actions/checkout`, `actions/setup-node` and
  `pnpm/action-setup` to v6 (via Dependabot PRs).

## [0.1.6] — 2026-04-19

### Added
- **Access-token auto-refresh**: every API-hitting command now
  refreshes the OAuth2 access token 60 s before its expiry, so
  long-running sessions no longer silently 401.
- **Forced dark mode** in Preferences (Auto / Sombre). The toggle
  lives next to the language selector and is persisted to
  `localStorage`.
- **Security audit extended**: the 🛡 modal now also surfaces
  reused passwords (grouped by the ciphers sharing them) and weak
  passwords (zxcvbn score ≤ 2), in addition to HIBP breach hits.
  Detection happens fully locally; no additional data leaves the
  machine.

## [0.1.5] — 2026-04-19

### Added
- **SSH agent** (Linux / macOS) that exposes the Ed25519 SSH keys
  stored in your vault over a Unix socket at
  `$XDG_RUNTIME_DIR/clavix/agent.sock` (or the user cache dir as a
  fallback), with file mode `0600`. Toggle from the Preferences
  section of the Infos modal, then `export SSH_AUTH_SOCK=...` in
  your shell. Supports `SSH_AGENTC_REQUEST_IDENTITIES` and
  `SSH_AGENTC_SIGN_REQUEST`. The agent is automatically stopped on
  lock / logout. RSA and ECDSA keys are detected but skipped for
  now. Windows ships a stub that returns a "not supported yet"
  error (named pipes / Pageant in a future release).

## [0.1.4] — 2026-04-19

### Added
- **Live TOTP generation** in the detail panel: the stored secret is
  parsed (plain Base32 or `otpauth://` URI with custom period / digits /
  algorithm), and the 6-digit code is generated in the browser via Web
  Crypto, refreshed every second, with a countdown and a Copy button.
  Algorithm validated against the RFC 6238 test vectors.
- **Create and edit Login items**: new `＋` button in the tree toolbar
  opens a modal (`LoginEditor.svelte`) with fields for name, folder,
  username, password, URLs (one per line), TOTP secret, notes and the
  favorite flag, plus an inline password generator. The detail panel
  gets an "Edit" button on non-deleted Login items. Field encryption
  is performed client-side with the user key before the
  `POST /ciphers` or `PUT /ciphers/{id}` call.

### Security
- `.claude/` directory now in `.gitignore` (internal Claude Code files
  should never be versioned).

## [0.1.3] — 2026-04-19

### Added
- **Onboarding screen** on first launch, explaining what Clavix does and
  pointing to the alpha-stage disclaimer. Dismissed permanently once
  acknowledged (stored in `localStorage`).
- **Password security audit** via the Have I Been Pwned range API,
  using k-anonymity: only the first 5 hex characters of the SHA-1 hash
  ever leave your machine. Results listed per compromised item with a
  jump-to-item shortcut. Accessible from the shield button (🛡) in the
  tree toolbar.
- **Password generator** with configurable length, character classes
  and ambiguous-character filter (🎲 button in the tree toolbar).
- **Quick filter by cipher type** (Login / Note / Card / Identity /
  SSH) in the sidebar, with per-type counts.
- **Trash actions**: restore a deleted item or permanently delete it
  from the detail panel.
- **YubiKey OTP support** as a 2FA provider (provider 3): a dedicated
  input captures the 44-character Modhex code and auto-submits once
  the YubiKey has finished typing it. If the server offers both TOTP
  and YubiKey, a method picker is shown.

### Security
- Activated Dependabot alerts, Dependabot security updates, secret
  scanning and push protection on the public repository.
- Added a CodeQL workflow running on every push, PR and weekly schedule
  for JavaScript/TypeScript analysis.
- `cookie` transitive dep pinned to `>= 0.7.0` via a pnpm override
  (fixes GHSA-pxg6-pf52-xh8x).

### Changed
- The onboarding screen lives in its own component
  (`src/lib/Onboarding.svelte`), a first step towards splitting the
  large `+page.svelte` into smaller units.
- Added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub issue and pull
  request templates, and a Dependabot config for routine dependency
  updates.

## [0.1.2] — 2026-04-19

### Added
- **Multilingual UI** (Français + English) via `paraglide-js`. Language
  is detected from the browser at first launch, persisted in
  localStorage, and switchable from the vault Infos modal.
- **Translated error messages**: every backend error code
  (`invalid_url`, `auth_failed`, `network_error`, etc.) is rendered
  through the i18n table instead of the raw English fallback.
- **Favorites** and **Trash** quick filters in the sidebar, with
  counts. Deleted items (soft-delete via `deleted_date`) are now
  visible in the Trash view and hidden from all other views.
- **Sortable columns**: click Name / Username / URL headers to sort
  ascending or descending, with a visual indicator.
- **Username and URL columns** in the cipher list, with responsive
  breakpoints.
- Search now matches across name, username and URL (not just name).

### Changed
- `svelte-check` in CI now compiles Paraglide first (messages JSON →
  `src/lib/paraglide/`).
- CI release matrix targets Ubuntu, macOS and Windows. `v0.1.1` only
  shipped Linux; `v0.1.2` ships all three.

## [0.1.1] — 2026-04-19

### Added
- **Detail panel for all cipher types**: cards, identities and SSH keys now
  show decrypted fields with masking on sensitive ones (card number, CVV,
  SSN, SSH private key) and one-click copy to clipboard.
- **KeePassXC-style keyboard shortcuts**: `Ctrl+C` / `Ctrl+B` / `Ctrl+U` for
  copying password / username / opening the URL of the focused item,
  `Ctrl+L` to lock, `Ctrl+F` or `/` to focus the search, `Escape` to close
  the detail panel.
- **Auto-lock on inactivity**, configurable from the vault Infos modal
  (Never / 1 / 5 / 10 / 15 / 30 min / 1 h). Setting persisted to
  localStorage. Default: 10 minutes.
- **List columns**: username and URL are now visible next to each cipher
  name, with responsive breakpoints that hide columns on narrow windows.
- macOS and Windows added to the release matrix (will take effect from
  the next tag; `v0.1.1` is still Linux-only).

### Changed
- **Virtualised cipher list**: only the items currently visible are rendered
  in the DOM, saving memory and making scroll fluid on large vaults.
- **Debounced search** (150 ms) to avoid re-filtering on every keystroke.
- **Parallelised vault decryption** in the Rust backend via `rayon`: sync
  and cache load are now noticeably faster on multi-core machines.
- **Tree counts** are computed in O(1) per node from a pre-built
  HashMap index, instead of re-scanning all ciphers per node.

### Fixed
- `folderId` was not being cleared when sharing a personal item to an
  organization, leaving a stale folder path visible on the official iOS
  client. It is now forcefully `null`-ed during a share.

## [0.1.0] — 2026-04-19 (initial release)

### Added
- Login against a self-hosted Vaultwarden instance (custom URL).
- Master password unlock with both PBKDF2 and Argon2id KDFs.
- TOTP 2FA challenge handling.
- Full vault sync: items, folders, collections, organizations.
- Client-side decryption: AES-256-CBC + HMAC-SHA256 for the personal vault,
  RSA-OAEP-SHA1 for organisation keys.
- Encrypted local SQLite cache for instant offline reads after unlock.
- Hierarchical tree view built from the Bitwarden `/` naming convention
  (personal folders + organisation collections), with a resizable
  splitter.
- Item detail for logins (username, hidden password with show/copy,
  URLs, TOTP secret, notes), clipboard auto-clear after 30 s.
- Item favicons fetched via the Vaultwarden icon service, with an emoji
  fallback per type (🔐 / 📝 / 💳 / 🪪 / 🔑).
- Drag and drop:
  - item onto a folder;
  - item onto an organisation collection (same organisation: move;
    personal → organisation or cross-org: re-encrypted share);
  - folder onto another folder, with cascade rename of sub-folders on
    the server.
- Persisted session on disk at `~/.local/share/clavix/`, with an Unlock
  screen that skips the 2FA and refreshes the OAuth token.
- GitHub Actions CI (`fmt`, `clippy`, `cargo audit`, `svelte-check`) and
  release workflow that bundles `.AppImage`, `.deb` and `.rpm`.

[0.1.9]: https://github.com/Upellift99/clavix/releases/tag/v0.1.9
[0.1.8]: https://github.com/Upellift99/clavix/releases/tag/v0.1.8
[0.1.7]: https://github.com/Upellift99/clavix/releases/tag/v0.1.7
[0.1.6]: https://github.com/Upellift99/clavix/releases/tag/v0.1.6
[0.1.5]: https://github.com/Upellift99/clavix/releases/tag/v0.1.5
[0.1.4]: https://github.com/Upellift99/clavix/releases/tag/v0.1.4
[0.1.3]: https://github.com/Upellift99/clavix/releases/tag/v0.1.3
[0.1.2]: https://github.com/Upellift99/clavix/releases/tag/v0.1.2
[0.1.1]: https://github.com/Upellift99/clavix/releases/tag/v0.1.1
[0.1.0]: https://github.com/Upellift99/clavix/releases/tag/v0.1.0
