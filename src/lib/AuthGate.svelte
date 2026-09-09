<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";
  import AuthLoginForm from "./AuthLoginForm.svelte";
  import Onboarding from "./Onboarding.svelte";
  import TwoFactorForm from "./TwoFactorForm.svelte";
  import UnlockForm from "./UnlockForm.svelte";
  import StandaloneOpenForm from "./StandaloneOpenForm.svelte";
  import type { AuthController } from "./auth.svelte";
  import type { Locale } from "./types";

  type Props = {
    auth: AuthController;
    onOnboardingComplete: () => void;
    currentLocale: Locale;
    onApplyLocale: (loc: Locale) => void;
  };

  let { auth, onOnboardingComplete, currentLocale, onApplyLocale }: Props = $props();

  // Endonym ("self-named") language labels so the control reads the same
  // in every locale — no message keys required. Order mirrors the
  // preferences dialog (base locale first).
  const LANGUAGES: { code: Locale; label: string }[] = [
    { code: "fr", label: "Français" },
    { code: "en", label: "English" },
  ];

  // Build version for the startup footer. Offline, straight from Rust.
  // A failure just leaves the version off — the link still works.
  let version = $state("");
  $effect(() => {
    api
      .appVersion()
      .then((v) => (version = v))
      .catch(() => (version = ""));
  });

  async function openWebsite() {
    await openUrl("https://clavix.org");
  }
</script>

{#if auth.phase === "init"}
  <p class="subtitle">{m.loading()}</p>
{/if}

{#if auth.phase === "onboarding"}
  <Onboarding onComplete={onOnboardingComplete} />
{/if}

{#if auth.phase === "idle" || (auth.phase === "authenticating" && !auth.storedAccount) || auth.phase === "error"}
  <AuthLoginForm
    bind:serverUrl={auth.serverUrl}
    bind:email={auth.email}
    bind:password={auth.password}
    disabled={auth.phase === "authenticating"}
    onSubmit={(e) => auth.submitLogin(e)}
  />
{/if}

{#if auth.phase === "unlock" || (auth.phase === "authenticating" && auth.storedAccount)}
  <UnlockForm
    account={auth.storedAccount}
    bind:password={auth.password}
    disabled={auth.phase === "authenticating"}
    yubikeyAvailable={auth.yubikeyAvailable}
    yubikeyBusy={auth.yubikeyBusy}
    bind:yubikeyPin={auth.yubikeyPin}
    requiresPin={auth.yubikeyRequiresPin}
    onSubmit={(e) => auth.submitUnlock(e)}
    onYubikey={() => auth.submitYubikey()}
    onSwitchAccount={() => auth.switchAccount()}
  />
{/if}

<!-- The emergency door, offered on both entry screens: "my server is
     gone" and "this machine has no account yet" are the same problem
     from two directions. Not shown mid-login. -->
{#if auth.phase === "unlock" || auth.phase === "idle"}
  <StandaloneOpenForm onOpen={(bytes, password) => auth.openExportFile(bytes, password)} />
{/if}

{#if auth.phase === "twoFactor"}
  <TwoFactorForm
    providers={auth.pendingProviders}
    bind:selectedProvider={auth.selectedProvider}
    bind:totpCode={auth.totpCode}
    bind:yubikeyOtp={auth.yubikeyOtp}
    webauthnBusy={auth.webauthnBusy}
    hasWebauthnChallenge={auth.webauthnChallenge !== null}
    onSubmit={(e) => auth.submitTwoFactor(e)}
    onWebauthn={() => auth.submitWebauthn()}
    onCancel={() => auth.cancelTwoFactor()}
  />
{/if}

{#if auth.phase !== "loggedIn" && auth.phase !== "init"}
  <footer class="auth-footer">
    {#if version}
      <span class="auth-footer-version">Clavix · {m.about_version({ version })}</span>
      <span class="auth-footer-sep" aria-hidden="true">—</span>
    {/if}
    <button type="button" class="auth-footer-link" onclick={openWebsite} title={m.about_website()}>
      clavix.org
    </button>
    <!-- Language switch: the vault preference lives behind the lock, so
         the pre-login screens carry their own. -->
    <span class="auth-footer-sep" aria-hidden="true">·</span>
    <span class="auth-footer-langs" role="group" aria-label={m.settings_language()}>
      {#each LANGUAGES as lang (lang.code)}
        <button
          type="button"
          class="auth-lang"
          class:active={lang.code === currentLocale}
          aria-pressed={lang.code === currentLocale}
          onclick={() => onApplyLocale(lang.code)}
        >
          {lang.label}
        </button>
      {/each}
    </span>
  </footer>
{/if}

<style>
  .auth-footer {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.4rem;
    margin-top: 1.25rem;
    font-size: 0.8rem;
    color: #777;
  }

  .auth-footer-sep {
    opacity: 0.6;
  }

  .auth-footer-link {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    color: #2563eb;
    text-decoration: underline;
    cursor: pointer;
  }

  .auth-footer-link:hover {
    color: #1d4ed8;
  }

  .auth-footer-langs {
    display: inline-flex;
    gap: 0.35rem;
  }

  /* Ghost buttons: quiet by default, link-coloured on hover, and the
     active language reads as solid text so the two never compete with
     the clavix.org link for "clickable" affordance. */
  .auth-lang {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    color: inherit;
    cursor: pointer;
  }

  .auth-lang:hover:not(.active) {
    color: #2563eb;
    text-decoration: underline;
  }

  .auth-lang.active {
    color: #333;
    font-weight: 600;
    cursor: default;
  }

  @media (prefers-color-scheme: dark) {
    .auth-footer {
      color: #999;
    }
    .auth-footer-link {
      color: #60a5fa;
    }
    .auth-footer-link:hover {
      color: #93c5fd;
    }
    .auth-lang:hover:not(.active) {
      color: #60a5fa;
    }
    .auth-lang.active {
      color: #e6e6e6;
    }
  }

  :global(:root.force-dark) .auth-footer {
    color: #999;
  }
  :global(:root.force-dark) .auth-footer-link {
    color: #60a5fa;
  }
  :global(:root.force-dark) .auth-footer-link:hover {
    color: #93c5fd;
  }
  :global(:root.force-dark) .auth-lang:hover:not(.active) {
    color: #60a5fa;
  }
  :global(:root.force-dark) .auth-lang.active {
    color: #e6e6e6;
  }
</style>
