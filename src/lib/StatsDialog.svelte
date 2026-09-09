<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";
  import { formatError } from "./format";
  import PasswordInput from "./PasswordInput.svelte";
  import type { SshAgentConfirm, ToolbarAlign } from "./prefs.svelte";
  import type {
    AutoLockTrigger,
    Locale,
    SshAgentStatus,
    SyncSummary,
    ThemePref,
  } from "./types";

  type Props = {
    summary: SyncSummary;
    currentLocale: Locale;
    themePref: ThemePref;
    autoLockMinutes: number;
    autoLockTrigger: AutoLockTrigger;
    closeToTray: boolean;
    minimizeToTray: boolean;
    hideDockOnTray: boolean;
    requireNarrowing: boolean;
    toolbarAlign: ToolbarAlign;
    autoSyncMinutes: number;
    sshAgentConfirm: SshAgentConfirm;
    sshAgentAutoStart: boolean;
    onApplyLocale: (loc: Locale) => void;
    onApplyTheme: (pref: ThemePref) => void;
    onApplyAutoLock: (trigger: AutoLockTrigger, minutes: number) => void;
    onApplyCloseToTray: (value: boolean) => void;
    onApplyMinimizeToTray: (value: boolean) => void;
    onApplyHideDockOnTray: (value: boolean) => void;
    onApplyRequireNarrowing: (value: boolean) => void;
    onApplyToolbarAlign: (value: ToolbarAlign) => void;
    onApplyAutoSyncMinutes: (value: number) => void;
    onApplySshAgentConfirm: (value: SshAgentConfirm) => void;
    onApplySshAgentAutoStart: (value: boolean) => void;
    onCopySocketPath: (socketPath: string) => void;
    onCopyShellCommand: (command: string) => void;
  };

  let {
    summary,
    currentLocale,
    themePref,
    autoLockMinutes,
    autoLockTrigger,
    closeToTray,
    minimizeToTray,
    hideDockOnTray,
    requireNarrowing,
    toolbarAlign,
    autoSyncMinutes,
    sshAgentConfirm,
    sshAgentAutoStart,
    onApplyLocale,
    onApplyTheme,
    onApplyAutoLock,
    onApplyCloseToTray,
    onApplyMinimizeToTray,
    onApplyHideDockOnTray,
    onApplyRequireNarrowing,
    onApplyToolbarAlign,
    onApplyAutoSyncMinutes,
    onApplySshAgentConfirm,
    onApplySshAgentAutoStart,
    onCopySocketPath,
    onCopyShellCommand,
  }: Props = $props();

  // The SSH_AUTH_SOCK guidance below is Unix-only: Windows OpenSSH
  // (ssh.exe, ssh-add, git-for-windows) finds the agent by probing the
  // \\.\pipe\openssh-ssh-agent named pipe, with no environment variable
  // involved. Same technique as prefs.svelte.ts's IS_LINUX.
  const IS_WINDOWS = /Windows/i.test(navigator.userAgent);

  let dialog = $state<HTMLDialogElement | null>(null);
  let sshAgent = $state<SshAgentStatus>({
    running: false,
    socketPath: null,
    keys: [],
    skipped: [],
  });
  let sshAgentBusy = $state(false);
  let sshAgentError = $state<string | null>(null);
  let sshAuthSockEnv = $state<string | null>(null);

  // Yubikey re-unlock enrolment state. The toggle here mutates
  // session.json on disk; the unlock view re-reads it on bootstrap,
  // which is why there's no two-way sync between this dialog and the
  // live `auth` controller. Closing and reopening the app picks up
  // any change made here.
  let yubikeyEnrolled = $state(false);
  let yubikeyEnrollPin = $state("");
  let yubikeyDisenrollPassword = $state("");
  let yubikeyBusy = $state(false);
  let yubikeyError = $state<string | null>(null);
  let yubikeyMessage = $state<string | null>(null);

  async function refreshSshAgent() {
    try {
      sshAgent = await api.sshAgentStatus();
    } catch (e) {
      console.warn("[clavix] ssh_agent_status failed:", e);
    }
    try {
      sshAuthSockEnv = await api.sshAuthSock();
    } catch (e) {
      console.warn("[clavix] ssh_auth_sock failed:", e);
    }
  }

  async function refreshYubikey() {
    try {
      yubikeyEnrolled = (await api.yubikeyUnlockState()).enrolled;
    } catch (e) {
      console.warn("[clavix] yubikey_unlock_state failed:", e);
      yubikeyEnrolled = false;
    }
  }

  async function enrollYubikey() {
    yubikeyBusy = true;
    yubikeyError = null;
    yubikeyMessage = null;
    try {
      const pin = yubikeyEnrollPin.trim();
      await api.enrollYubikeyUnlock(pin.length > 0 ? pin : null);
      yubikeyEnrollPin = "";
      yubikeyMessage = m.yubikey_unlock_enrolled();
      await refreshYubikey();
    } catch (e) {
      yubikeyError = formatError(e);
    } finally {
      yubikeyBusy = false;
    }
  }

  async function disenrollYubikey() {
    if (yubikeyDisenrollPassword.length === 0) return;
    yubikeyBusy = true;
    yubikeyError = null;
    yubikeyMessage = null;
    try {
      await api.disenrollYubikeyUnlock(yubikeyDisenrollPassword);
      yubikeyDisenrollPassword = "";
      await refreshYubikey();
    } catch (e) {
      yubikeyError = formatError(e);
    } finally {
      yubikeyBusy = false;
    }
  }

  async function toggleSshAgent() {
    sshAgentBusy = true;
    sshAgentError = null;
    try {
      if (sshAgent.running) {
        await api.stopSshAgent();
      } else {
        sshAgent = await api.startSshAgent(sshAgentConfirm);
        sshAgentBusy = false;
        return;
      }
      await refreshSshAgent();
    } catch (e) {
      sshAgentError = formatError(e);
    } finally {
      sshAgentBusy = false;
    }
  }

  // Persist the confirmation policy and, if the agent is already running,
  // relaunch it so the change takes effect immediately (the socket path
  // is stable, so SSH_AUTH_SOCK stays valid across the restart).
  async function applyConfirmPolicy(value: SshAgentConfirm) {
    onApplySshAgentConfirm(value);
    if (!sshAgent.running) return;
    sshAgentBusy = true;
    sshAgentError = null;
    try {
      sshAgent = await api.startSshAgent(value);
    } catch (e) {
      sshAgentError = formatError(e);
    } finally {
      sshAgentBusy = false;
    }
  }

  // The select encodes both halves of the setting in one value, because
  // a native <select> carries one. "off" needs no delay; everything else
  // is "<trigger>:<minutes>".
  const autoLockValue = $derived(
    autoLockTrigger === "off" ? "off" : `${autoLockTrigger}:${autoLockMinutes}`,
  );

  function applyAutoLock(raw: string) {
    if (raw === "off") {
      onApplyAutoLock("off", 0);
      return;
    }
    const [trigger, minutes] = raw.split(":");
    onApplyAutoLock(trigger as AutoLockTrigger, parseInt(minutes, 10));
  }

  // `null` until probed. Only ever false on a session whose lock state we
  // can't read (no screensaver D-Bus name, no GUI session) — in which
  // case the screen-lock options would silently never fire, so the UI
  // says so rather than letting the user pick a dead setting.
  let screenLockAvailable = $state<boolean | null>(null);

  export async function open() {
    dialog?.showModal();
    // Deliberately not awaited before the SSH/Yubikey refreshes: it's a
    // decoration on one row, and on a wedged D-Bus it can take a couple
    // of seconds to answer.
    void api
      .screenLockAvailable()
      .then((v) => (screenLockAvailable = v))
      .catch(() => (screenLockAvailable = false));
    await refreshSshAgent();
    await refreshYubikey();
  }

  function close() {
    dialog?.close();
  }
</script>

<dialog bind:this={dialog} class="stats-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>{m.stats_title()}</h2>
      <button type="button" class="secondary small" onclick={close} aria-label={m.action_close()}>
        ✕
      </button>
    </header>
    <dl>
      <dt>{m.stats_account()}</dt>
      <dd>{summary.name ?? summary.email}</dd>
      <dt>{m.stats_items()}</dt>
      <dd>{summary.itemCount}</dd>
      <dt>{m.stats_folders()}</dt>
      <dd>{summary.folderCount}</dd>
      <dt>{m.stats_collections()}</dt>
      <dd>{summary.collectionCount}</dd>
      <dt>{m.stats_organizations()}</dt>
      <dd>{summary.organizationCount}</dd>
    </dl>

    <h3>{m.settings_title()}</h3>
    <dl>
      <dt>{m.settings_language()}</dt>
      <dd>
        <select
          value={currentLocale}
          onchange={(e) => onApplyLocale((e.currentTarget as HTMLSelectElement).value as Locale)}
        >
          <option value="fr">Français</option>
          <option value="en">English</option>
        </select>
      </dd>
      <dt>{m.settings_theme()}</dt>
      <dd>
        <select
          value={themePref}
          onchange={(e) => onApplyTheme((e.currentTarget as HTMLSelectElement).value as ThemePref)}
        >
          <option value="auto">{m.settings_theme_auto()}</option>
          <option value="dark">{m.settings_theme_dark()}</option>
        </select>
      </dd>
      <dt>{m.stats_auto_lock()}</dt>
      <dd>
        <select
          value={autoLockValue}
          onchange={(e) => applyAutoLock((e.currentTarget as HTMLSelectElement).value)}
        >
          <option value="off">{m.stats_auto_lock_never()}</option>
          <optgroup label={m.stats_auto_lock_group_idle()}>
            <option value="idle:1">{m.stats_auto_lock_minutes({ count: "1" })}</option>
            <option value="idle:5">{m.stats_auto_lock_minutes({ count: "5" })}</option>
            <option value="idle:10">{m.stats_auto_lock_minutes({ count: "10" })}</option>
            <option value="idle:15">{m.stats_auto_lock_minutes({ count: "15" })}</option>
            <option value="idle:30">{m.stats_auto_lock_minutes({ count: "30" })}</option>
            <option value="idle:60">{m.stats_auto_lock_hour()}</option>
          </optgroup>
          <optgroup label={m.stats_auto_lock_group_screen()}>
            <option value="screenLock:0">{m.stats_auto_lock_screen_now()}</option>
            <option value="screenLock:5">{m.stats_auto_lock_minutes({ count: "5" })}</option>
            <option value="screenLock:15">{m.stats_auto_lock_minutes({ count: "15" })}</option>
            <option value="screenLock:60">{m.stats_auto_lock_hour()}</option>
          </optgroup>
        </select>
        <!-- One line per mode, always shown. "Inactivité" in particular
             does not mean what most people read into it — it's measured
             against this window, not against the computer — and a setting
             whose name misleads is worse than one that explains itself. -->
        {#if autoLockTrigger === "screenLock" && screenLockAvailable === false}
          <p class="hint auto-lock-warning">⚠️ {m.stats_auto_lock_screen_unavailable()}</p>
        {:else if autoLockTrigger === "screenLock"}
          <p class="hint">{m.stats_auto_lock_screen_hint()}</p>
        {:else if autoLockTrigger === "idle"}
          <p class="hint">{m.stats_auto_lock_idle_hint()}</p>
        {:else}
          <p class="hint">{m.stats_auto_lock_never_hint()}</p>
        {/if}
      </dd>
      <dt>{m.settings_auto_sync()}</dt>
      <dd>
        <select
          value={String(autoSyncMinutes)}
          onchange={(e) =>
            onApplyAutoSyncMinutes(
              parseInt((e.currentTarget as HTMLSelectElement).value, 10),
            )}
        >
          <option value="0">{m.settings_auto_sync_never()}</option>
          <option value="5">{m.stats_auto_lock_minutes({ count: "5" })}</option>
          <option value="15">{m.stats_auto_lock_minutes({ count: "15" })}</option>
          <option value="30">{m.stats_auto_lock_minutes({ count: "30" })}</option>
          <option value="60">{m.stats_auto_lock_hour()}</option>
        </select>
        <p class="hint">
          {autoSyncMinutes > 0
            ? m.settings_auto_sync_hint()
            : m.settings_auto_sync_never_hint()}
        </p>
      </dd>
      <dt>{m.settings_toolbar_align()}</dt>
      <dd>
        <select
          value={toolbarAlign}
          onchange={(e) =>
            onApplyToolbarAlign(
              (e.currentTarget as HTMLSelectElement).value as ToolbarAlign,
            )}
        >
          <option value="left">{m.settings_toolbar_align_left()}</option>
          <option value="center">{m.settings_toolbar_align_center()}</option>
        </select>
      </dd>
      <dt>{m.settings_require_narrowing()}</dt>
      <dd>
        <select
          value={requireNarrowing ? "narrow" : "all"}
          onchange={(e) =>
            onApplyRequireNarrowing(
              (e.currentTarget as HTMLSelectElement).value === "narrow",
            )}
        >
          <option value="narrow">{m.settings_require_narrowing_on()}</option>
          <option value="all">{m.settings_require_narrowing_off()}</option>
        </select>
      </dd>
      <dt>{m.settings_close_to_tray()}</dt>
      <dd>
        <select
          value={closeToTray ? "tray" : "quit"}
          onchange={(e) =>
            onApplyCloseToTray(
              (e.currentTarget as HTMLSelectElement).value === "tray",
            )}
        >
          <option value="tray">{m.settings_close_to_tray_tray()}</option>
          <option value="quit">{m.settings_close_to_tray_quit()}</option>
        </select>
      </dd>
      <dt>{m.settings_minimize_to_tray()}</dt>
      <dd>
        <select
          value={minimizeToTray ? "tray" : "taskbar"}
          onchange={(e) =>
            onApplyMinimizeToTray(
              (e.currentTarget as HTMLSelectElement).value === "tray",
            )}
        >
          <option value="tray">{m.settings_minimize_to_tray_tray()}</option>
          <option value="taskbar">{m.settings_minimize_to_tray_taskbar()}</option>
        </select>
      </dd>
      <dt>{m.settings_hide_dock_on_tray()}</dt>
      <dd>
        <select
          value={hideDockOnTray ? "hide" : "keep"}
          onchange={(e) =>
            onApplyHideDockOnTray(
              (e.currentTarget as HTMLSelectElement).value === "hide",
            )}
        >
          <option value="hide">{m.settings_hide_dock_on_tray_on()}</option>
          <option value="keep">{m.settings_hide_dock_on_tray_off()}</option>
        </select>
      </dd>
    </dl>

    <h3>{m.ssh_agent_title()}</h3>
    <p class="hint ssh-agent-hint">{m.ssh_agent_hint()}</p>
    <dl class="ssh-agent-confirm-setting">
      <dt>{m.settings_ssh_confirm()}</dt>
      <dd>
        <select
          value={sshAgentConfirm}
          disabled={sshAgentBusy}
          onchange={(e) =>
            applyConfirmPolicy((e.currentTarget as HTMLSelectElement).value as SshAgentConfirm)}
        >
          <option value="never">{m.settings_ssh_confirm_never()}</option>
          <option value="session">{m.settings_ssh_confirm_session()}</option>
          <option value="always">{m.settings_ssh_confirm_always()}</option>
        </select>
      </dd>
      <dt>{m.settings_ssh_autostart()}</dt>
      <dd>
        <label class="ssh-agent-autostart">
          <input
            type="checkbox"
            checked={sshAgentAutoStart}
            onchange={(e) => onApplySshAgentAutoStart((e.currentTarget as HTMLInputElement).checked)}
          />
          {m.settings_ssh_autostart_label()}
        </label>
        <p class="hint">{m.settings_ssh_autostart_hint()}</p>
      </dd>
    </dl>
    <div class="ssh-agent-row">
      <button type="button" onclick={toggleSshAgent} disabled={sshAgentBusy}>
        {sshAgent.running ? m.ssh_agent_stop() : m.ssh_agent_start()}
      </button>
      <span class="ssh-agent-state" class:on={sshAgent.running}>
        {sshAgent.running
          ? m.ssh_agent_running({ count: String(sshAgent.keys.length) })
          : m.ssh_agent_stopped()}
      </span>
      {#if sshAgent.running && sshAgent.skipped.length > 0}
        <!-- Say it next to the count itself: the exposed number looking
             short is exactly what sends the user hunting for an answer. -->
        <span class="ssh-agent-skipped-badge">
          {m.ssh_agent_skipped_badge({ count: String(sshAgent.skipped.length) })}
        </span>
      {/if}
    </div>
    {#if sshAgent.running && sshAgent.socketPath}
      <div class="ssh-agent-sock">
        <code>{sshAgent.socketPath}</code>
        {#if !IS_WINDOWS}
          <button
            type="button"
            class="secondary small"
            onclick={() => onCopySocketPath(sshAgent.socketPath!)}
          >
            {m.ssh_agent_copy_export()}
          </button>
        {/if}
      </div>
      {#if IS_WINDOWS}
        <!-- No SSH_AUTH_SOCK exists on Windows: ssh.exe / ssh-add probe
             the openssh-ssh-agent pipe automatically. Point at the same
             authoritative check instead of the env-var story. -->
        <p class="ssh-agent-env-ok">✓ {m.ssh_agent_env_windows_hint()}</p>
        <div class="ssh-agent-env-check">
          <div class="ssh-agent-sock">
            <code>ssh-add -l</code>
            <button
              type="button"
              class="secondary small"
              onclick={() => onCopyShellCommand("ssh-add -l")}
            >
              {m.action_copy()}
            </button>
          </div>
        </div>
      {:else}
        <!-- What follows describes CLAVIX'S OWN launch environment, which is
             frozen at process start. It says nothing about the shell where
             the user actually runs `ssh` — a correctly configured session
             still reads as a mismatch here whenever Clavix was started
             before the variable was in place. So the non-matching cases are
             worded as "can't tell from here" and point at the one check
             that is authoritative, rather than asserting a problem. -->
        {#if sshAuthSockEnv === sshAgent.socketPath}
          <p class="ssh-agent-env-ok">✓ {m.ssh_agent_env_ok()}</p>
        {:else}
          <p class="ssh-agent-env-unknown">
            {sshAuthSockEnv
              ? m.ssh_agent_env_other({ current: sshAuthSockEnv })
              : m.ssh_agent_env_unset()}
          </p>
          <div class="ssh-agent-env-check">
            <p class="hint">{m.ssh_agent_env_verify_hint()}</p>
            <div class="ssh-agent-sock">
              <code>ssh-add -l</code>
              <button
                type="button"
                class="secondary small"
                onclick={() => onCopyShellCommand("ssh-add -l")}
              >
                {m.action_copy()}
              </button>
            </div>
          </div>
        {/if}
      {/if}
    {/if}
    {#if sshAgent.running && sshAgent.keys.length > 0}
      <ul class="ssh-agent-keys">
        {#each sshAgent.keys as key (key.fingerprint)}
          <li class="ssh-agent-key">
            <span class="ssh-agent-key-comment">{key.comment || "—"}</span>
            <span class="ssh-agent-key-algo">{key.algorithm}</span>
            <!-- Shown in full: the columns now hug their content, which
                 leaves room for the whole fingerprint. CSS ellipsises it
                 if the dialog is ever too narrow, and `title` keeps the
                 full value reachable either way. -->
            <code class="ssh-agent-key-fp" title={key.fingerprint}>{key.fingerprint}</code>
          </li>
        {/each}
      </ul>
    {/if}
    {#if sshAgent.skipped.length > 0}
      <details class="ssh-agent-skipped-list">
        <summary>
          {m.ssh_agent_skipped({ count: String(sshAgent.skipped.length) })}
        </summary>
        <ul>
          {#each sshAgent.skipped as sk (sk.name + sk.reason)}
            <li>
              <strong>{sk.name}</strong>
              <span class="ssh-agent-skip-reason">{sk.reason}</span>
            </li>
          {/each}
        </ul>
      </details>
    {/if}
    {#if sshAgentError}
      <p class="audit-error">{sshAgentError}</p>
    {/if}

    <h3>{m.yubikey_unlock_section_title()}</h3>
    <p class="hint">{m.yubikey_unlock_section_hint()}</p>
    <p class="yubikey-warning">{m.yubikey_unlock_warning()}</p>
    {#if yubikeyEnrolled}
      <form
        class="yubikey-disenroll"
        onsubmit={(e) => {
          e.preventDefault();
          disenrollYubikey();
        }}
      >
        <label>
          {m.yubikey_unlock_disenroll_password()}
          <PasswordInput
            bind:value={yubikeyDisenrollPassword}
            autocomplete="off"
            disabled={yubikeyBusy}
            required
          />
          <small class="yubikey-master-note">⚠️ {m.yubikey_unlock_master_not_pin()}</small>
        </label>
        <button
          type="submit"
          class="secondary"
          disabled={yubikeyBusy || yubikeyDisenrollPassword.length === 0}
        >
          {yubikeyBusy ? m.yubikey_unlock_disenrolling() : m.yubikey_unlock_disenroll()}
        </button>
      </form>
    {:else}
      <form
        class="yubikey-enroll"
        onsubmit={(e) => {
          e.preventDefault();
          enrollYubikey();
        }}
      >
        <label>
          {m.yubikey_unlock_pin_label()}
          <PasswordInput
            bind:value={yubikeyEnrollPin}
            autocomplete="off"
            disabled={yubikeyBusy}
            placeholder={m.yubikey_unlock_pin_placeholder()}
          />
        </label>
        <button type="submit" disabled={yubikeyBusy}>
          {yubikeyBusy ? m.yubikey_unlock_enrolling() : m.yubikey_unlock_enroll()}
        </button>
      </form>
    {/if}
    {#if yubikeyMessage}
      <p class="yubikey-message">{yubikeyMessage}</p>
    {/if}
    {#if yubikeyError}
      <p class="audit-error">{yubikeyError}</p>
    {/if}

    <h3>{m.stats_breakdown()}</h3>
    <dl>
      <dt>{m.stats_logins()}</dt>
      <dd>{summary.typeCounts.login}</dd>
      <dt>{m.stats_notes()}</dt>
      <dd>{summary.typeCounts.secureNote}</dd>
      <dt>{m.stats_cards()}</dt>
      <dd>{summary.typeCounts.card}</dd>
      <dt>{m.stats_identities()}</dt>
      <dd>{summary.typeCounts.identity}</dd>
      {#if summary.typeCounts.sshKey > 0}
        <dt>{m.stats_ssh_keys()}</dt>
        <dd>{summary.typeCounts.sshKey}</dd>
      {/if}
    </dl>
  {/key}
</dialog>
