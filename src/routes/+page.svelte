<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import CipherEditor from "$lib/CipherEditor.svelte";
  import ImportDialog from "$lib/ImportDialog.svelte";
  import ExportDialog from "$lib/ExportDialog.svelte";
  import AuthGate from "$lib/AuthGate.svelte";
  import Toolbar from "$lib/Toolbar.svelte";
  import VaultSidebar from "$lib/VaultSidebar.svelte";
  import CipherList from "$lib/CipherList.svelte";
  import CipherDetail from "$lib/CipherDetail.svelte";
  import ClipboardToast from "$lib/ClipboardToast.svelte";
  import GeneratorDialog from "$lib/GeneratorDialog.svelte";
  import StatsDialog from "$lib/StatsDialog.svelte";
  import AuditDialog from "$lib/AuditDialog.svelte";
  import AboutDialog from "$lib/AboutDialog.svelte";
  import SshConfirmDialog from "$lib/SshConfirmDialog.svelte";
  import ConfirmDialog from "$lib/ConfirmDialog.svelte";
  import RepromptDialog from "$lib/RepromptDialog.svelte";
  import UpdateBanner from "$lib/UpdateBanner.svelte";
  import StandaloneBanner from "$lib/StandaloneBanner.svelte";
  import { ClipboardController, type ClipboardVariant } from "$lib/clipboard.svelte";
  import { DragController } from "$lib/drag.svelte";
  import { AuthController } from "$lib/auth.svelte";
  import { VaultController } from "$lib/vault.svelte";
  import {
    DETAIL_HEIGHT_MAX,
    DETAIL_HEIGHT_MIN,
    PrefsController,
    TREE_WIDTH_MAX,
    TREE_WIDTH_MIN,
  } from "$lib/prefs.svelte";
  import { api } from "$lib/api";
  import { setupAutoLock } from "$lib/auto-lock.svelte";
  import { setupAutoSync } from "$lib/auto-sync.svelte";
  import { formatError } from "$lib/format";
  import { startSplitterDrag } from "$lib/splitter";
  import { makeVaultKeyHandler } from "$lib/keyboard";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import type {
    CipherDetail as CipherDetailData,
    CipherSummary,
    ConfirmFn,
    UpdateInfo,
  } from "$lib/types";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";

  const prefs = new PrefsController();
  const drag = new DragController();

  // Every drop in this app is a write (move to folder, move to
  // collection, share). With no server behind the vault there is
  // nowhere for one to land, so no drag may start at all.
  $effect(() => {
    drag.disabled = auth.isReadOnly;
  });
  const clipboard = new ClipboardController();
  const auth = new AuthController();
  const vault = new VaultController();

  let searchInput: HTMLInputElement | null = null;
  let statsDialog = $state<{ open: () => Promise<void> } | null>(null);
  let auditDialog = $state<{ open: () => void } | null>(null);
  let aboutDialog = $state<{ open: () => Promise<void> } | null>(null);
  let generatorDialog = $state<{ open: () => void } | null>(null);
  let confirmDialog = $state<{ ask: ConfirmFn } | null>(null);
  let repromptDialog = $state<{ ask: (name: string) => Promise<boolean> } | null>(null);
  let importOpen = $state(false);
  let exportOpen = $state(false);

  // Every destructive action funnels through here. The dialog is mounted
  // unconditionally at the bottom of the page, so a null `confirmDialog`
  // would mean the component tree isn't up yet — answer "no" rather than
  // let a delete through unconfirmed.
  const confirm: ConfirmFn = async (request) =>
    (await confirmDialog?.ask(request)) ?? false;

  /**
   * The per-item master-password gate.
   *
   * Owned by the page rather than by the detail panel because a flagged
   * item can be reached from four places — the panel, the row context
   * menu, the Ctrl+B/C/T shortcuts and the editor — and a gate that only
   * covers one of them is decoration. Answering it unlocks the item
   * until the vault locks, so an item with three secrets asks once.
   *
   * Fails closed, like `confirm`: no dialog, no reveal.
   */
  let unlockedItems = $state<Set<string>>(new Set());

  async function requireReprompt(
    item: { id: string; name: string; reprompt: boolean } | null,
  ): Promise<boolean> {
    if (!item) return false;
    if (!item.reprompt || unlockedItems.has(item.id)) return true;
    const ok = (await repromptDialog?.ask(item.name)) ?? false;
    if (ok) unlockedItems = new Set(unlockedItems).add(item.id);
    return ok;
  }

  /** Gate for a cipher we only know by id — resolves the loaded detail. */
  async function requireRepromptForId(id: string): Promise<boolean> {
    const detail = vault.detail?.id === id ? vault.detail : await api.getCipher(id);
    return requireReprompt(detail);
  }

  async function confirmSoftDelete(id: string, name: string) {
    const ok = await confirm({
      title: m.action_confirm_soft_delete_title(),
      body: m.action_confirm_soft_delete({ name }),
      confirmLabel: m.action_soft_delete(),
      danger: true,
    });
    if (ok) await vault.softDeleteCipher(id);
  }

  async function confirmDeleteForever(id: string, name: string) {
    const ok = await confirm({
      title: m.action_confirm_delete_title(),
      body: m.action_confirm_delete({ name }),
      confirmLabel: m.action_delete_forever(),
      danger: true,
    });
    if (ok) await vault.deleteCipherForever(id);
  }

  async function confirmDuplicate(id: string, name: string) {
    const ok = await confirm({
      title: m.action_confirm_duplicate_title(),
      body: m.action_confirm_duplicate({ name }),
      confirmLabel: m.action_duplicate(),
    });
    if (ok) await vault.duplicateCipher(id, m.action_duplicate_suffix());
  }

  // ---- multi-selection ----------------------------------------------
  // The set lives here rather than in the vault store: it is a property
  // of what is on screen, and every filter change or sync that rebuilds
  // the list can leave ids in it that no longer exist. `selectedIds` is
  // therefore reconciled against the visible items before any bulk call.
  let selectedIds = $state<Set<string>>(new Set());
  const trashView = $derived(vault.quickFilter === "trash");

  function toggleSelection(id: string) {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selectedIds = next;
  }

  function setSelection(ids: string[]) {
    selectedIds = new Set(ids);
  }

  function clearSelection() {
    if (selectedIds.size > 0) selectedIds = new Set();
  }

  /** The selection, minus anything the current list no longer shows. */
  function liveSelection(): string[] {
    const visible = new Set(vault.filteredCiphers.map((c) => c.id));
    return [...selectedIds].filter((id) => visible.has(id));
  }

  function reportBulkFailures(failed: number) {
    vault.error = failed > 0 ? m.bulk_failed({ count: String(failed) }) : null;
  }

  async function bulkDelete() {
    const ids = liveSelection();
    if (ids.length === 0) return;
    const count = String(ids.length);
    // Inside the trash, "delete" is the permanent one — same as the
    // per-item buttons in the detail panel.
    const ok = await confirm(
      trashView
        ? {
            title: m.bulk_delete_forever_confirm_title(),
            body: m.bulk_delete_forever_confirm({ count }),
            confirmLabel: m.action_delete_forever(),
            danger: true,
          }
        : {
            title: m.bulk_delete_confirm_title(),
            body: m.bulk_delete_confirm({ count }),
            confirmLabel: m.action_soft_delete(),
            danger: true,
          },
    );
    if (!ok) return;
    const failed = trashView
      ? await vault.bulkDeleteForever(ids)
      : await vault.bulkSoftDelete(ids);
    clearSelection();
    reportBulkFailures(failed);
  }

  async function bulkRestore() {
    const ids = liveSelection();
    if (ids.length === 0) return;
    const failed = await vault.bulkRestore(ids);
    clearSelection();
    reportBulkFailures(failed);
  }

  async function bulkMove(folderId: string | null) {
    const ids = liveSelection();
    if (ids.length === 0) return;
    const failed = await vault.bulkMoveToFolder(ids, folderId);
    clearSelection();
    reportBulkFailures(failed);
  }

  // Update check: populated once at startup by the Rust check (see api.checkForUpdate).
  // The banner shows only while a newer version exists and the user hasn't
  // dismissed it this session.
  let updateInfo = $state<UpdateInfo | null>(null);
  let updateDismissed = $state(false);
  const showUpdateBanner = $derived(
    updateInfo?.updateAvailable === true && !updateDismissed,
  );

  async function openReleasePage() {
    if (!updateInfo) return;
    try {
      await openUrl(updateInfo.url);
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  // "Show all items" is a per-session escape hatch from the gate: it lasts
  // until the vault is locked, and does not touch the stored preference.
  let showAllOnce = $state(false);
  const listGated = $derived(
    prefs.requireNarrowing &&
      !showAllOnce &&
      !vault.hasNarrowing &&
      vault.quickFilter === "all",
  );

  auth.on(async (event) => {
    if (event === "loggedIn") {
      // A file-backed standalone session already holds its vault; it
      // has no cache entry and nothing to sync against.
      if (auth.origin === "exportFile") {
        await vault.loadStandalone();
        return;
      }

      // Paint the UI immediately from the encrypted local cache, then
      // reconcile against the server in the background. On a fresh
      // profile loadCached finds nothing and syncInBackground fills the
      // vault once the network roundtrip lands — no more empty screen
      // until the user hits "Sync" manually.
      await vault.loadCached();

      // A cache-backed session has no server to reconcile with, and
      // starting the SSH agent in an emergency unlock would expose the
      // vault's keys on a socket without the user asking.
      if (auth.isReadOnly) return;

      vault.syncInBackground();
      void autoStartSshAgent();
    }
  });

  // Bring the SSH agent back after an unlock, when the user opted in.
  //
  // Deliberately placed after `loadCached()`: starting the agent needs a
  // decrypted vault, and the cache supplies one without waiting for the
  // network — so this works offline too. A profile with no cache yet has
  // no keys to load, and the attempt simply fails; the settings dialog
  // still offers Start, so nothing is lost but the automatic step.
  //
  // Failures stay quiet on purpose. This is a convenience the user did
  // not trigger by hand, and an error toast on every unlock (say, on a
  // machine where the socket path is unavailable) would be noise.
  async function autoStartSshAgent() {
    if (!prefs.sshAgentAutoStart) return;
    try {
      await api.startSshAgent(prefs.sshAgentConfirm);
    } catch (e) {
      console.warn("[clavix] ssh agent auto-start failed:", e);
    }
  }

  // Tint the clipboard toast by what was copied. Nearly every copy funnels
  // through here, so deriving the kind from the label keeps the call sites
  // untouched; anything unrecognised (URLs, SSH socket, …) stays the default.
  function clipboardVariant(label: string): ClipboardVariant {
    const l = label.toLowerCase();
    if (l.includes("passe") || l.includes("password")) return "password";
    if (l.includes("totp") || l.includes("otp")) return "totp";
    if (l.includes("identifiant") || l.includes("username")) return "username";
    return "default";
  }

  async function copyToClipboard(value: string, label: string) {
    try {
      await clipboard.copy(value, label, clipboardVariant(label));
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  // Right-click context menu over a list row. Mirrors the KeePassXC entry
  // menu: open, copy username (Ctrl+B), copy password (Ctrl+C), copy the
  // current TOTP (Ctrl+T), open the URL (Ctrl+U). Username/URL come straight
  // from the summary so the menu paints instantly; password/TOTP need the
  // decrypted detail, which we fetch in the background — those two rows only
  // appear once we actually know the item carries them.
  let menuCipher = $state<CipherSummary | null>(null);
  let menuDetail = $state<CipherDetailData | null>(null);
  let menuX = $state(0);
  let menuY = $state(0);
  let menuEl = $state<HTMLDivElement | null>(null);

  function openRowMenu(event: MouseEvent, cipher: CipherSummary) {
    event.preventDefault();
    menuCipher = cipher;
    menuDetail = vault.detail?.id === cipher.id ? vault.detail : null;
    menuX = event.clientX;
    menuY = event.clientY;
    // Only login items can carry a password/TOTP worth decrypting for.
    if (!menuDetail && cipher.kind === 1) {
      void loadMenuDetail(cipher.id);
    }
  }

  async function loadMenuDetail(id: string) {
    try {
      const detail = await api.getCipher(id);
      // Guard against a stale response: the menu may have closed or moved
      // to another row while the decrypt was in flight.
      if (menuCipher?.id === id) menuDetail = detail;
    } catch {
      // The menu simply won't gain the decrypt-only actions; opening the
      // item surfaces the real error through the normal path.
    }
  }

  function closeRowMenu() {
    menuCipher = null;
    menuDetail = null;
  }

  // Tug the menu back inside the viewport once laid out, so a right-click
  // near the right/bottom edge doesn't clip its actions.
  $effect(() => {
    if (menuCipher === null || menuEl === null) return;
    const rect = menuEl.getBoundingClientRect();
    const overflowX = rect.right - window.innerWidth;
    const overflowY = rect.bottom - window.innerHeight;
    if (overflowX > 0) menuX = Math.max(8, menuX - overflowX - 8);
    if (overflowY > 0) menuY = Math.max(8, menuY - overflowY - 8);
  });

  function openMenuCipher() {
    const id = menuCipher?.id;
    closeRowMenu();
    if (id) vault.openCipher(id);
  }

  async function copyMenuUsername() {
    const username = menuDetail?.login?.username ?? menuCipher?.username;
    closeRowMenu();
    if (username) await copyToClipboard(username, "identifiant");
  }

  async function copyMenuPassword() {
    const id = menuCipher?.id;
    const detail = menuDetail;
    const hasPassword = detail?.login?.hasPassword;
    closeRowMenu();
    if (!id || !hasPassword) return;
    if (!(await requireReprompt(detail))) return;
    try {
      const password = await api.revealField(id, "password");
      if (password) await copyToClipboard(password, "mot de passe");
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  async function copyMenuTotp() {
    const id = menuCipher?.id;
    const detail = menuDetail;
    const hasTotp = detail?.login?.hasTotp;
    closeRowMenu();
    if (!id || !hasTotp) return;
    if (!(await requireReprompt(detail))) return;
    try {
      const { code } = await api.totpCode(id);
      await copyToClipboard(code, "code TOTP");
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  async function openMenuUri() {
    const uri = menuCipher?.primaryUri;
    closeRowMenu();
    if (!uri) return;
    try {
      await openUrl(uri);
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  // Delete/restore from the row menu, so the trash is reachable without
  // opening the item first. Name and id are read before closing the menu
  // — `closeRowMenu` clears `menuCipher`, and the confirmation that
  // follows is asynchronous.
  async function softDeleteMenuCipher() {
    const cipher = menuCipher;
    closeRowMenu();
    if (cipher) await confirmSoftDelete(cipher.id, cipher.name);
  }

  async function deleteMenuCipherForever() {
    const cipher = menuCipher;
    closeRowMenu();
    if (cipher) await confirmDeleteForever(cipher.id, cipher.name);
  }

  async function duplicateMenuCipher() {
    const cipher = menuCipher;
    closeRowMenu();
    if (cipher) await confirmDuplicate(cipher.id, cipher.name);
  }

  async function restoreMenuCipher() {
    const id = menuCipher?.id;
    closeRowMenu();
    if (id) await vault.restoreCipher(id);
  }

  async function copySshAgentSocket(socketPath: string) {
    await copyToClipboard(`export SSH_AUTH_SOCK=${socketPath}`, "SSH_AUTH_SOCK");
  }

  // Copies a shell command verbatim — unlike copySshAgentSocket, which
  // wraps its argument in an `export` assignment.
  async function copyShellCommand(command: string) {
    await copyToClipboard(command, "commande");
  }

  async function lockAndReset() {
    await auth.lock();
    vault.reset();
    showAllOnce = false;
    closeRowMenu();
    clearSelection();
    // A reprompt answered before the lock must not still count after it.
    unlockedItems = new Set();
  }

  async function switchAccountAndReset() {
    await auth.switchAccount();
    vault.reset();
    clearSelection();
    unlockedItems = new Set();
  }

  function onSplitterMouseDown(event: MouseEvent) {
    startSplitterDrag(event, {
      axis: "x",
      min: TREE_WIDTH_MIN,
      max: TREE_WIDTH_MAX,
      startSize: prefs.treeWidth,
      onChange: (w) => (prefs.treeWidth = w),
      onCommit: () => prefs.persistTreeWidth(),
    });
  }

  function onDetailSplitterMouseDown(event: MouseEvent) {
    startSplitterDrag(event, {
      axis: "y",
      invert: true,
      min: DETAIL_HEIGHT_MIN,
      max: DETAIL_HEIGHT_MAX,
      startSize: prefs.detailHeight,
      onChange: (h) => (prefs.detailHeight = h),
      onCommit: () => prefs.persistDetailHeight(),
    });
  }

  const handleGlobalKeydown = makeVaultKeyHandler({
    isLoggedIn: () => auth.phase === "loggedIn",
    getDetail: () => vault.detail,
    getSearchInput: () => searchInput,
    closeDetail: () => vault.closeDetail(),
    lock: () => lockAndReset(),
    copy: copyToClipboard,
    // Ctrl+C / Ctrl+T act on the item the detail panel is showing, so
    // the gate is the same one that panel uses. An empty string means
    // "nothing to copy" to the handler, which is what a refused prompt
    // should look like.
    getPassword: async (id) =>
      (await requireRepromptForId(id)) ? ((await api.revealField(id, "password")) ?? "") : "",
    getTotpCode: async (id) =>
      (await requireRepromptForId(id)) ? (await api.totpCode(id)).code : "",
    onError: (e) => (vault.error = formatError(e)),
  });

  // Suppress the WebKitGTK native context menu (Reload / Back / Forward
  // / Inspect Element) everywhere except inside text-editable surfaces,
  // so users keep Paste / Copy / Spell-check on inputs, textareas and
  // contenteditable nodes. The folder-tree right-click in VaultSidebar
  // already calls preventDefault on its own; this handler covers every
  // other surface (cipher list, detail, dialogs, toolbar, empty space)
  // where the default debug menu would otherwise leak through.
  function suppressNativeContextMenu(event: MouseEvent) {
    const t = event.target;
    if (
      t instanceof HTMLInputElement ||
      t instanceof HTMLTextAreaElement ||
      (t instanceof HTMLElement && t.isContentEditable)
    ) {
      return;
    }
    event.preventDefault();
  }

  setupAutoLock({
    getTrigger: () => prefs.autoLockTrigger,
    getMinutes: () => prefs.autoLockMinutes,
    getLastActivityAt: () => prefs.lastActivityAt,
    markActivity: () => prefs.markActivity(),
    isLoggedIn: () => auth.phase === "loggedIn",
    onLock: lockAndReset,
  });

  setupAutoSync({
    getMinutes: () => prefs.autoSyncMinutes,
    isLoggedIn: () => auth.phase === "loggedIn",
    getLastSyncAt: () => vault.lastSyncAt,
    // The editor holds unsaved input against a cipher a sync would
    // replace under it, so an open editor postpones the refresh rather
    // than racing it. A sync already in flight is skipped for the
    // obvious reason.
    canSync: () => !vault.syncing && !vault.editorOpen,
    onSync: () => vault.syncInBackground({ quiet: true }),
  });

  // Mirror the close-to-tray preference into Rust whenever it
  // changes (and once on bootstrap, after `prefs.bootstrap()` lands
  // the localStorage value). The window-event handler reads from
  // an AtomicBool on AppState, so this keeps the X button's
  // behaviour in lockstep with the dialog toggle.
  $effect(() => {
    api.setCloseToTray(prefs.closeToTray).catch((e) => {
      console.warn("[clavix] setCloseToTray failed:", e);
    });
  });
  $effect(() => {
    api.setMinimizeToTray(prefs.minimizeToTray).catch((e) => {
      console.warn("[clavix] setMinimizeToTray failed:", e);
    });
  });
  $effect(() => {
    api.setHideDockOnTray(prefs.hideDockOnTray).catch((e) => {
      console.warn("[clavix] setHideDockOnTray failed:", e);
    });
  });
  // Hand the user's locale to the tray menu builder so the
  // Ouvrir / Verrouiller / Quitter strings switch with the
  // language toggle. Native menus don't go through Paraglide,
  // hence the dedicated IPC.
  $effect(() => {
    api.setTrayLocale(prefs.currentLocale).catch((e) => {
      console.warn("[clavix] setTrayLocale failed:", e);
    });
  });

  let unlistenSessionLocked: UnlistenFn | null = null;

  onMount(async () => {
    prefs.bootstrap();
    await auth.bootstrap({ onboarded: prefs.isOnboarded() });
    // Tray menu "Verrouiller maintenant" clears the Rust session
    // out-of-band — without this listener the UI would stay on the
    // vault view until the next IPC call hits a session check.
    unlistenSessionLocked = await listen("clavix:session-locked", () => {
      lockAndReset();
    });
    // Fire-and-forget: a failed update check must never disrupt startup, so we
    // swallow errors (offline, rate-limited, GitHub down) and simply show no
    // banner.
    api
      .checkForUpdate()
      .then((info) => {
        updateInfo = info;
      })
      .catch(() => {});
  });

  onDestroy(() => {
    clipboard.dispose();
    vault.dispose();
    unlistenSessionLocked?.();
  });

  function completeOnboarding() {
    prefs.markOnboarded();
    auth.phase = "idle";
  }

  const errorMsg = $derived(auth.error ?? vault.error);
  const wide = $derived(auth.phase === "loggedIn" && vault.summary !== null);
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === "Escape" && menuCipher) {
      e.preventDefault();
      closeRowMenu();
      return;
    }
    handleGlobalKeydown(e);
  }}
  oncontextmenu={suppressNativeContextMenu}
/>

<main class="container" class:wide>
  {#key prefs.currentLocale}
    {#if auth.phase !== "loggedIn"}
      <div class="auth-screen">
        <AuthGate
          {auth}
          onOnboardingComplete={completeOnboarding}
          currentLocale={prefs.currentLocale}
          onApplyLocale={(loc) => prefs.applyLocale(loc, { reload: true })}
        />
      </div>
    {:else}
      <AuthGate
        {auth}
        onOnboardingComplete={completeOnboarding}
        currentLocale={prefs.currentLocale}
        onApplyLocale={(loc) => prefs.applyLocale(loc, { reload: true })}
      />
    {/if}

    {#if auth.phase === "loggedIn"}
      {#if auth.isReadOnly && auth.origin}
        <StandaloneBanner origin={auth.origin} />
      {/if}
      {#if showUpdateBanner && updateInfo}
        <UpdateBanner
          info={updateInfo}
          onView={openReleasePage}
          onDismiss={() => (updateDismissed = true)}
        />
      {/if}
      <Toolbar
        align={prefs.toolbarAlign}
        syncing={vault.syncing}
        hasSync={vault.summary !== null}
        lastSyncAt={vault.lastSyncAt}
        lastSyncError={vault.lastSyncError}
        readOnly={auth.isReadOnly}
        onSync={() => vault.sync()}
        onLock={lockAndReset}
        onSwitchAccount={switchAccountAndReset}
        onCreateItem={() => vault.openCreateEditor()}
        onOpenImport={() => (importOpen = true)}
        onOpenExport={() => (exportOpen = true)}
        onOpenGenerator={() => generatorDialog?.open()}
        onOpenAudit={() => auditDialog?.open()}
        onOpenStats={() => statsDialog?.open()}
        onOpenAbout={() => aboutDialog?.open()}
      />

      {#if vault.summary}
        <section class="vault-section">
          {#if vault.summary.ciphers.length > 0}
            <div class="vault-layout" style="--tree-width: {prefs.treeWidth}px;">
              <VaultSidebar
                summary={vault.summary}
                folderTree={vault.folderTree}
                orgTrees={vault.orgTrees}
                cipherIndex={vault.cipherIndex}
                expanded={vault.expanded}
                selectedKey={vault.selectedKey}
                quickFilter={vault.quickFilter}
                currentLocale={prefs.currentLocale}
                {drag}
                onSelectQuickFilter={(f) => vault.selectQuickFilter(f)}
                onSelectNode={(k) => vault.selectNode(k)}
                onToggleExpanded={(k) => vault.toggleExpanded(k)}
                onExpandAll={() => vault.expandAllNodes()}
                onCollapseAll={() => vault.collapseAllNodes()}
                onMoveCipherToFolder={(id, fid) => vault.moveCipherToFolder(id, fid)}
                onMoveCipherToCollection={(id, cid) => vault.moveCipherToCollection(id, cid)}
                onMoveFolderPath={(s, t) => vault.performFolderMove(s, t)}
                onDeleteFolder={(ids) => vault.deleteFolder(ids)}
                {confirm}
                onRenameFolder={(src, dst) => vault.renameFolderPath(src, dst)}
              />

              <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
              <div
                class="splitter"
                role="separator"
                aria-orientation="vertical"
                aria-label={m.a11y_resize_tree()}
                onmousedown={onSplitterMouseDown}
              ></div>

              <CipherList
                items={vault.filteredCiphers}
                totalCount={vault.summary.ciphers.length}
                hasNarrowing={vault.hasNarrowing}
                gated={listGated}
                onShowAll={() => (showAllOnce = true)}
                selectedId={vault.detail?.id ?? null}
                sortKey={vault.sortKey}
                sortAsc={vault.sortAsc}
                storedAccount={auth.storedAccount}
                visibleColumns={prefs.visibleColumns}
                {drag}
                onOpenCipher={(id) => vault.openCipher(id)}
                onEditCipher={(id) =>
                  auth.isReadOnly ? undefined : vault.openEditorFor(id, requireReprompt)}
                onRowContextMenu={openRowMenu}
                onToggleSort={(k) => vault.toggleSort(k)}
                onToggleColumn={(k, v) => prefs.setVisibleColumn(k, v)}
                onSearchInputRef={(el) => (searchInput = el)}
                bind:search={vault.search}
                {selectedIds}
                onToggleSelection={toggleSelection}
                onSetSelection={setSelection}
                onClearSelection={clearSelection}
                folders={vault.summary.folders}
                {trashView}
                onBulkMove={bulkMove}
                onBulkDelete={bulkDelete}
                onBulkRestore={bulkRestore}
                readOnly={auth.isReadOnly}
              />
            </div>

            {#if vault.detailLoading}
              <section class="box">
                <p class="hint">{m.detail_decrypting()}</p>
              </section>
            {/if}

            {#if vault.detail}
              <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
              <div
                class="detail-splitter"
                role="separator"
                aria-orientation="horizontal"
                aria-label={m.a11y_resize_detail()}
                onmousedown={onDetailSplitterMouseDown}
              ></div>
              <div class="detail-pane" style="height: {prefs.detailHeight}px;">
                <CipherDetail
                  detail={vault.detail}
                  summaryEntry={vault.detailSummaryEntry}
                  organizations={vault.summary.organizations}
                  onCopy={copyToClipboard}
                  onClose={() => vault.closeDetail()}
                  onEdit={async () => {
                    if (await requireReprompt(vault.detail)) await vault.openEditEditor();
                  }}
                  onRestore={(id) => vault.restoreCipher(id)}
                  onSoftDelete={(id) => confirmSoftDelete(id, vault.detail?.name ?? "")}
                  onDeleteForever={(id) => confirmDeleteForever(id, vault.detail?.name ?? "")}
                  onDuplicate={confirmDuplicate}
                  onReprompt={() => requireReprompt(vault.detail)}
                  {confirm}
                  onError={(e) => (vault.error = formatError(e))}
                  onRefresh={(id) => vault.openCipher(id)}
                  readOnly={auth.isReadOnly}
                />
              </div>
            {/if}
          {/if}
        </section>
      {/if}
    {/if}

    {#if errorMsg}
      <section class="box error">
        <h2>{m.error()}</h2>
        <pre>{errorMsg}</pre>
      </section>
    {/if}
  {/key}
</main>

<ClipboardToast {clipboard} />

{#if menuCipher}
  <!-- Click-anywhere-else dismisses; right-clicking elsewhere is swallowed so
       the native WebKit menu never leaks through. Keyboard reaches the items
       via tab order, Escape closes it (handled on the window). -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div
    class="ctx-menu-backdrop"
    onclick={closeRowMenu}
    oncontextmenu={(e) => {
      e.preventDefault();
      closeRowMenu();
    }}
  ></div>
  <div
    bind:this={menuEl}
    class="ctx-menu"
    role="menu"
    style="left: {menuX}px; top: {menuY}px;"
  >
    <button type="button" role="menuitem" onclick={openMenuCipher}>
      <span class="ctx-label">{m.ctx_open()}</span>
    </button>
    {#if menuCipher.username}
      <button type="button" role="menuitem" onclick={copyMenuUsername}>
        <span class="ctx-label">{m.ctx_copy_username()}</span>
        <kbd class="ctx-shortcut">Ctrl+B</kbd>
      </button>
    {/if}
    {#if menuDetail?.login?.hasPassword}
      <button type="button" role="menuitem" onclick={copyMenuPassword}>
        <span class="ctx-label">{m.ctx_copy_password()}</span>
        <kbd class="ctx-shortcut">Ctrl+C</kbd>
      </button>
    {/if}
    {#if menuDetail?.login?.hasTotp}
      <button type="button" role="menuitem" onclick={copyMenuTotp}>
        <span class="ctx-label">{m.ctx_copy_totp()}</span>
        <kbd class="ctx-shortcut">Ctrl+T</kbd>
      </button>
    {/if}
    {#if menuCipher.primaryUri}
      <button type="button" role="menuitem" onclick={openMenuUri}>
        <span class="ctx-label">{m.ctx_open_url()}</span>
        <kbd class="ctx-shortcut">Ctrl+U</kbd>
      </button>
    {/if}
    <!-- Everything below writes. In standalone mode the menu keeps only
         its open/copy entries. -->
    {#if !auth.isReadOnly}
      {#if !menuCipher.deletedDate}
        <button type="button" role="menuitem" onclick={duplicateMenuCipher}>
          <span class="ctx-label">{m.action_duplicate()}</span>
        </button>
      {/if}
      <!-- Destructive block, kept below a rule and away from the copy
           actions: the row above it is one the user hits constantly. -->
      <div class="ctx-sep" role="separator"></div>
      {#if menuCipher.deletedDate}
        <button type="button" role="menuitem" onclick={restoreMenuCipher}>
          <span class="ctx-label">{m.action_restore()}</span>
        </button>
        <button type="button" role="menuitem" class="danger" onclick={deleteMenuCipherForever}>
          <span class="ctx-label">{m.action_delete_forever()}</span>
        </button>
      {:else}
        <button type="button" role="menuitem" class="danger" onclick={softDeleteMenuCipher}>
          <span class="ctx-label">{m.action_soft_delete()}</span>
        </button>
      {/if}
    {/if}
  </div>
{/if}

<GeneratorDialog
  bind:this={generatorDialog}
  currentLocale={prefs.currentLocale}
  onCopy={(value) => copyToClipboard(value, m.detail_field_password())}
/>

{#if vault.summary}
  <StatsDialog
    bind:this={statsDialog}
    summary={vault.summary}
    currentLocale={prefs.currentLocale}
    themePref={prefs.themePref}
    autoLockMinutes={prefs.autoLockMinutes}
    autoLockTrigger={prefs.autoLockTrigger}
    closeToTray={prefs.closeToTray}
    minimizeToTray={prefs.minimizeToTray}
    hideDockOnTray={prefs.hideDockOnTray}
    requireNarrowing={prefs.requireNarrowing}
    toolbarAlign={prefs.toolbarAlign}
    autoSyncMinutes={prefs.autoSyncMinutes}
    sshAgentConfirm={prefs.sshAgentConfirm}
    sshAgentAutoStart={prefs.sshAgentAutoStart}
    onApplyLocale={(loc) => prefs.applyLocale(loc, { reload: true })}
    onApplyTheme={(t) => prefs.applyTheme(t)}
    onApplyAutoLock={(trigger, min) => prefs.setAutoLock(trigger, min)}
    onApplyCloseToTray={(v) => prefs.setCloseToTray(v)}
    onApplyMinimizeToTray={(v) => prefs.setMinimizeToTray(v)}
    onApplyHideDockOnTray={(v) => prefs.setHideDockOnTray(v)}
    onApplyRequireNarrowing={(v) => prefs.setRequireNarrowing(v)}
    onApplyToolbarAlign={(v) => prefs.setToolbarAlign(v)}
    onApplyAutoSyncMinutes={(v) => prefs.setAutoSyncMinutes(v)}
    onApplySshAgentConfirm={(v) => prefs.setSshAgentConfirm(v)}
    onApplySshAgentAutoStart={(v) => prefs.setSshAgentAutoStart(v)}
    onCopySocketPath={copySshAgentSocket}
    onCopyShellCommand={copyShellCommand}
  />
{/if}

<AuditDialog
  bind:this={auditDialog}
  currentLocale={prefs.currentLocale}
  onJumpToCipher={(id) => vault.jumpToCipher(id)}
/>

<AboutDialog bind:this={aboutDialog} currentLocale={prefs.currentLocale} />

<!-- Always mounted: the SSH agent can request a signature confirmation
     at any time, including while the vault view is up or hidden. -->
<SshConfirmDialog />

<!-- Shared "are you sure?" prompt. Its strings come from the caller, so
     it needs no `{#key currentLocale}` wrapper — each `ask()` builds
     them fresh at the language in force. -->
<ConfirmDialog bind:this={confirmDialog} />

<!-- Per-item master-password gate (Bitwarden's "reprompt"). -->
<RepromptDialog bind:this={repromptDialog} />

{#key prefs.currentLocale}
  <CipherEditor
    open={vault.editorOpen}
    mode={vault.editorMode}
    initial={vault.editorInitial}
    folders={vault.summary?.folders ?? []}
    organizations={vault.summary?.organizations ?? []}
    collections={vault.summary?.collections ?? []}
    currentLocale={prefs.currentLocale}
    onCancel={() => vault.closeEditor()}
    onSubmit={(input) => vault.submitEditor(input)}
    onCopy={copyToClipboard}
  />
  <ImportDialog
    open={importOpen}
    folders={vault.summary?.folders ?? []}
    organizations={vault.summary?.organizations ?? []}
    collections={vault.summary?.collections ?? []}
    existing={vault.summary?.ciphers ?? []}
    onCancel={() => (importOpen = false)}
    onDone={async () => {
      importOpen = false;
      await vault.sync();
    }}
  />
  <ExportDialog
    open={exportOpen}
    ciphers={vault.summary?.ciphers ?? []}
    folders={vault.summary?.folders ?? []}
    onCancel={() => (exportOpen = false)}
  />
{/key}
