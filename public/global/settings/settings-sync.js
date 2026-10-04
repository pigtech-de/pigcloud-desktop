window.PigcloudSettingsSync = (() => {
    "use strict";

    const EVT = window.PigcloudConstants.EVT;
    const SILENT_ACTIONS = new Set(["check-updates", "install-update", "updates", "cloud", "open-folder"]);
    const instances = new WeakMap();
    const tr = (key, replacements) => window.t(key, replacements);
    function displayPath(value) {
        if (window.PigcloudArchive?.stripUnsafeDisplayChars) return window.PigcloudArchive.stripUnsafeDisplayChars(value);
        return Array.from(String(value || "")).filter(character => {
            const code = character.codePointAt(0);
            return code >= 0x20 && !(code >= 0x7f && code <= 0x9f)
                && !(code >= 0x202a && code <= 0x202e) && !(code >= 0x2066 && code <= 0x2069);
        }).join("");
    }
    const element = (tag, className, text) => {
        const result = document.createElement(tag);
        result.className = className;
        if (text !== undefined) result.textContent = text;
        return result;
    };
    const label = key => {
        const result = element("span", "", tr(key));
        result.dataset.translateKey = key;
        return result;
    };
    function button(key, action, icon = "fa-check", primary = false) {
        const result = element("button", "btn " + (primary ? "btn-primary" : "btn-tonal"));
        result.type = "button";
        result.dataset.syncAction = action;
        const glyph = element("i", "fa-solid " + icon);
        glyph.setAttribute("aria-hidden", "true");
        result.append(glyph, label(key));
        return result;
    }
    function section(key, icon = "fa-list") {
        const result = element("section", "account-form stack-md");
        const heading = element("h4", "text-heading account-section-heading hstack");
        heading.id = "sync-heading-" + key;
        result.setAttribute("aria-labelledby", heading.id);
        const glyph = element("i", "fa-solid " + icon + " section-heading-icon");
        glyph.setAttribute("aria-hidden", "true");
        heading.append(glyph, label(key));
        result.append(heading);
        return result;
    }
    function field(key, id, type = "text", icon = "fa-sliders") {
        const wrapper = element("div", "form-field vstack");
        const title = element("label", "form-label", tr(key));
        title.dataset.translateKey = key;
        title.htmlFor = id;
        const input = element("input", "form-input");
        input.id = id;
        input.name = id;
        input.type = type;
        if (type === "checkbox") {
            wrapper.className = "settings-option hstack";
            input.className = "switch-input";
            input.setAttribute("aria-label", tr(key));
            input.dataset.translateAriaLabel = key;
            const toggle = element("label", "switch");
            const track = element("span", "switch-track");
            track.setAttribute("aria-hidden", "true");
            toggle.append(input, track);
            const glyph = element("i", "fa-solid " + icon + " settings-option-icon");
            glyph.setAttribute("aria-hidden", "true");
            const info = element("div", "settings-option-info vstack");
            info.append(title);
            wrapper.append(glyph, info, toggle);
        } else wrapper.append(title, input);
        return {wrapper, input};
    }
    function list() {
        const result = element("div", "account-security-list vstack");
        result.setAttribute("role", "list");
        return result;
    }
    function row(text) {
        const result = element("div", "account-security-item stack-sm");
        result.setAttribute("role", "listitem");
        if (text) result.append(element("div", "account-security-title", text));
        return result;
    }

    const CAMERA_ROLL_METHODS = ["status", "enrolBegin", "enrolAwait", "enrolCancel", "revoke", "setUploadEnabled"];
    const CAMERA_ROLL_UNREACHABLE_REASONS = new Set(["unreachable", "server_error", "rate_limited", "malformed"]);
    const CAMERA_ROLL_CONSENT = ["syncCameraRollConsentScope", "syncCameraRollConsentDuration", "syncCameraRollConsentStored", "syncCameraRollConsentLock", "syncCameraRollConsentOneWay"];
    const CAMERA_ROLL_SHED_REASONS = new Set(["shed"]);
    const CAMERA_ROLL_PAUSE_KEYS = {daily_limit: "syncCameraRollDailyLimit", needs_foreground: "syncCameraRollNeedsForeground"};
    function clockTime(ms) {
        const lang = window.currentLanguage || document.documentElement.lang || "de";
        return new Date(ms).toLocaleTimeString(lang === "de" ? "de-DE" : "en-US", {hour: "2-digit", minute: "2-digit"});
    }
    function cameraRollRateLimited(snapshot, now) {
        const until = Number(snapshot?.rateLimitedUntil) || 0;
        if (until <= now) return {key: "syncCameraRollHourlyLimitSoon", tone: "status-checking"};
        return {key: "syncCameraRollHourlyLimit", tone: "status-checking", replacements: {time: clockTime(until)}};
    }
    function cameraRollEstimate(snapshot, limits) {
        const pending = Number(snapshot?.counts?.pending) || 0;
        if (pending <= 0) return null;
        const rate = Number(snapshot?.measuredBytesPerSecond) || 0;
        const bytes = Number(snapshot?.pendingBytes) || 0;
        if (rate <= 0 || bytes <= 0) return {key: "syncCameraRollEtaMeasuring"};
        const perHour = Number(snapshot?.uploadsPerHour) || 0;
        let seconds = Math.max(bytes / rate, perHour > 0 ? pending / perHour * 3600 : 0);
        const daily = Number(limits?.dailyUploadLimit) || 0;
        if (daily > 0) {
            const remaining = Number.isFinite(Number(limits?.dailyUploadRemaining)) && limits?.dailyUploadRemaining !== null ? Math.max(0, Number(limits.dailyUploadRemaining)) : daily;
            if (bytes > remaining) seconds = Math.max(seconds, (1 + Math.ceil((bytes - remaining) / daily)) * 86400);
        }
        if (seconds < 7200) return {key: "syncCameraRollEtaMinutes", replacements: {count: Math.max(1, Math.ceil(seconds / 60))}};
        if (seconds < 172800) return {key: "syncCameraRollEtaHours", replacements: {count: Math.ceil(seconds / 3600)}};
        return {key: "syncCameraRollEtaDays", replacements: {count: Math.ceil(seconds / 86400)}};
    }
    function uploadAllowance() {
        let state;
        try { state = JSON.parse(document.getElementById("settings-page")?.dataset.storageState || "null"); } catch { return null; }
        const raw = state?.limits;
        if (!raw) return null;
        return window.PigcloudSharedUtil?.sanitizeQuotaLimits ? window.PigcloudSharedUtil.sanitizeQuotaLimits(raw) : raw;
    }
    function cameraRollActivity(snapshot) {
        const counts = snapshot?.counts || {};
        const pending = Number(counts.pending) || 0;
        if (snapshot?.access === "none") return {key: "syncCameraRollNoAccess", tone: "status-warning"};
        if (snapshot?.quotaReached) return {key: "syncCameraRollQuota", tone: "status-warning"};
        if (pending > 0 && snapshot?.network && snapshot.network !== "unmetered") return {key: "syncCameraRollWaitingWifi", tone: "status-idle"};
        if (pending > 0 && snapshot?.requiresCharging && snapshot?.charging === false) return {key: "syncCameraRollWaitingCharge", tone: "status-idle"};
        if (snapshot?.queueState === "scanning") return {key: "syncCameraRollScanning", tone: "status-checking"};
        if (snapshot?.queueState === "uploading") return {key: "syncCameraRollUploading", tone: "status-checking"};
        if (snapshot?.queueState === "paused") {
            const reason = snapshot.queueReason || "";
            if (reason === "rate_limited") return cameraRollRateLimited(snapshot, Date.now());
            const key = CAMERA_ROLL_PAUSE_KEYS[reason] || (CAMERA_ROLL_SHED_REASONS.has(reason) ? "syncCameraRollSlowedDown" : "syncCameraRollRetrying");
            return {key, tone: "status-checking"};
        }
        if (pending > 0) return {key: "syncCameraRollQueued", tone: "status-idle"};
        return {key: "syncCameraRollUpToDate", tone: "status-valid"};
    }
    async function mount({panel, tab}) {
        if (instances.has(panel)) return instances.get(panel);
        const host = window.PigcloudSyncEngine || window.Capacitor?.Plugins?.SyncEngine;
        const cameraRoll = window.Capacitor?.Plugins?.CameraRoll;
        const engine = host || {};
        const source = typeof host?.capabilities === "function" ? host : (typeof cameraRoll?.capabilities === "function" ? cameraRoll : null);
        tab.hidden = true;
        if (!source) return null;
        tab.dataset.pending = "true";
        let capabilities;
        try { capabilities = await source.capabilities(); } catch { return null; }
        finally { delete tab.dataset.pending; }
        const hasPairs = !!capabilities?.pairs && ["getSettings", "saveSettings", "status"].every(name => typeof engine[name] === "function");
        const hasCameraRoll = !!capabilities?.cameraRoll && CAMERA_ROLL_METHODS.every(name => typeof cameraRoll?.[name] === "function");
        if (!hasPairs && !hasCameraRoll) return null;
        tab.hidden = false;
        const overlay = panel.closest("#settings-page");
        const webAccount = panel.hasAttribute("data-sync-account-owner");
        let expectedOwner = panel.dataset.syncAccountOwner || "";
        let ownerRefreshing = false;
        let ownerRefreshFailed = false;
        let ownerRequest = 0;
        let identityBlocked = webAccount;
        let accountMismatch = false;
        let settings = null;
        let snapshot = null;
        let updateInfo = null;
        let selection = "";
        let epoch = 0;
        let request = 0;
        let active = false;
        let disposed = false;
        let timer = null;
        let unsubscribe = null;
        let editor = null;
        let editing = false;
        let operation = false;
        let globalStopping = false;
        let connecting = false;
        let cancelRequested = false;
        let pairSelect = null;
        let pairRenderKey = "";
        let selectorKey = "";
        const feedRenderKeys = {};
        const busyPaths = new Set();
        const resolvedPaths = new Set();
        const menus = [];
        const feeds = {activity: null, conflicts: null, files: null};
        const statusSection = section("syncStatusTitle", "fa-sync-alt");
        const status = element("p", "field-status status-idle", tr("syncLoading"));
        status.id = "sync-status";
        status.setAttribute("aria-live", "polite");
        const notice = element("p", "field-status status-warning");
        notice.id = "sync-notice";
        notice.setAttribute("aria-live", "polite");
        const feedback = element("p", "field-status status-idle");
        feedback.id = "sync-feedback";
        feedback.setAttribute("aria-live", "polite");
        const refreshIssue = element("p", "field-status status-warning");
        refreshIssue.id = "sync-refresh-issue";
        refreshIssue.setAttribute("aria-live", "polite");
        const controls = element("div", "account-security-actions");
        controls.append(button("syncStartAll", "start", "fa-play", true), button("syncStopAll", "stop", "fa-stop"), button("syncRefresh", "refresh", "fa-rotate"));
        if (typeof engine.unlock === "function") controls.append(button("syncUnlock", "unlock", "fa-lock-open", true));
        if (typeof engine.loginCli === "function") controls.append(button("syncConnect", "connect", "fa-link", true));
        if (typeof engine.cancelLoginCli === "function") {
            const cancel = button("syncCancel", "cancel-connect", "fa-xmark");
            cancel.hidden = true;
            controls.append(cancel);
        }
        const stopHelp = element("p", "text-small text-muted");
        stopHelp.append(label("syncStopAllDescription"));
        statusSection.append(status, notice, controls, stopHelp, feedback, refreshIssue);
        const pairsSection = section("syncPairsTitle", "fa-folder");
        const pairsList = list();
        pairsList.id = "sync-pairs";
        pairsSection.append(pairsList, button("syncAdd", "add", "fa-plus"));
        const editorSection = section("syncPairEditorTitle", "fa-folder-open");
        editorSection.hidden = true;
        const remote = field("syncRemotePath", "sync-remote-path");
        const local = field("syncLocalPath", "sync-local-path");
        remote.input.required = true;
        local.input.required = true;
        local.input.readOnly = capabilities.folderPicker && typeof engine.pickFolder === "function";
        const editorControls = element("div", "account-form-actions");
        if (capabilities.folderPicker && typeof engine.pickFolder === "function") local.wrapper.append(button("syncBrowse", "browse", "fa-folder-open"));
        editorControls.append(button("syncCancel", "cancel-pair", "fa-xmark"), button("syncSave", "save-pair", "fa-check", true));
        editorSection.append(remote.wrapper, local.wrapper, editorControls);
        const optionsSection = section("syncOptionsTitle", "fa-sliders");
        const poll = field("syncPollInterval", "sync-poll-interval", "number");
        poll.input.min = "5";
        poll.input.max = "3600";
        poll.input.step = "1";
        const startup = field("syncStartup", "sync-startup", "checkbox", "fa-power-off");
        const tray = field("syncMinimize", "sync-minimize", "checkbox", "fa-desktop");
        const preview = field("syncUpdatePreview", "sync-update-preview", "checkbox", "fa-flask");
        const cli = element("p", "field-status status-idle");
        cli.id = "sync-cli";
        cli.setAttribute("aria-live", "polite");
        optionsSection.append(poll.wrapper);
        if (capabilities.autostart) optionsSection.append(startup.wrapper);
        if (capabilities.tray) optionsSection.append(tray.wrapper);
        if (capabilities.updates) optionsSection.append(preview.wrapper);
        const optionControls = element("div", "account-form-actions");
        optionControls.append(button("syncSave", "save-options", "fa-check", true));
        optionsSection.append(optionControls);
        const engineSection = section("syncEngineTitle", "fa-gear");
        const engineControls = element("div", "account-security-actions");
        if (typeof engine.pickCli === "function") engineControls.append(button("syncChooseCli", "pick-cli", "fa-folder-open"));
        if (typeof engine.resetCli === "function") engineControls.append(button("syncDetectCli", "reset-cli", "fa-rotate"));
        const updateState = element("p", "field-status status-idle");
        updateState.id = "sync-update-state";
        updateState.setAttribute("aria-live", "polite");
        updateState.hidden = true;
        if (typeof engine.checkUpdates === "function") engineControls.append(button("syncCheckUpdates", "check-updates", "fa-rotate"));
        if (typeof engine.installUpdate === "function") engineControls.append(button("syncRestartUpdate", "install-update", "fa-power-off", true));
        if (typeof engine.openUpdates === "function") engineControls.append(button("syncUpdates", "updates", "fa-download"));
        engineSection.append(cli, updateState, engineControls);
        const detailsSection = section("syncDetailsTitle");
        const selectorHost = element("div", "form-field vstack");
        const selectorLabel = element("label", "form-label", tr("syncSelectPair"));
        selectorLabel.dataset.translateKey = "syncSelectPair";
        selectorLabel.id = "sync-select-label";
        selectorHost.append(selectorLabel);
        detailsSection.append(selectorHost);
        const feedLists = {};
        const feedGroups = {};
        const feedSelect = window.PigcloudCustomSelect.create([
            {value: "conflicts", label: tr("syncConflictsTitle"), translateKey: "syncConflictsTitle"},
            {value: "activity", label: tr("syncActivityTitle"), translateKey: "syncActivityTitle"},
            {value: "files", label: tr("syncFilesTitle"), translateKey: "syncFilesTitle"},
        ], {initialValue: "conflicts", className: "form-input"});
        const feedLabel = element("label", "form-label", tr("syncDetailsView"));
        feedLabel.id = "sync-feed-label";
        feedLabel.dataset.translateKey = "syncDetailsView";
        feedSelect.el.querySelector("[role='combobox']")?.setAttribute("aria-labelledby", feedLabel.id);
        const feedSelector = element("div", "form-field vstack");
        feedSelector.append(feedLabel, feedSelect.el);
        detailsSection.append(feedSelector);
        feedSelect.addEventListener("change", () => {
            for (const [kind, group] of Object.entries(feedGroups)) group.hidden = kind !== feedSelect.value;
        });
        for (const kind of ["conflicts", "activity", "files"]) {
            const group = section({conflicts: "syncConflictsTitle", activity: "syncActivityTitle", files: "syncFilesTitle"}[kind]);
            const body = list();
            body.id = "sync-" + kind;
            group.append(body);
            group.hidden = kind !== feedSelect.value;
            detailsSection.append(group);
            feedLists[kind] = body;
            feedGroups[kind] = group;
        }
        const cameraRollSection = section("syncCameraRollTitle", "fa-images");
        const cameraRollConsent = element("div", "account-security-item stack-sm");
        for (const key of CAMERA_ROLL_CONSENT) {
            const line = element("p", "text-small text-muted");
            line.append(label(key));
            cameraRollConsent.append(line);
        }
        const cameraRollToggle = field("syncCameraRollEnable", "sync-camera-roll", "checkbox", "fa-images");
        const cameraRollStatus = element("p", "field-status status-idle", tr("syncCameraRollOff"));
        cameraRollStatus.id = "sync-camera-roll-status";
        cameraRollStatus.setAttribute("aria-live", "polite");
        const cameraRollStep = element("p", "field-status status-checking");
        cameraRollStep.id = "sync-camera-roll-step";
        cameraRollStep.setAttribute("aria-live", "polite");
        const cameraRollIssue = element("p", "field-status status-error");
        cameraRollIssue.id = "sync-camera-roll-issue";
        cameraRollIssue.setAttribute("aria-live", "polite");
        const cameraRollQueue = element("p", "field-status status-idle");
        cameraRollQueue.id = "sync-camera-roll-queue";
        cameraRollQueue.setAttribute("aria-live", "polite");
        const cameraRollPartial = element("p", "field-status status-warning");
        cameraRollPartial.id = "sync-camera-roll-partial";
        const cameraRollCounts = element("p", "text-small text-muted");
        cameraRollCounts.id = "sync-camera-roll-counts";
        const cameraRollEta = element("p", "text-small text-muted");
        cameraRollEta.id = "sync-camera-roll-eta";
        cameraRollEta.hidden = true;
        let allowance = uploadAllowance();
        const cameraRollCharging = field("syncCameraRollCharging", "sync-camera-roll-charging", "checkbox", "fa-bolt");
        const hasQueue = typeof cameraRoll?.backUpNow === "function";
        const cameraRollActions = element("div", "account-security-actions");
        cameraRollActions.append(
            ...(hasQueue ? [button("syncCameraRollBackUpNow", "back-up-camera-roll", "fa-cloud-arrow-up", true)] : []),
            ...(typeof cameraRoll?.requestMediaAccess === "function" ? [button("syncCameraRollAllowAccess", "camera-roll-access", "fa-images")] : []),
            button("syncCameraRollCancel", "cancel-camera-roll", "fa-xmark"),
            button("syncCameraRollRevoke", "revoke-camera-roll", "fa-trash-can"),
        );
        cameraRollSection.append(
            cameraRollConsent,
            cameraRollToggle.wrapper,
            ...(typeof cameraRoll?.setRequiresCharging === "function" ? [cameraRollCharging.wrapper] : []),
            cameraRollStatus,
            cameraRollQueue,
            cameraRollPartial,
            cameraRollCounts,
            cameraRollEta,
            cameraRollStep,
            cameraRollIssue,
            cameraRollActions,
        );

        let cameraRollSnapshot = null;
        let cameraRollBusy = false;
        let cameraRollCancelled = false;
        let cameraRollStepKey = "";
        let cameraRollIssueKey = "";

        panel.replaceChildren(
            ...(hasPairs ? [statusSection, pairsSection, editorSection, detailsSection, optionsSection, engineSection] : []),
            ...(hasCameraRoll ? [cameraRollSection] : []),
        );

        function message(key, error = false) {
            feedback.textContent = tr(key);
            feedback.className = "field-status " + (error ? "status-error" : "status-valid");
        }
        function current(captured) {
            return !disposed && active && captured.epoch === epoch && captured.revision === settings?.revision;
        }
        function capture() { return {epoch, revision: settings?.revision}; }
        function pathKey(pairId, path) { return JSON.stringify([pairId, path]); }
        function stateLabel(value) {
            const key = {running: "syncRunning", stopped: "syncStopped", starting: "syncStarting", stopping: "syncStopping", locked: "syncLocked", error: "syncError", idle: "syncIdle", offline: "syncOffline", unavailable: "syncUnavailable", noCli: "syncMissingCli", notConfigured: "syncLoginRequired", unsupportedEndpoint: "syncUnsupportedEndpoint", failed: "syncError", stale: "syncStale", mismatch: "syncMismatch"}[value];
            return key ? tr(key) : String(value || tr("syncUnavailable"));
        }
        function updateLabel(value) {
            if (!value || typeof value.state !== "string") return "";
            if (value.waiting) return tr("syncUpdateWaiting");
            if (value.state === "available") return tr(value.installable ? "syncUpdateAvailable" : "syncUpdateManual", {version: value.version});
            if (value.state === "idle") return tr(value.code === "updateUnsupported" ? "syncUpdateUnavailable" : "syncUpdateIdle");
            if (value.state === "error") {
                return tr({updateSignature: "syncUpdateSignature", updateStopFailed: "syncUpdateStopFailed"}[value.code] || "syncUpdateFailed");
            }
            const key = {checking: "syncUpdateChecking", downloading: "syncUpdateDownloading", ready: "syncUpdateReady", installing: "syncUpdateInstalling"}[value.state];
            return key ? tr(key, {version: value.version, percent: value.percent}) : "";
        }
        function nativeMessage(value) {
            if (!value || typeof value.code !== "string" || !value.code) return "";
            const key = "syncNative" + value.code.charAt(0).toUpperCase() + value.code.slice(1);
            const translated = tr(key);
            return translated && translated !== key ? translated : "";
        }
        function detailText(value) {
            if (typeof value === "string") return value;
            if (Array.isArray(value)) return value.map(detailText).filter(Boolean).join("; ");
            return nativeMessage(value) || value?.message || "";
        }
        function actionFailure(error) {
            const translated = nativeMessage(error);
            if (translated) {
                feedback.textContent = translated;
                feedback.className = "field-status status-error";
            } else message("syncActionFailed", true);
        }
        function checkAccount() {
            const owner = settings?.accountOwner || "";
            const liveOwner = snapshot?.accountOwner || "";
            accountMismatch = webAccount && !ownerRefreshing && !ownerRefreshFailed && ((owner && owner !== expectedOwner) || (liveOwner && liveOwner !== expectedOwner));
            const blocked = webAccount && (ownerRefreshing || ownerRefreshFailed || !owner || owner !== expectedOwner || !snapshot || liveOwner !== expectedOwner);
            if (blocked && !identityBlocked) epoch++;
            identityBlocked = blocked;
            if (!blocked) return;
            selection = "";
            editor = null;
            editorSection.hidden = true;
            remote.input.value = "";
            local.input.value = "";
            for (const menu of menus.splice(0)) menu.destroy();
            if (pairSelect) { pairSelect.destroy(); pairSelect.el.remove(); pairSelect = null; }
            pairsList.replaceChildren();
            pairRenderKey = "";
            selectorKey = "";
            for (const kind of Object.keys(feeds)) {
                feeds[kind] = null;
                feedRenderKeys[kind] = "";
                feedLists[kind].replaceChildren();
            }
        }
        function permittedWhileBlocked(action, pairId) {
            return ["refresh", "connect", "cancel-connect", "login", "cloud", "updates", "check-updates", "install-update", "pick-cli", "reset-cli"].includes(action) || (action === "stop" && !pairId);
        }
        function activityTime(timestamp) {
            if (!Number.isFinite(timestamp)) return "";
            const date = new Date(timestamp * 1000);
            return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat(document.documentElement.lang || undefined, {dateStyle: "short", timeStyle: "short"}).format(date) : "";
        }
        function updateDisabled() {
            for (const control of panel.querySelectorAll("button[data-sync-action]")) {
                if (cameraRollSection.contains(control)) continue;
                const action = control.dataset.syncAction;
                control.disabled = (operation || globalStopping) && !["refresh", "cancel-pair", "cancel-connect", "cloud"].includes(action);
                if (action === "stop" && !control.dataset.pairId) control.disabled = globalStopping;
                if (action === "cancel-connect") control.hidden = !connecting;
                if (control.dataset.path) control.disabled ||= busyPaths.has(pathKey(control.dataset.pairId, control.dataset.path));
                if (editorSection.contains(control)) control.disabled ||= !editor || editor.epoch !== epoch;
                if (["start", "unlock"].includes(action)) control.disabled ||= settings?.cliAvailable === false;
                if (action === "install-update") control.disabled ||= updateInfo?.state === "installing";
                if (identityBlocked) control.disabled ||= !permittedWhileBlocked(action, control.dataset.pairId);
            }
            for (const entry of feedLists.conflicts.children) {
                const control = entry.querySelector("[data-path]");
                if (control) entry.setAttribute("aria-busy", String(busyPaths.has(pathKey(control.dataset.pairId, control.dataset.path))));
            }
        }
        function focusedAction(container) {
            return container.contains(document.activeElement) ? {...document.activeElement.dataset} : null;
        }
        function restoreAction(container, focused) {
            if (!focused?.syncAction) return;
            const target = Array.from(container.querySelectorAll("[data-sync-action]")).find(control => Object.entries(focused).every(([key, value]) => control.dataset[key] === value));
            if (target && !target.disabled) target.focus();
        }
        function renderFeeds() {
            for (const kind of Object.keys(feedLists)) {
                const body = feedLists[kind];
                const entries = feeds[kind];
                const renderKey = JSON.stringify([selection, entries instanceof Error ? "unavailable" : entries, kind === "conflicts" ? [...resolvedPaths] : null, tr("syncActivityEmpty")]);
                if (feedRenderKeys[kind] === renderKey) continue;
                feedRenderKeys[kind] = renderKey;
                const focused = focusedAction(body);
                body.replaceChildren();
                body.removeAttribute("role");
                const empty = key => element("p", "text-small text-muted", tr(key));
                if (!selection) { body.append(empty("syncSelectPair")); continue; }
                if (entries === null) { body.append(empty("syncLoading")); continue; }
                if (entries instanceof Error) { body.append(empty("syncFeedUnavailable")); continue; }
                const visible = kind === "conflicts" ? entries.filter(item => !resolvedPaths.has(pathKey(selection, item.path))) : entries;
                if (!visible.length) {
                    body.append(empty({activity: "syncActivityEmpty", conflicts: "syncConflictsEmpty", files: "syncFilesEmpty"}[kind]));
                    continue;
                }
                body.setAttribute("role", "list");
                for (const item of visible) {
                    const entry = row(displayPath(item.path || item.name || ""));
                    if (kind === "conflicts") {
                        const actions = element("div", "account-security-actions");
                        for (const choice of ["local", "remote", "both"]) {
                            const control = button({local: "syncKeepLocal", remote: "syncKeepRemote", both: "syncKeepBoth"}[choice], "resolve", "fa-check");
                            control.dataset.choice = choice;
                            control.dataset.path = item.path;
                            control.dataset.pairId = selection;
                            actions.append(control);
                        }
                        entry.setAttribute("aria-busy", String(busyPaths.has(pathKey(selection, item.path))));
                        entry.append(actions);
                    } else {
                        const directionKey = {upload: "syncUploaded", download: "syncDownloaded", delete: "syncDeleted"}[item.direction];
                        entry.append(element("div", "account-security-meta", [directionKey ? tr(directionKey) : item.action || item.state || item.status, activityTime(item.timestamp), detailText(item.error || item.message || item.reason)].filter(Boolean).join(" | ")));
                        if (kind === "files" && (item.error || item.status === "failed" || item.state === "failed")) {
                            const retry = button("syncRetry", "retry", "fa-rotate");
                            retry.dataset.pairId = selection;
                            retry.dataset.path = item.path;
                            entry.append(retry);
                        }
                    }
                    body.append(entry);
                }
                restoreAction(body, focused);
            }
            updateDisabled();
        }
        function renderPairs() {
            const pairs = settings?.pairs || [];
            const renderKey = JSON.stringify([pairs, snapshot?.pairs?.map(pair => ({id: pair.id, state: pair.state, error: pair.error, pending: pair.status?.pendingCount, failed: pair.status?.failedCount, downloads: pair.status?.failedDownloadCount, deferred: pair.status?.deferredCount, due: pair.status?.nextDueSeconds, online: pair.status?.online})), tr("syncStart")]);
            if (pairRenderKey === renderKey) {
                if (pairSelect) pairSelect.value = selection;
                updateDisabled();
                return;
            }
            pairRenderKey = renderKey;
            const focused = focusedAction(pairsList);
            for (const menu of menus.splice(0)) menu.destroy();
            pairsList.replaceChildren();
            if (pairs.length) pairsList.setAttribute("role", "list");
            else pairsList.removeAttribute("role");
            if (!pairs.length) pairsList.append(element("p", "text-small text-muted", tr("syncNoPairs")));
            for (const pair of pairs) {
                const entry = row(displayPath(pair.remotePath));
                entry.append(element("div", "account-security-meta", displayPath(pair.mountPoint)));
                const pairState = snapshot?.pairs?.find(item => item.id === pair.id);
                entry.append(element("p", "field-status status-idle", stateLabel(pairState?.state)));
                if (pairState?.error) entry.append(element("p", "field-status status-error", detailText(pairState.error)));
                if (pairState?.status) {
                    entry.append(element("div", "account-security-meta", tr("syncCounts", {
                        pending: pairState.status.pendingCount || 0,
                        failed: (pairState.status.failedCount || 0) + (pairState.status.failedDownloadCount || 0),
                        deferred: pairState.status.deferredCount || 0,
                    })));
                    if (pairState.status.online === false) entry.append(element("p", "field-status status-warning", tr("syncOffline")));
                    if (pairState.status.nextDueSeconds > 0) entry.append(element("div", "account-security-meta", tr("syncNextRetry", {seconds: pairState.status.nextDueSeconds})));
                }
                const actions = element("div", "account-security-actions");
                for (const [key, action, icon] of [["syncStart", "start", "fa-play"], ["syncStop", "stop", "fa-stop"], ["syncDetails", "details", "fa-list"]]) {
                    const control = button(key, action, icon);
                    control.dataset.pairId = pair.id;
                    if (action === "start") control.hidden = ["running", "starting", "stopping"].includes(pairState?.state);
                    if (action === "stop") control.hidden = !["running", "starting", "stopping"].includes(pairState?.state);
                    actions.append(control);
                }
                const opener = button("syncMore", "menu", "fa-ellipsis");
                const surface = element("div", "nav-preferences vstack");
                surface.hidden = true;
                for (const [key, action, icon] of [["syncEdit", "edit", "fa-pen"], ["syncOpenFolder", "open-folder", "fa-folder-open"], ["syncRetry", "retry", "fa-rotate"], ["syncFlush", "flush", "fa-cloud-arrow-up"], ["syncRemove", "remove", "fa-trash-can"]]) {
                    if (action === "open-folder" && typeof engine.openFolder !== "function") continue;
                    if (action === "flush" && !capabilities.flush) continue;
                    const control = button(key, action, icon);
                    control.className = "context-menu-item";
                    control.dataset.pairId = pair.id;
                    surface.append(control);
                }
                actions.append(opener, surface);
                entry.append(actions);
                pairsList.append(entry);
                menus.push(window.PigcloudMenu.attach(opener, surface, {placement: "bottom-start", items: () => Array.from(surface.querySelectorAll("button"))}));
            }
            const choices = pairs.map(pair => ({value: pair.id, label: displayPath(pair.remotePath) + " (" + displayPath(pair.mountPoint) + ")"}));
            if (!choices.length) choices.push({value: "", label: tr("syncSelectPair")});
            if (!pairSelect) {
                pairSelect = window.PigcloudCustomSelect.create(choices, {initialValue: selection});
                pairSelect.el.querySelector("[role='combobox']")?.setAttribute("aria-labelledby", selectorLabel.id);
                pairSelect.addEventListener("change", () => select(pairSelect.value));
                selectorHost.append(pairSelect.el);
            } else if (selectorKey !== JSON.stringify(choices)) pairSelect.setOptions(choices);
            selectorKey = JSON.stringify(choices);
            pairSelect.value = selection;
            pairSelect.disabled = !pairs.length;
            updateDisabled();
            restoreAction(pairsList, focused);
        }
        function renderCameraRoll() {
            if (!hasCameraRoll) return;
            const enrolled = !!cameraRollSnapshot?.enrolled;
            const on = enrolled && !!cameraRollSnapshot?.uploadEnabled;
            const reenrolNeeded = !enrolled && cameraRollSnapshot?.state === "reenrolNeeded";
            const paused = on && cameraRollSnapshot?.state === "paused";
            const unreachable = paused && CAMERA_ROLL_UNREACHABLE_REASONS.has(cameraRollSnapshot?.pauseReason || "unreachable");
            cameraRollToggle.input.checked = on;
            cameraRollToggle.input.disabled = cameraRollBusy;
            cameraRollStatus.textContent = cameraRollSnapshot === null ? tr("syncLoading")
                : reenrolNeeded ? tr("syncCameraRollReenrol")
                : unreachable ? tr("syncCameraRollUnreachable")
                : paused ? tr("syncCameraRollConfirming")
                : on ? tr("syncCameraRollEnrolled") : enrolled ? tr("syncCameraRollPaused") : tr("syncCameraRollOff");
            cameraRollStatus.className = "field-status " + (reenrolNeeded ? "status-error" : paused ? "status-checking" : "status-idle");
            cameraRollStep.textContent = cameraRollStepKey ? tr(cameraRollStepKey) : "";
            cameraRollStep.hidden = !cameraRollStepKey;
            cameraRollIssue.textContent = cameraRollIssueKey ? tr(cameraRollIssueKey) : "";
            cameraRollIssue.hidden = !cameraRollIssueKey;
            cameraRollSection.querySelector('[data-sync-action="cancel-camera-roll"]').hidden = !cameraRollBusy;
            const revoke = cameraRollSection.querySelector('[data-sync-action="revoke-camera-roll"]');
            revoke.hidden = !enrolled;
            revoke.disabled = cameraRollBusy;

            const activity = on && hasQueue ? cameraRollActivity(cameraRollSnapshot) : null;
            cameraRollQueue.hidden = !activity || paused;
            cameraRollQueue.textContent = activity ? tr(activity.key, activity.replacements) : "";
            cameraRollQueue.className = "field-status " + (activity?.tone || "status-idle");
            const blocked = !activity || paused || ["syncCameraRollNoAccess", "syncCameraRollQuota"].includes(activity.key);
            const estimate = !blocked && cameraRollSnapshot && "pendingBytes" in cameraRollSnapshot ? cameraRollEstimate(cameraRollSnapshot, allowance) : null;
            cameraRollEta.hidden = !estimate;
            cameraRollEta.textContent = estimate ? tr(estimate.key, estimate.replacements) : "";
            cameraRollPartial.hidden = !(on && cameraRollSnapshot?.access === "partial");
            cameraRollPartial.textContent = cameraRollPartial.hidden ? "" : tr("syncCameraRollPartial");
            const counts = cameraRollSnapshot?.counts;
            cameraRollCounts.hidden = !(on && hasQueue && counts);
            cameraRollCounts.textContent = cameraRollCounts.hidden ? "" : tr("syncCameraRollCounts", {
                pending: Number(counts.pending) || 0,
                uploaded: Number(counts.uploaded) || 0,
                failed: Number(counts.failed) || 0,
            });
            cameraRollCharging.wrapper.hidden = !enrolled;
            cameraRollCharging.input.checked = !!cameraRollSnapshot?.requiresCharging;
            cameraRollCharging.input.disabled = cameraRollBusy;
            const backUp = cameraRollSection.querySelector('[data-sync-action="back-up-camera-roll"]');
            if (backUp) {
                backUp.hidden = !on;
                backUp.disabled = cameraRollBusy;
            }
            const access = cameraRollSection.querySelector('[data-sync-action="camera-roll-access"]');
            if (access) {
                access.hidden = !(on && ["none", "partial"].includes(cameraRollSnapshot?.access));
                access.disabled = cameraRollBusy;
            }
        }
        async function refreshCameraRoll() {
            if (!hasCameraRoll) return;
            try {
                cameraRollSnapshot = await cameraRoll.status();
            } catch {
                cameraRollSnapshot = {enrolled: false, uploadEnabled: false};
                cameraRollIssueKey = "syncCameraRollFailed";
            }
            renderCameraRoll();
        }
        async function enrolCameraRoll() {
            const owner = panel.dataset.syncAccountOwner || "";
            if (webAccount && !owner) return "syncCameraRollAccountUnknown";
            const endpoint = window.location.origin + "/cloud/actions.php";
            const begun = await cameraRoll.enrolBegin({endpoint, deviceLabel: tr("syncCameraRollDeviceLabel")});
            if (!begun?.userCode || !begun?.commitment) return "syncCameraRollFailed";
            if (cameraRollCancelled) return "syncCameraRollCancelled";
            const pending = await window.PigcloudCsrf.postJsonResult("/cloud/actions.php?action=device-pending", {code: begun.userCode});
            const ephB64 = pending.ok && pending.data?.success === true ? pending.data.pending?.ephemeralPublicKey : "";
            if (!ephB64) return "syncCameraRollFailed";
            if (cameraRollCancelled) return "syncCameraRollCancelled";
            const eph = window.PigcloudSharedUtil.base64ToBytes(ephB64);
            const digest = new Uint8Array(await window.crypto.subtle.digest("SHA-256", eph));
            if (eph.length !== 1216 || window.PigcloudSharedUtil.bytesToBase64Url(digest) !== begun.commitment) return "syncCameraRollMismatch";

            const input = await window.PigcloudAccountPassword.requestPassword({title: tr("syncCameraRollTitle"), message: tr("syncCameraRollUnlockPrompt")});
            if (!input || input.mode !== "password" || !input.password) return "syncCameraRollCancelled";
            let sealedB64;
            try {
                if (cameraRollCancelled) return "syncCameraRollCancelled";
                const sudo = await window.PigcloudSudoGuard.activateWithPassword(input.password);
                if (!sudo?.ok) return "syncCameraRollUnlockFailed";
                if (!await window.PigcloudE2EEUnlock.unlockFull(input.password)) return "syncCameraRollUnlockFailed";
                const payload = window.E2EE.packBackgroundKeyTransfer(window.pigcloudE2EE || {});
                if (!payload) return "syncCameraRollUnlockFailed";
                sealedB64 = window.E2EE.toBase64(window.E2EE.hybridSeal(payload, {x25519: eph.slice(0, 32), kyber: eph.slice(32, 1216)}));
                payload.fill(0);
            } finally {
                input.password = "";
            }
            if (cameraRollCancelled) return "syncCameraRollCancelled";

            const approved = await window.PigcloudCsrf.postJsonResult("/cloud/actions.php?action=device-approve", {code: begun.userCode, sealed_key: sealedB64});
            if (!approved.ok || approved.data?.success !== true) return "syncCameraRollFailed";
            const stored = await cameraRoll.enrolAwait({
                endpoint,
                account: owner,
                timeoutSeconds: begun.expiresIn || 900,
            });
            return stored?.enrolled ? "" : "syncCameraRollFailed";
        }
        async function revokeCameraRoll() {
            const identifier = cameraRollSnapshot?.apiKeyId || "";
            if (identifier) {
                const dropped = await window.PigcloudCsrf.postJsonResult("/cloud/actions.php?action=account-revoke-cli-device", {identifier});
                const alreadyGone = dropped.data?.messageKey === "deviceTokenRevokeNotFound";
                if (!alreadyGone && (!dropped.ok || dropped.data?.success !== true)) return "syncCameraRollRevokeFailed";
            }
            await cameraRoll.revoke({});
            return "";
        }
        async function cameraRollAction(name) {
            if (name === "cancel-camera-roll") {
                cameraRollCancelled = true;
                try { await cameraRoll.enrolCancel(); } catch {  }
                cameraRollBusy = false;
                cameraRollStepKey = "";
                cameraRollIssueKey = "syncCameraRollCancelled";
                renderCameraRoll();
                return;
            }
            if (cameraRollBusy) return;
            if (name === "back-up-camera-roll" || name === "camera-roll-access") {
                cameraRollBusy = true;
                cameraRollIssueKey = "";
                renderCameraRoll();
                try {
                    if (name === "back-up-camera-roll") await cameraRoll.backUpNow();
                    else await cameraRoll.requestMediaAccess();
                } catch {
                    cameraRollIssueKey = "syncCameraRollActionFailed";
                } finally {
                    cameraRollBusy = false;
                }
                await refreshCameraRoll();
                return;
            }
            const confirmed = await window.PigcloudDialogManager.confirm(tr("syncCameraRollRevoke"), tr("syncCameraRollRevokeConfirm"), {danger: true});
            if (!confirmed) return;
            cameraRollBusy = true;
            renderCameraRoll();
            let failure;
            try { failure = await revokeCameraRoll(); }
            catch { failure = "syncCameraRollFailed"; }
            finally { cameraRollBusy = false; }
            cameraRollIssueKey = failure;
            cameraRollStepKey = failure ? "" : "syncCameraRollRevoked";
            await refreshCameraRoll();
        }
        async function toggleCameraRoll() {
            if (cameraRollBusy) { renderCameraRoll(); return; }
            const wanted = cameraRollToggle.input.checked;
            cameraRollIssueKey = "";
            if (!wanted) {
                cameraRollToggle.input.checked = !!cameraRollSnapshot?.uploadEnabled;
                if (cameraRollSnapshot?.enrolled) await cameraRollAction("revoke-camera-roll");
                return;
            }
            if (cameraRollSnapshot?.enrolled) {
                cameraRollBusy = true;
                renderCameraRoll();
                try { await cameraRoll.setUploadEnabled({enabled: true}); }
                catch { cameraRollIssueKey = "syncCameraRollFailed"; }
                finally { cameraRollBusy = false; }
                await refreshCameraRoll();
                return;
            }
            cameraRollBusy = true;
            cameraRollCancelled = false;
            cameraRollStepKey = "syncCameraRollEnrolling";
            renderCameraRoll();
            let failure = "syncCameraRollFailed";
            try { failure = await enrolCameraRoll(); }
            catch { failure = cameraRollCancelled ? "syncCameraRollCancelled" : "syncCameraRollFailed"; }
            finally {
                cameraRollBusy = false;
                cameraRollStepKey = "";
                cameraRollIssueKey = failure;
            }
            await refreshCameraRoll();
        }
        function render() {
            renderCameraRoll();
            if (!hasPairs) return;
            checkAccount();
            status.textContent = ownerRefreshing ? tr("syncLoading") : ownerRefreshFailed ? tr("syncUnavailable") : accountMismatch ? tr("syncAccountMismatch") : settings?.cliAvailable === false ? tr("syncMissingCli") : stateLabel(snapshot?.state);
            notice.textContent = identityBlocked ? "" : detailText(snapshot?.notice);
            notice.hidden = !notice.textContent;
            cli.textContent = identityBlocked ? "" : settings?.cliAvailable ? tr("syncCliDetected", {path: settings.cliPath || "pc"}) : tr("syncMissingCli");
            const connect = controls.querySelector('[data-sync-action="connect"]');
            if (connect) connect.hidden = !accountMismatch && snapshot?.state !== "notConfigured";
            const locked = snapshot?.state === "locked";
            const needsConnection = accountMismatch || snapshot?.state === "notConfigured";
            const running = ["running", "starting", "stopping"].includes(snapshot?.state) || snapshot?.pairs?.some(pair => ["running", "starting", "stopping"].includes(pair.state));
            controls.querySelector('[data-sync-action="start"]').hidden = identityBlocked || needsConnection || locked || !settings?.pairs.length || running;
            const unlock = controls.querySelector('[data-sync-action="unlock"]');
            if (unlock) unlock.hidden = !locked || identityBlocked;
            pairsSection.hidden = identityBlocked;
            detailsSection.hidden = identityBlocked || !selection;
            optionsSection.hidden = identityBlocked;
            engineSection.hidden = !engineControls.children.length;
            updateState.textContent = updateLabel(updateInfo);
            updateState.hidden = !updateState.textContent;
            updateState.className = "field-status " + (updateInfo?.state === "error" ? "status-error"
                : updateInfo?.state === "ready" ? "status-valid" : "status-idle");
            const restart = engineControls.querySelector('[data-sync-action="install-update"]');
            if (restart) restart.hidden = !updateInfo?.downloaded || !updateInfo.installable;
            if (identityBlocked) { updateDisabled(); return; }
            if (!editing && settings) {
                poll.input.value = String(settings.pollInterval);
                startup.input.checked = !!settings.launchOnStartup;
                tray.input.checked = !!settings.minimizeToTray;
                preview.input.checked = !!settings.allowPrerelease;
            }
            renderPairs();
            renderFeeds();
        }
        async function readFeeds(captured, ticket) {
            if (identityBlocked) return;
            const pairId = selection;
            const resolvedBeforeQuery = new Set(resolvedPaths);
            const results = await Promise.allSettled(["activity", "conflicts", "files"].map(kind => engine[kind]({pairId})));
            if (!current(captured) || ticket !== request || pairId !== selection) return;
            ["activity", "conflicts", "files"].forEach((kind, index) => {
                const result = results[index];
                const value = result.status === "fulfilled" ? result.value : null;
                const matches = value?.pairId === pairId && value?.revision === captured.revision;
                const entries = matches ? value[kind] : null;
                feeds[kind] = Array.isArray(entries) ? entries : new Error("Unavailable");
                if (kind === "conflicts" && Array.isArray(entries)) {
                    for (const key of resolvedBeforeQuery) {
                        if (JSON.parse(key)[0] === pairId) resolvedPaths.delete(key);
                    }
                }
            });
            renderFeeds();
        }
        async function refresh() {
            if (!active || disposed) return;
            await refreshCameraRoll();
            if (!hasPairs) return;
            const capturedEpoch = epoch;
            const ticket = ++request;
            const results = await Promise.allSettled([engine.getSettings(), engine.status()]);
            if (!active || disposed || capturedEpoch !== epoch || ticket !== request) return;
            if (results[0].status !== "fulfilled") { refreshIssue.textContent = tr("syncRefreshFailed"); return; }
            const next = results[0].value;
            if (!Array.isArray(next?.pairs)) { refreshIssue.textContent = tr("syncRefreshFailed"); return; }
            if (settings && next.revision !== settings.revision) {
                epoch++;
                if (editor) message("syncNativeStaleSettings", true);
                editor = null;
                editorSection.hidden = true;
                editing = false;
                resolvedPaths.clear();
                for (const kind of Object.keys(feeds)) feeds[kind] = null;
            }
            settings = next;
            const resultSnapshot = results[1].status === "fulfilled" && results[1].value?.revision === settings.revision ? results[1].value : null;
            snapshot = resultSnapshot && snapshot?.revision === resultSnapshot.revision && (snapshot.sequence || 0) > (resultSnapshot.sequence || 0) ? snapshot : resultSnapshot;
            if (resultSnapshot?.updates) updateInfo = resultSnapshot.updates;
            refreshIssue.textContent = snapshot ? "" : tr("syncRefreshFailed");
            if (!settings.pairs.some(pair => pair.id === selection)) {
                const nextSelection = settings.pairs[0]?.id || "";
                if (selection !== nextSelection) {
                    selection = nextSelection;
                    epoch++;
                    for (const kind of Object.keys(feeds)) feeds[kind] = null;
                }
            }
            render();
            if (selection && !identityBlocked) await readFeeds(capture(), ticket);
        }
        function select(pairId) {
            if (identityBlocked) return;
            if (!settings?.pairs.some(pair => pair.id === pairId)) return;
            if (selection === pairId) return;
            selection = pairId;
            epoch++;
            if (editor) {
                editor = null;
                editorSection.hidden = true;
                message("syncDraftChanged", true);
            }
            for (const kind of Object.keys(feeds)) feeds[kind] = null;
            pairSelect.value = selection;
            renderFeeds();
            refresh().catch(() => message("syncRefreshFailed", true));
        }
        function schedule() {
            if (!active || disposed) return;
            timer = setTimeout(() => {
                timer = null;
                refresh().catch(() => message("syncRefreshFailed", true)).finally(schedule);
            }, 3000);
        }
        function onSnapshot(update) {
            if (!active || disposed) return;
            if (update && update.updates && typeof update.updates === "object") updateInfo = update.updates;
            if (update && !Array.isArray(update.pairs) && update.updates) {
                render();
                return;
            }
            if (update && Array.isArray(update.pairs) && (update.sequence || 0) < (snapshot?.sequence || 0)) return;
            if (webAccount && update && Array.isArray(update.pairs) && (update.accountOwner || "") !== expectedOwner) {
                snapshot = update;
                render();
                return;
            }
            if (update && Array.isArray(update.pairs) && update.revision === settings?.revision) {
                if ((update.sequence || 0) < (snapshot?.sequence || 0)) return;
                snapshot = update;
                render();
            } else if (typeof update?.loginState === "string") {
                refresh().catch(() => { refreshIssue.textContent = tr("syncRefreshFailed"); });
            }
        }
        function visibility() {
            const visible = !disposed && !overlay?.hidden && !panel.hidden;
            if (visible === active) return;
            active = visible;
            epoch++;
            if (timer !== null) clearTimeout(timer);
            timer = null;
            if (unsubscribe) unsubscribe();
            unsubscribe = null;
            if (active) {
                if (editor) editor.epoch = epoch;
                if (typeof engine.subscribe === "function") unsubscribe = engine.subscribe(onSnapshot);
                refresh().catch(() => message("syncRefreshFailed", true)).finally(schedule);
            }
        }
        function edit(pair) {
            editor = {pairId: pair?.id || null, epoch};
            remote.input.value = pair?.remotePath || "/";
            local.input.value = pair?.mountPoint || "";
            editorSection.hidden = false;
            updateDisabled();
            remote.input.focus();
        }
        async function save(pairs, captured) {
            const result = await engine.saveSettings({
                revision: captured.revision,
                pairs,
                pollInterval: Number(poll.input.value),
                launchOnStartup: startup.input.checked,
                minimizeToTray: tray.input.checked,
                ...(capabilities.updates ? {allowPrerelease: preview.input.checked} : {}),
            });
            if (result?.success === false || result?.ok === false) throw new Error("Save failed");
            if (!current(captured)) return;
            editing = false;
            editor = null;
            editorSection.hidden = true;
            message("syncSaved");
        }
        async function action(control) {
            const name = control.dataset.syncAction;
            const pairId = control.dataset.pairId;
            if (name === "menu") return;
            if (["cancel-camera-roll", "revoke-camera-roll", "back-up-camera-roll", "camera-roll-access"].includes(name)) {
                await cameraRollAction(name);
                return;
            }
            if (name === "refresh") {
                if (ownerRefreshFailed) await refreshOwner();
                else await refresh();
                return;
            }
            if (name === "cancel-pair") { editor = null; editorSection.hidden = true; return; }
            if (name === "cancel-connect") {
                if (!connecting) return;
                cancelRequested = true;
                try { await engine.cancelLoginCli(); }
                catch (error) { cancelRequested = false; actionFailure(error); }
                return;
            }
            if (!active) return;
            if (name === "stop" && !pairId) {
                if (globalStopping) return;
                globalStopping = true;
                const captured = capture();
                updateDisabled();
                try {
                    const result = await engine.stop({});
                    if (result?.success === false || result?.ok === false) throw new Error("Stop failed");
                    if (current(captured)) message("syncActionDone");
                } catch (error) {
                    if (current(captured)) actionFailure(error);
                } finally {
                    globalStopping = false;
                    updateDisabled();
                }
                if (current(captured)) await refresh();
                return;
            }
            if (operation || globalStopping) return;
            const captured = capture();
            if (identityBlocked && !permittedWhileBlocked(name, pairId)) return;
            const pair = settings?.pairs.find(item => item.id === pairId);
            if (pairId && !pair) return;
            if (name === "details") {
                select(pairId);
                detailsSection.scrollIntoView?.({block: "start"});
                const target = pairSelect?.el.querySelector("[role='combobox']");
                target?.focus();
                return;
            }
            if (name === "add" || name === "edit") { edit(pair); return; }
            for (const menu of menus) menu.close();
            const path = control.dataset.path;
            const key = pathKey(pairId, path);
            if (name === "resolve" && busyPaths.has(key)) return;
            operation = true;
            if (name === "connect") { connecting = true; cancelRequested = false; }
            if (name === "resolve") busyPaths.add(key);
            updateDisabled();
            try {
                if (["remove", "resolve"].includes(name)) {
                    const confirmed = await window.PigcloudDialogManager.confirm(tr(name === "remove" ? "syncRemove" : "syncResolveTitle"), tr(name === "remove" ? "syncRemoveConfirm" : "syncResolveConfirm", {path: displayPath(name === "remove" ? pair.mountPoint : path)}), {danger: name === "remove" || control.dataset.choice !== "both"});
                    if (!confirmed || !current(captured)) return;
                }
                if (name === "browse") {
                    const target = editor;
                    const picked = await engine.pickFolder();
                    if (current(captured) && target && editor === target && picked) local.input.value = typeof picked === "string" ? picked : picked.path || "";
                    return;
                }
                if (name === "save-pair" || name === "save-options" || name === "remove") {
                    if (!poll.input.checkValidity()) { poll.input.reportValidity(); return; }
                    let pairs = settings.pairs.map(item => ({id: item.id, remotePath: item.remotePath, mountPoint: item.mountPoint}));
                    if (name === "save-pair") {
                        if (!editor || editor.epoch !== epoch || !remote.input.reportValidity() || !local.input.reportValidity()) return;
                        const replacement = {remotePath: remote.input.value.trim(), mountPoint: local.input.value};
                        if (editor.pairId) pairs = pairs.map(item => item.id === editor.pairId ? {...replacement, id: item.id} : item);
                        else pairs.push(replacement);
                    }
                    if (name === "remove") pairs = pairs.filter(item => item.id !== pairId);
                    await save(pairs, captured);
                } else if (name === "unlock") {
                    const answer = await window.PigcloudAccountPassword.requestPassword({title: tr("syncUnlock"), message: tr("syncUnlockPrompt")});
                    if (!answer || answer.mode !== "password" || !current(captured)) return;
                    try { await engine.unlock({password: answer.password}); } finally { answer.password = ""; }
                    if (current(captured)) message("syncActionDone");
                } else {
                    const methods = {"pick-cli": "pickCli", "reset-cli": "resetCli", "open-folder": "openFolder", cloud: "openCloud", updates: "openUpdates", "check-updates": "checkUpdates", "install-update": "installUpdate", login: "login", connect: "loginCli"};
                    const method = methods[name] || name;
                    const args = pairId ? {pairId} : {};
                    if (path) args.path = path;
                    if (name === "resolve") args.choice = control.dataset.choice;
                    const result = await engine[method](args);
                    if (result?.success === false || result?.ok === false) throw new Error("Action failed");
                    if (current(captured)) {
                        if (name === "resolve") resolvedPaths.add(key);
                        if (!SILENT_ACTIONS.has(name)) message(name === "resolve" ? "syncResolved" : "syncActionDone");
                    }
                }
            } catch (error) {
                if (current(captured)) {
                    if (name === "connect" && cancelRequested) message("syncConnectCancelled");
                    else actionFailure(error);
                }
                return;
            } finally {
                operation = false;
                if (name === "connect") connecting = false;
                busyPaths.delete(key);
                updateDisabled();
            }
            if (current(captured)) {
                renderFeeds();
                await refresh();
            }
        }
        const onClick = event => {
            const control = event.target.closest("button[data-sync-action]");
            if (control && panel.contains(control) && !control.disabled) action(control).catch(() => message("syncRefreshFailed", true));
        };
        const onInput = () => { editing = true; };
        const onCameraRollToggle = () => toggleCameraRoll().catch(() => {
            cameraRollBusy = false;
            cameraRollIssueKey = "syncCameraRollFailed";
            renderCameraRoll();
        });
        panel.addEventListener("click", onClick);
        optionsSection.addEventListener("input", onInput);
        const onCameraRollCharging = () => {
            const wanted = cameraRollCharging.input.checked;
            cameraRoll.setRequiresCharging({enabled: wanted})
                .catch(() => { cameraRollIssueKey = "syncCameraRollActionFailed"; })
                .then(() => refreshCameraRoll())
                .catch(() => {});
        };
        if (hasCameraRoll) cameraRollToggle.input.addEventListener("change", onCameraRollToggle);
        if (hasCameraRoll) cameraRollCharging.input.addEventListener("change", onCameraRollCharging);
        async function refreshOwner() {
            if (!webAccount || disposed) return;
            const ticket = ++ownerRequest;
            epoch++;
            ownerRefreshing = true;
            ownerRefreshFailed = false;
            render();
            try {
                const result = await window.PigcloudCsrf.postJsonResult('/cloud/actions.php?action=desktop-account', {});
                if (disposed || ticket !== ownerRequest) return;
                const owner = result.data?.owner;
                if (!result.ok || result.data?.success !== true || typeof owner !== "string" || (owner !== "" && !/^[0-9a-f]{16}$/.test(owner))) throw new Error("Invalid account identity");
                expectedOwner = owner;
                panel.dataset.syncAccountOwner = owner;
                ownerRefreshing = false;
                render();
                await refresh();
            } catch {
                if (disposed || ticket !== ownerRequest) return;
                expectedOwner = "";
                panel.dataset.syncAccountOwner = "";
                ownerRefreshing = false;
                ownerRefreshFailed = true;
                refreshIssue.textContent = tr("syncRefreshFailed");
                render();
            }
        }
        const onEncryptionState = () => { refreshOwner().catch(() => { refreshIssue.textContent = tr("syncRefreshFailed"); }); };
        const onSection = () => visibility();
        const onLanguage = () => { if (active) render(); };
        const onStorage = event => {
            if (!hasCameraRoll || !event.detail?.limits) return;
            allowance = window.PigcloudSharedUtil?.sanitizeQuotaLimits ? window.PigcloudSharedUtil.sanitizeQuotaLimits(event.detail.limits) : event.detail.limits;
            renderCameraRoll();
        };
        document.addEventListener(EVT.SETTINGS_SECTION_SHOWN, onSection);
        document.addEventListener(EVT.LANGUAGE_CHANGE, onLanguage);
        document.addEventListener(EVT.STORAGE_UPDATE, onStorage);
        if (webAccount) document.addEventListener(EVT.E2EE_STATE, onEncryptionState);
        const observer = new MutationObserver(visibility);
        observer.observe(overlay || panel, {attributes: true, attributeFilter: ["hidden"]});
        observer.observe(panel, {attributes: true, attributeFilter: ["hidden"]});
        const controller = {
            refresh,
            dispose() {
                disposed = true;
                ownerRequest++;
                visibility();
                observer.disconnect();
                document.removeEventListener(EVT.SETTINGS_SECTION_SHOWN, onSection);
                document.removeEventListener(EVT.LANGUAGE_CHANGE, onLanguage);
                document.removeEventListener(EVT.STORAGE_UPDATE, onStorage);
                if (webAccount) document.removeEventListener(EVT.E2EE_STATE, onEncryptionState);
                panel.removeEventListener("click", onClick);
                optionsSection.removeEventListener("input", onInput);
                cameraRollToggle.input.removeEventListener("change", onCameraRollToggle);
                cameraRollCharging.input.removeEventListener("change", onCameraRollCharging);
                for (const menu of menus) menu.destroy();
                pairSelect?.destroy();
                feedSelect.destroy();
                instances.delete(panel);
            },
        };
        instances.set(panel, controller);
        visibility();
        return controller;
    }

    const panel = document.getElementById("settings-panel-sync");
    const tab = document.getElementById("settings-tab-sync");
    const ready = panel && tab ? mount({panel, tab}).catch(error => { console.warn("Sync panel initialization failed:", error); return null; }) : Promise.resolve(null);
    return {mount, ready};
})();
