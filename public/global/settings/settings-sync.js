window.PigcloudSettingsSync = (() => {
    "use strict";

    const EVT = window.PigcloudConstants.EVT;
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
    function button(key, action, icon = "fa-check") {
        const result = element("button", "btn btn-tonal btn-sm");
        result.type = "button";
        result.dataset.syncAction = action;
        const glyph = element("i", "fa-solid " + icon);
        glyph.setAttribute("aria-hidden", "true");
        result.append(glyph, label(key));
        return result;
    }
    function section(key) {
        const result = element("section", "account-form stack-sm");
        const heading = element("h4", "text-heading account-section-heading hstack");
        heading.append(label(key));
        result.append(heading);
        return result;
    }
    function field(key, id, type = "text") {
        const wrapper = element("div", "form-field vstack");
        const title = element("label", "form-label", tr(key));
        title.dataset.translateKey = key;
        title.htmlFor = id;
        const input = element("input", "form-input");
        input.id = id;
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
            wrapper.append(title, toggle);
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

    async function mount({panel, tab}) {
        if (instances.has(panel)) return instances.get(panel);
        const engine = window.PigcloudSyncEngine || window.Capacitor?.Plugins?.SyncEngine;
        tab.hidden = true;
        if (!engine || typeof engine.capabilities !== "function") return null;
        tab.dataset.pending = "true";
        let capabilities;
        try { capabilities = await engine.capabilities(); } catch { return null; }
        finally { delete tab.dataset.pending; }
        if (!capabilities?.pairs || !["getSettings", "saveSettings", "status"].every(name => typeof engine[name] === "function")) return null;
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
        const statusSection = section("syncStatusTitle");
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
        const controls = element("div", "hstack");
        controls.append(button("syncStartAll", "start", "fa-play"), button("syncStopAll", "stop", "fa-stop"), button("syncRefresh", "refresh", "fa-rotate"));
        if (typeof engine.unlock === "function") controls.append(button("syncUnlock", "unlock", "fa-lock-open"));
        if (typeof engine.loginCli === "function") controls.append(button("syncConnect", "connect", "fa-link"));
        if (typeof engine.cancelLoginCli === "function") {
            const cancel = button("syncCancel", "cancel-connect", "fa-xmark");
            cancel.hidden = true;
            controls.append(cancel);
        }
        if (typeof engine.login === "function") controls.append(button("syncLogin", "login", "fa-right-to-bracket"));
        if (typeof engine.openCloud === "function") controls.append(button("syncCloud", "cloud", "fa-cloud"));
        if (typeof engine.openUpdates === "function") controls.append(button("syncUpdates", "updates", "fa-download"));
        const stopHelp = element("p", "text-small text-muted");
        stopHelp.append(label("syncStopAllDescription"));
        statusSection.append(status, notice, controls, stopHelp, feedback, refreshIssue);
        const pairsSection = section("syncPairsTitle");
        const pairsList = list();
        pairsList.id = "sync-pairs";
        pairsSection.append(pairsList, button("syncAdd", "add", "fa-plus"));
        const editorSection = section("syncPairEditorTitle");
        editorSection.hidden = true;
        const remote = field("syncRemotePath", "sync-remote-path");
        const local = field("syncLocalPath", "sync-local-path");
        remote.input.required = true;
        local.input.required = true;
        local.input.readOnly = capabilities.folderPicker && typeof engine.pickFolder === "function";
        const editorControls = element("div", "hstack");
        if (capabilities.folderPicker && typeof engine.pickFolder === "function") editorControls.append(button("syncBrowse", "browse", "fa-folder-open"));
        editorControls.append(button("syncSave", "save-pair"), button("syncCancel", "cancel-pair", "fa-xmark"));
        editorSection.append(remote.wrapper, local.wrapper, editorControls);
        const optionsSection = section("syncOptionsTitle");
        const poll = field("syncPollInterval", "sync-poll-interval", "number");
        poll.input.min = "5";
        poll.input.max = "3600";
        poll.input.step = "1";
        const startup = field("syncStartup", "sync-startup", "checkbox");
        const tray = field("syncMinimize", "sync-minimize", "checkbox");
        const cli = element("p", "field-status status-idle");
        cli.id = "sync-cli";
        cli.setAttribute("aria-live", "polite");
        optionsSection.append(poll.wrapper);
        if (capabilities.autostart) optionsSection.append(startup.wrapper);
        if (capabilities.tray) optionsSection.append(tray.wrapper);
        const optionControls = element("div", "hstack");
        optionControls.append(button("syncSave", "save-options"));
        if (typeof engine.pickCli === "function") optionControls.append(button("syncChooseCli", "pick-cli", "fa-folder-open"));
        if (typeof engine.resetCli === "function") optionControls.append(button("syncDetectCli", "reset-cli", "fa-rotate"));
        optionsSection.append(cli, optionControls);
        const detailsSection = section("syncDetailsTitle");
        const selectorHost = element("div", "form-field vstack");
        const selectorLabel = element("label", "form-label", tr("syncSelectPair"));
        selectorLabel.dataset.translateKey = "syncSelectPair";
        selectorLabel.id = "sync-select-label";
        selectorHost.append(selectorLabel);
        detailsSection.append(selectorHost);
        const feedLists = {};
        for (const kind of ["conflicts", "activity", "files"]) {
            const group = section({conflicts: "syncConflictsTitle", activity: "syncActivityTitle", files: "syncFilesTitle"}[kind]);
            const body = list();
            body.id = "sync-" + kind;
            group.append(body);
            detailsSection.append(group);
            feedLists[kind] = body;
        }
        panel.replaceChildren(statusSection, pairsSection, editorSection, optionsSection, detailsSection);

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
            return ["refresh", "connect", "cancel-connect", "login", "cloud", "updates"].includes(action) || (action === "stop" && !pairId);
        }
        function activityTime(timestamp) {
            if (!Number.isFinite(timestamp)) return "";
            const date = new Date(timestamp * 1000);
            return Number.isFinite(date.getTime()) ? new Intl.DateTimeFormat(document.documentElement.lang || undefined, {dateStyle: "short", timeStyle: "short"}).format(date) : "";
        }
        function updateDisabled() {
            for (const control of panel.querySelectorAll("button[data-sync-action]")) {
                const action = control.dataset.syncAction;
                control.disabled = operation && !["refresh", "cancel-pair", "cancel-connect", "cloud"].includes(action);
                if (action === "cancel-connect") control.hidden = !connecting;
                if (control.dataset.path) control.disabled ||= busyPaths.has(pathKey(control.dataset.pairId, control.dataset.path));
                if (editorSection.contains(control)) control.disabled ||= !editor;
                if (["start", "unlock"].includes(action)) control.disabled ||= settings?.cliAvailable === false;
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
                if (!selection) { body.append(row(tr("syncSelectPair"))); continue; }
                if (entries === null) { body.append(row(tr("syncLoading"))); continue; }
                if (entries instanceof Error) { body.append(row(tr("syncFeedUnavailable"))); continue; }
                const visible = kind === "conflicts" ? entries.filter(item => !resolvedPaths.has(pathKey(selection, item.path))) : entries;
                if (!visible.length) {
                    body.append(row(tr({activity: "syncActivityEmpty", conflicts: "syncConflictsEmpty", files: "syncFilesEmpty"}[kind])));
                    continue;
                }
                for (const item of visible) {
                    const entry = row(displayPath(item.path || item.name || ""));
                    if (kind === "conflicts") {
                        const actions = element("div", "hstack");
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
            if (!pairs.length) pairsList.append(row(tr("syncNoPairs")));
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
                const actions = element("div", "hstack");
                for (const [key, action, icon] of [["syncStart", "start", "fa-play"], ["syncStop", "stop", "fa-stop"], ["syncDetails", "details", "fa-list"]]) {
                    const control = button(key, action, icon);
                    control.dataset.pairId = pair.id;
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
        function render() {
            checkAccount();
            status.textContent = ownerRefreshing ? tr("syncLoading") : ownerRefreshFailed ? tr("syncUnavailable") : accountMismatch ? tr("syncAccountMismatch") : settings?.cliAvailable === false ? tr("syncMissingCli") : stateLabel(snapshot?.state);
            notice.textContent = identityBlocked ? "" : detailText(snapshot?.notice);
            notice.hidden = !notice.textContent;
            cli.textContent = settings?.cliAvailable ? tr("syncCliDetected", {path: settings.cliPath || "pc"}) : tr("syncMissingCli");
            const connect = controls.querySelector('[data-sync-action="connect"]');
            if (connect) connect.hidden = !accountMismatch && snapshot?.state !== "notConfigured";
            pairsSection.hidden = identityBlocked;
            detailsSection.hidden = identityBlocked;
            optionsSection.hidden = identityBlocked;
            if (identityBlocked) { updateDisabled(); return; }
            if (!editing && settings) {
                poll.input.value = String(settings.pollInterval);
                startup.input.checked = !!settings.launchOnStartup;
                tray.input.checked = !!settings.minimizeToTray;
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
            const capturedEpoch = epoch;
            const ticket = ++request;
            const results = await Promise.allSettled([engine.getSettings(), engine.status()]);
            if (!active || disposed || capturedEpoch !== epoch || ticket !== request) return;
            if (results[0].status !== "fulfilled") { refreshIssue.textContent = tr("syncRefreshFailed"); return; }
            const next = results[0].value;
            if (!Array.isArray(next?.pairs)) { refreshIssue.textContent = tr("syncRefreshFailed"); return; }
            if (settings && next.revision !== settings.revision) {
                epoch++;
                editor = null;
                editorSection.hidden = true;
                editing = false;
                resolvedPaths.clear();
                for (const kind of Object.keys(feeds)) feeds[kind] = null;
            }
            settings = next;
            const resultSnapshot = results[1].status === "fulfilled" && results[1].value?.revision === settings.revision ? results[1].value : null;
            snapshot = resultSnapshot && snapshot?.revision === resultSnapshot.revision && (snapshot.sequence || 0) > (resultSnapshot.sequence || 0) ? snapshot : resultSnapshot;
            refreshIssue.textContent = snapshot ? "" : tr("syncRefreshFailed");
            if (!settings.pairs.some(pair => pair.id === selection)) {
                selection = settings.pairs[0]?.id || "";
                epoch++;
                for (const kind of Object.keys(feeds)) feeds[kind] = null;
            }
            render();
            if (selection && !identityBlocked) await readFeeds(capture(), ticket);
        }
        function select(pairId) {
            if (identityBlocked) return;
            if (!settings?.pairs.some(pair => pair.id === pairId)) return;
            selection = pairId;
            epoch++;
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
            if (name === "menu") return;
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
            if (operation || !active) return;
            const captured = capture();
            const pairId = control.dataset.pairId;
            if (identityBlocked && !permittedWhileBlocked(name, pairId)) return;
            const pair = settings?.pairs.find(item => item.id === pairId);
            if (pairId && !pair) return;
            if (name === "details") { select(pairId); return; }
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
                        const replacement = {remotePath: remote.input.value.trim(), mountPoint: local.input.value.trim()};
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
                    const methods = {"pick-cli": "pickCli", "reset-cli": "resetCli", "open-folder": "openFolder", cloud: "openCloud", updates: "openUpdates", login: "login", connect: "loginCli"};
                    const method = methods[name] || name;
                    const args = pairId ? {pairId} : {};
                    if (path) args.path = path;
                    if (name === "resolve") args.choice = control.dataset.choice;
                    const result = await engine[method](args);
                    if (result?.success === false || result?.ok === false) throw new Error("Action failed");
                    if (current(captured)) {
                        if (name === "resolve") resolvedPaths.add(key);
                        message(name === "resolve" ? "syncResolved" : "syncActionDone");
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
        panel.addEventListener("click", onClick);
        optionsSection.addEventListener("input", onInput);
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
        document.addEventListener(EVT.SETTINGS_SECTION_SHOWN, onSection);
        document.addEventListener(EVT.LANGUAGE_CHANGE, onLanguage);
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
                if (webAccount) document.removeEventListener(EVT.E2EE_STATE, onEncryptionState);
                panel.removeEventListener("click", onClick);
                optionsSection.removeEventListener("input", onInput);
                for (const menu of menus) menu.destroy();
                pairSelect?.destroy();
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
