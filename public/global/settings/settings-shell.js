window.PigcloudSettingsShell = (() => {
    "use strict";

    const controllers = new WeakMap();
    const EVT = window.PigcloudConstants.EVT;
    const tr = key => window.t(key);
    const node = (tag, className) => {
        const result = document.createElement(tag);
        result.className = className;
        return result;
    };

    function prepare(overlay) {
        if (overlay.querySelector(".settings-page-layout")) return overlay;
        const built = window.PigcloudModal.build("settingsPageTitle", "settings-page-title", "modal-full settings-page");
        built.header.className = "settings-page-header";
        built.title.className = "settings-page-title";
        built.title.dataset.translateKey = "settingsPageTitle";
        built.closeBtn.id = "settings-page-close";
        const back = node("button", "icon-button is-ghost settings-back-button");
        back.type = "button";
        back.id = "settings-back-button";
        back.dataset.translateAriaLabel = "settingsBackButton";
        back.setAttribute("aria-label", tr("settingsBackButton"));
        const icon = node("i", "fas fa-arrow-left");
        icon.setAttribute("aria-hidden", "true");
        back.append(icon);
        built.header.prepend(back);
        const layout = node("div", "settings-page-layout");
        const sidebar = overlay.querySelector(".settings-sidebar") || node("nav", "settings-sidebar vstack");
        sidebar.removeAttribute("role");
        sidebar.dataset.translateAriaLabel = "settingsNavLandmark";
        sidebar.setAttribute("aria-label", tr("settingsNavLandmark"));
        if (!sidebar.querySelector(".settings-nav-tabs")) {
            const tabs = node("div", "settings-nav-tabs vstack");
            tabs.setAttribute("role", "tablist");
            tabs.append(...sidebar.childNodes);
            sidebar.append(tabs);
        }
        const content = overlay.querySelector(".settings-content") || node("div", "settings-content");
        layout.append(sidebar, content);
        const help = overlay.querySelector(".settings-help-rail");
        if (help) layout.append(help);
        built.body.replaceWith(layout);
        built.footer.remove();
        const announcer = overlay.querySelector("#settings-live-announcer") || node("div", "visually-hidden");
        announcer.id = "settings-live-announcer";
        announcer.setAttribute("role", "status");
        announcer.setAttribute("aria-live", "polite");
        announcer.setAttribute("aria-atomic", "true");
        built.header.after(announcer);
        overlay.append(built.content);
        return overlay;
    }

    function create(options = {}) {
        const overlay = options.overlay || node("div", "modal-overlay");
        if (controllers.has(overlay)) return controllers.get(overlay);
        overlay.id = "settings-page";
        overlay.setAttribute("role", "dialog");
        overlay.setAttribute("aria-modal", "true");
        overlay.setAttribute("aria-labelledby", "settings-page-title");
        overlay.hidden = true;
        prepare(overlay);
        if (!overlay.isConnected) document.body.append(overlay);
        const sidebar = overlay.querySelector(".settings-sidebar");
        const content = overlay.querySelector(".settings-content");
        const page = overlay.querySelector(".settings-page");
        const defaultSection = options.defaultSection || "profile";
        let opened = false;
        let releaseFocus = null;
        let focusFrame = null;
        let lastFocus = null;
        let storageAvailable = true;
        let pendingSection = "";
        const focusables = () => Array.from(overlay.querySelectorAll("a[href],button,textarea,input,select,[tabindex]:not([tabindex='-1'])"))
            .filter(el => !el.disabled && !el.closest("[hidden]") && el.getAttribute("aria-hidden") !== "true");

        function selectSection(section) {
            const resolved = options.aliases?.[section] || section;
            const tabs = Array.from(sidebar.querySelectorAll(".settings-nav-item"));
            const available = tabs.filter(tab => !tab.hidden && !tab.disabled).map(tab => tab.dataset.section);
            pendingSection = !available.includes(resolved) && tabs.some(tab => tab.dataset.section === resolved && tab.dataset.pending === "true") ? resolved : "";
            const target = available.includes(resolved) ? resolved : available.includes(defaultSection) ? defaultSection : available[0];
            if (!target) return;
            for (const tab of tabs) {
                const active = tab.dataset.section === target;
                tab.classList.toggle("is-active", active);
                tab.setAttribute("aria-selected", String(active));
            }
            for (const panel of content.querySelectorAll(".settings-section")) panel.hidden = panel.dataset.section !== target;
            options.onSection?.(target);
            if (storageAvailable) {
                try { sessionStorage.setItem("pigcloud_settings_tab", target); } catch { storageAvailable = false; }
            }
            if (opened && window.matchMedia("(max-width: 640px)").matches && !page.classList.contains("is-drilled-in")) {
                page.classList.add("is-drilled-in");
                window.PigcloudModalHistory?.push("settings-drilled");
            }
            document.dispatchEvent(new CustomEvent(EVT.SETTINGS_SECTION_SHOWN, {detail: {section: target}}));
            if (opened) window.PigcloudModalHistory?.reflect("settings/" + target);
        }

        function open(args = {}) {
            let section = args.section || defaultSection;
            if (!args.section && storageAvailable) {
                try { section = sessionStorage.getItem("pigcloud_settings_tab") || section; } catch { storageAvailable = false; }
            }
            if (!opened) {
                opened = true;
                lastFocus = document.activeElement;
                overlay.hidden = false;
                if (overlay.style.display !== "flex") window.PigcloudScrollLock?.lock();
                overlay.style.display = "flex";
                window.PigcloudModalHistory?.push("settings");
                options.opener?.setAttribute("aria-expanded", "true");
                options.onOpen?.();
                focusFrame = requestAnimationFrame(() => {
                    focusFrame = null;
                    if (!opened) return;
                    if (window.trapFocusInModal) releaseFocus = window.trapFocusInModal(overlay);
                    else (focusables()[0] || overlay).focus();
                });
            }
            selectSection(section);
            options.onAnchor?.(section, args.anchor);
            if (args.mobileOverview && window.matchMedia("(max-width: 640px)").matches && page.classList.contains("is-drilled-in")) {
                page.classList.remove("is-drilled-in");
                window.PigcloudModalHistory?.pop();
            }
        }

        function close(skipHistory = false) {
            if (!opened) return;
            opened = false;
            if (focusFrame !== null) cancelAnimationFrame(focusFrame);
            focusFrame = null;
            pendingSection = "";
            options.onClose?.(skipHistory);
            overlay.hidden = true;
            overlay.style.display = "none";
            page.classList.remove("is-drilled-in");
            window.PigcloudModalHistory?.pop(skipHistory);
            window.PigcloudScrollLock?.unlock();
            options.opener?.setAttribute("aria-expanded", "false");
            if (releaseFocus) releaseFocus();
            else if (lastFocus?.isConnected) lastFocus.focus();
            else options.opener?.focus();
            releaseFocus = null;
        }

        new MutationObserver(() => {
            if (!opened || !pendingSection) return;
            const tab = Array.from(sidebar.querySelectorAll(".settings-nav-item")).find(item => item.dataset.section === pendingSection);
            if (tab && !tab.hidden && !tab.disabled) selectSection(pendingSection);
            else if (!tab || tab.dataset.pending !== "true") pendingSection = "";
        }).observe(sidebar, {attributes: true, subtree: true, attributeFilter: ["hidden", "disabled", "data-pending"]});
        sidebar.addEventListener("click", event => {
            const tab = event.target.closest(".settings-nav-item");
            if (tab && sidebar.contains(tab)) selectSection(tab.dataset.section);
        });
        overlay.querySelector("#settings-page-close").addEventListener("click", () => close());
        overlay.querySelector("#settings-back-button").addEventListener("click", () => {
            if (page.classList.contains("is-drilled-in")) window.history.back();
        });
        overlay.addEventListener("click", event => { if (event.target === overlay) close(); });
        overlay.addEventListener("keydown", event => {
            if (!opened || event.defaultPrevented) return;
            if (event.key === "Escape") { event.preventDefault(); close(); }
            if (event.key !== "Tab" || releaseFocus) return;
            const elements = focusables();
            event.preventDefault();
            if (!elements.length) return;
            const index = elements.indexOf(document.activeElement);
            elements[(index + (event.shiftKey ? -1 : 1) + elements.length) % elements.length].focus();
        });
        document.addEventListener(EVT.OPEN_SETTINGS, event => open(event.detail || {}));
        document.addEventListener(EVT.CLOSE_SETTINGS, event => close(event.detail?.skipHistory === true));
        function addSection({id, labelKey, icon: iconName}) {
            const tab = node("button", "settings-nav-item hstack");
            tab.type = "button";
            tab.id = "settings-tab-" + id;
            tab.dataset.section = id;
            tab.setAttribute("role", "tab");
            tab.setAttribute("aria-selected", "false");
            tab.setAttribute("aria-controls", "settings-panel-" + id);
            const icon = node("i", "fa-solid " + iconName);
            icon.setAttribute("aria-hidden", "true");
            const label = node("span", "");
            label.dataset.translateKey = labelKey;
            label.textContent = tr(labelKey);
            tab.append(icon, label);
            const panel = node("div", "settings-section vstack");
            panel.id = "settings-panel-" + id;
            panel.dataset.section = id;
            panel.setAttribute("role", "tabpanel");
            panel.setAttribute("aria-labelledby", tab.id);
            panel.hidden = true;
            sidebar.querySelector(".settings-nav-tabs").append(tab);
            content.append(panel);
            return {tab, panel};
        }
        const controller = {overlay, addSection, open, close, selectSection, focusables};
        controllers.set(overlay, controller);
        return controller;
    }

    const existing = document.getElementById("settings-page");
    if (existing) prepare(existing);
    return {create};
})();
