(function () {
    "use strict";

    const instances = [];
    const menuRecords = [];

    function isEditableTarget(el) {
        return el instanceof Element
            && (el.isContentEditable || /^(?:INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
    }

    function visibleOptionEls(optionEls) {
        return optionEls.filter(el => el.getClientRects().length > 0);
    }

    function clearDigitHints(optionEls) {
        optionEls.forEach(el => {
            const kbd = el.querySelector(".custom-select-kbd");
            if (kbd) { kbd.remove(); }
        });
    }

    function applyDigitHints(optionEls) {
        clearDigitHints(optionEls);
        visibleOptionEls(optionEls).slice(0, 9).forEach((el, i) => {
            const kbd = document.createElement("kbd");
            kbd.className = "custom-select-kbd";
            kbd.setAttribute("aria-hidden", "true");
            kbd.textContent = String(i + 1);
            el.prepend(kbd);
        });
    }

    document.addEventListener("keydown", (e) => {
        if (!/^[1-9]$/.test(e.key) || e.ctrlKey || e.metaKey || e.altKey) { return; }
        if (isEditableTarget(e.target)) { return; }
        const record = menuRecords.find(r => r.isOpen());
        if (!record) { return; }
        e.preventDefault();
        e.stopPropagation();
        const item = visibleOptionEls(record.optionEls)[Number(e.key) - 1];
        if (item) { item.click(); }
    }, true);

    function resolveLabel(opt) {
        if (opt.translateKey && window.translations && window.currentLanguage) {
            const lang = window.translations[window.currentLanguage];
            if (lang && lang[opt.translateKey]) {
                return lang[opt.translateKey];
            }
        }
        return opt.label;
    }

    function closeAllCustomSelects(except) {
        instances.forEach(inst => {
            if (inst !== except) { inst.close(); }
        });
        if (window.closeTypeFilterMenu) { window.closeTypeFilterMenu(); }
        if (window.closeToolbarOverflow) { window.closeToolbarOverflow(); }
    }

    function getProxy(idOrEl) {
        const el = typeof idOrEl === "string" ? document.getElementById(idOrEl) : idOrEl;
        return el && el._customSelectProxy ? el._customSelectProxy : el;
    }

    function buildOptionEl(opt, index, menuId) {
        const item = document.createElement("div");
        item.className = "custom-select-option";
        item.setAttribute("role", "option");
        item.tabIndex = -1;
        item.id = menuId + "-opt-" + index;
        item.dataset.value = opt.value;
        if (opt.translateKey) { item.dataset.translateKey = opt.translateKey; }
        item.textContent = opt.label;
        return item;
    }

    function bindValueState(spec) {
        const { options, text, optionEls, toggle, container, changeListeners, hasCurrentSize } = spec;
        let currentValue = spec.initialValue;
        let proxy = null;

        function updateDisplay() {
            const opt = options.find(o => o.value === currentValue);
            if (opt) {
                text.textContent = resolveLabel(opt);
                if (opt.translateKey) {
                    text.dataset.translateKey = opt.translateKey;
                } else {
                    delete text.dataset.translateKey;
                }
            }
            const listOpen = toggle.getAttribute("aria-expanded") === "true";
            optionEls.forEach(el => {
                const selected = el.dataset.value === currentValue;
                el.classList.toggle("is-selected", selected);
                el.setAttribute("aria-selected", selected ? "true" : "false");
                if (selected && listOpen) { toggle.setAttribute("aria-activedescendant", el.id); }
            });
            if (!listOpen) { toggle.removeAttribute("aria-activedescendant"); }
        }

        function setValue(val, fireEvent) {
            const prev = currentValue;
            currentValue = val;
            if (hasCurrentSize) { container.dataset.currentSize = val; }
            updateDisplay();
            if (fireEvent && prev !== val) {
                changeListeners.forEach(fn => fn({ target: proxy, value: val }));
            }
        }

        return {
            getValue: () => currentValue,
            setValue,
            updateDisplay,
            attachProxy: (built) => { proxy = built; }
        };
    }

    function labelFor(id) {
        return id ? document.querySelector(`label[for="${id}"]`) : null;
    }

    function sheetTitleFor(container, toggle) {
        const byLabel = labelFor(container.id);
        return (byLabel && byLabel.textContent.trim()) || toggle.getAttribute("aria-label") || toggle.title || "";
    }

    function buildInstance(spec) {
        const { container, options, menuId, getValue, setValue, toggle, menu, optionEls, updateDisplay } = spec;
        let isDisabled = false;
        let titleEl = null;

        function applyLevelRoles(asLevel) {
            menu.setAttribute("role", asLevel ? "menu" : "listbox");
            optionEls.forEach(el => {
                el.setAttribute("role", asLevel ? "menuitemradio" : "option");
                if (asLevel) {
                    el.setAttribute("aria-checked", el.classList.contains("is-selected") ? "true" : "false");
                    el.removeAttribute("aria-selected");
                } else {
                    el.removeAttribute("aria-checked");
                }
            });
            if (!asLevel) { updateDisplay(); }
        }

        const ctl = window.PigcloudMenu.attach(toggle, menu, {
            placement: "bottom-start",
            toggleIcon: false,
            openerLit: true,
            openerArrows: false,
            items: () => visibleOptionEls(optionEls),
            drillIn: () => sheetTitleFor(container, toggle),
            onOpen: (surface) => {
                closeAllCustomSelects(proxy);
                applyDigitHints(optionEls);
                container.classList.add("is-open");
                updateDisplay();
                if (surface.closest(".menu-level")) {
                    applyLevelRoles(true);
                    return;
                }
                if (surface.classList.contains("sheet")) {
                    const title = sheetTitleFor(container, toggle);
                    if (title) {
                        titleEl = document.createElement("div");
                        titleEl.className = "custom-select-sheet-title";
                        titleEl.textContent = title;
                        surface.prepend(titleEl);
                    }
                    return;
                }
                surface.style.minWidth = toggle.getBoundingClientRect().width + "px";
                ctl.reposition();
            },
            onClose: () => {
                clearDigitHints(optionEls);
                updateDisplay();
                if (menu.getAttribute("role") === "menu") { applyLevelRoles(false); }
                container.classList.remove("is-open");
                menu.style.minWidth = "";
                if (titleEl) {
                    titleEl.remove();
                    titleEl = null;
                }
            }
        });

        function closeMenu() { ctl.close(); }

        toggle.addEventListener("keydown", (e) => {
            if (isDisabled) { return; }
            if (e.key === "ArrowDown" || e.key === "ArrowUp") {
                e.preventDefault();
                const idx = options.findIndex(o => o.value === getValue());
                const next = e.key === "ArrowDown"
                    ? Math.min(idx + 1, options.length - 1)
                    : Math.max(idx - 1, 0);
                if (next !== idx) { setValue(options[next].value, true); }
            }
        });

        function bindOptionClick(item, idx) {
            item.addEventListener("click", (e) => {
                e.stopPropagation();
                if (isDisabled) { return; }
                const value = options[idx].value;
                if (value === getValue() && "reselect" in container.dataset) {
                    spec.changeListeners.forEach(fn => fn({ target: proxy, value }));
                } else {
                    setValue(value, true);
                }
                closeMenu();
            });
        }

        optionEls.forEach((item, i) => bindOptionClick(item, i));

        const proxy = {
            el: container,
            get value() { return getValue(); },
            set value(val) { setValue(val, false); },
            get disabled() { return isDisabled; },
            set disabled(val) {
                isDisabled = !!val;
                container.classList.toggle("is-disabled", isDisabled);
                toggle.disabled = isDisabled;
            },
            addEventListener(type, fn) {
                if (type === "change") { spec.changeListeners.push(fn); }
            },
            removeEventListener(type, fn) {
                if (type === "change") {
                    const idx = spec.changeListeners.indexOf(fn);
                    if (idx !== -1) { spec.changeListeners.splice(idx, 1); }
                }
            },
            setAttribute(name, val) { container.setAttribute(name, val); },
            getAttribute(name) { return container.getAttribute(name); },
            destroy() {
                ctl.destroy();
                if (titleEl) { titleEl.remove(); }
                menu.remove();
                container.remove();
                const idx = instances.indexOf(proxy);
                if (idx !== -1) { instances.splice(idx, 1); }
                const rec = menuRecords.findIndex(r => r.menu === menu);
                if (rec !== -1) { menuRecords.splice(rec, 1); }
            },
            close() { closeMenu(); },
            setOptions(newOptions) {
                options.length = 0;
                newOptions.forEach(o => options.push(o));
                Array.from(menu.querySelectorAll(".custom-select-option")).forEach(el => el.remove());
                optionEls.length = 0;
                options.forEach((opt, i) => {
                    const item = buildOptionEl(opt, i, menuId);
                    menu.appendChild(item);
                    optionEls.push(item);
                    bindOptionClick(item, i);
                });
                if (options.length > 0 && !options.some(o => o.value === getValue())) {
                    setValue(options[0].value, false);
                } else if (typeof updateDisplay === "function") {
                    updateDisplay();
                }
                if (ctl.isOpen()) {
                    applyDigitHints(optionEls);
                    if (menu.closest(".menu-level")) { applyLevelRoles(true); }
                }
            }
        };

        container._customSelectProxy = proxy;
        instances.push(proxy);
        menuRecords.push({ menu, optionEls, isOpen: ctl.isOpen });
        return proxy;
    }

    function buildChrome(options, menuId, labelAttrs) {
        const container = document.createElement("div");
        container.className = "custom-select";

        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "custom-select-toggle hstack";
        toggle.setAttribute("role", "combobox");
        toggle.setAttribute("aria-haspopup", "listbox");
        toggle.setAttribute("aria-expanded", "false");
        toggle.setAttribute("aria-controls", menuId);
        if (labelAttrs && labelAttrs.title) { toggle.title = labelAttrs.title; }
        if (labelAttrs && labelAttrs.ariaLabel) { toggle.setAttribute("aria-label", labelAttrs.ariaLabel); }

        const text = document.createElement("span");
        text.className = "custom-select-text text-truncate";
        const chevron = document.createElement("i");
        chevron.className = "fas fa-chevron-down";
        chevron.setAttribute("aria-hidden", "true");
        toggle.appendChild(text);
        toggle.appendChild(chevron);
        container.appendChild(toggle);

        const menu = document.createElement("div");
        menu.className = "custom-select-menu";
        menu.id = menuId;
        menu.setAttribute("role", "listbox");
        menu.hidden = true;
        const optionEls = [];

        options.forEach((opt, i) => {
            const item = buildOptionEl(opt, i, menuId);
            menu.appendChild(item);
            optionEls.push(item);
        });

        document.body.appendChild(menu);

        return { container, toggle, text, menu, optionEls };
    }

    function buildSegmentItem(opt) {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "segmented-item";
        item.dataset.value = opt.value;
        if (opt.translateKey) { item.dataset.translateKey = opt.translateKey; }
        item.textContent = opt.label;
        item.setAttribute("aria-pressed", "false");
        return item;
    }

    function buildSegmentedInstance(spec) {
        const { container, options, itemEls, changeListeners } = spec;
        let currentValue = spec.initialValue;
        let isDisabled = false;
        let proxy = null;

        function render() {
            itemEls.forEach(el => {
                el.setAttribute("aria-pressed", el.dataset.value === currentValue ? "true" : "false");
            });
        }

        function setValue(val, fireEvent) {
            const prev = currentValue;
            currentValue = val;
            render();
            if (fireEvent && prev !== val) {
                changeListeners.forEach(fn => fn({ target: proxy, value: val }));
            }
        }

        function bindItem(item) {
            item.addEventListener("click", () => {
                if (isDisabled) { return; }
                setValue(item.dataset.value, true);
            });
        }

        container.addEventListener("keydown", (e) => {
            if (isDisabled || (e.key !== "ArrowLeft" && e.key !== "ArrowRight")) { return; }
            const idx = options.findIndex(o => o.value === currentValue);
            const next = e.key === "ArrowRight"
                ? Math.min(idx + 1, options.length - 1)
                : Math.max(idx - 1, 0);
            if (next === idx) { return; }
            e.preventDefault();
            setValue(options[next].value, true);
            itemEls[next].focus();
        });

        itemEls.forEach(bindItem);

        proxy = {
            el: container,
            get value() { return currentValue; },
            set value(val) { setValue(val, false); },
            get disabled() { return isDisabled; },
            set disabled(val) {
                isDisabled = !!val;
                container.classList.toggle("is-disabled", isDisabled);
                itemEls.forEach(el => { el.disabled = isDisabled; });
            },
            addEventListener(type, fn) {
                if (type === "change") { changeListeners.push(fn); }
            },
            removeEventListener(type, fn) {
                if (type === "change") {
                    const idx = changeListeners.indexOf(fn);
                    if (idx !== -1) { changeListeners.splice(idx, 1); }
                }
            },
            setAttribute(name, val) { container.setAttribute(name, val); },
            getAttribute(name) { return container.getAttribute(name); },
            destroy() {
                container.remove();
                const idx = instances.indexOf(proxy);
                if (idx !== -1) { instances.splice(idx, 1); }
            },
            close() {},
            setOptions(newOptions) {
                options.length = 0;
                newOptions.forEach(o => options.push(o));
                container.replaceChildren();
                itemEls.length = 0;
                options.forEach(opt => {
                    const item = buildSegmentItem(opt);
                    container.appendChild(item);
                    itemEls.push(item);
                    bindItem(item);
                });
                if (options.length > 0 && !options.some(o => o.value === currentValue)) {
                    setValue(options[0].value, false);
                } else {
                    render();
                }
            }
        };

        render();
        container._customSelectProxy = proxy;
        instances.push(proxy);
        return proxy;
    }

    function readOptions(selectEl) {
        return Array.from(selectEl.options).map(opt => ({
            value: opt.value,
            label: opt.textContent.trim(),
            translateKey: opt.dataset.translateKey || ""
        }));
    }

    function upgradeToSegmented(selectEl, options, changeListeners) {
        const container = document.createElement("div");
        container.className = "segmented";
        container.setAttribute("role", "group");
        if (selectEl.id) { container.id = selectEl.id; }
        if (selectEl.hasAttribute("aria-label")) { container.setAttribute("aria-label", selectEl.getAttribute("aria-label")); }
        Object.keys(selectEl.dataset).forEach(key => {
            if (key === "translateKey" || key === "segmented") { return; }
            container.dataset[key] = selectEl.dataset[key];
        });
        const itemEls = options.map(buildSegmentItem);
        itemEls.forEach(item => container.appendChild(item));
        if (selectEl.parentNode) {
            selectEl.parentNode.replaceChild(container, selectEl);
        }
        return buildSegmentedInstance({ container, options, itemEls, changeListeners, initialValue: selectEl.value });
    }

    function wantsSegmented(selectEl) {
        if (!("segmented" in selectEl.dataset)) { return false; }
        if (selectEl.dataset.segmented !== "sheet") { return true; }
        return !!window.PigcloudSheet && window.PigcloudSheet.isSheetViewport();
    }

    function upgrade(selectEl) {
        if (!selectEl || selectEl.tagName !== "SELECT") { return null; }

        const options = readOptions(selectEl);
        const changeListeners = [];
        if (wantsSegmented(selectEl)) {
            return upgradeToSegmented(selectEl, options, changeListeners);
        }

        const hasCurrentSize = "currentSize" in selectEl.dataset;
        const menuId = (selectEl.id || "cs-" + Math.random().toString(36).slice(2, 8)) + "-menu";

        const chrome = buildChrome(options, menuId, {
            title: selectEl.title,
            ariaLabel: selectEl.getAttribute("aria-label")
        });
        const { container, toggle, text, menu, optionEls } = chrome;

        if (selectEl.id) { container.id = selectEl.id; }
        if (selectEl.className) {
            selectEl.className.split(/\s+/).forEach(cls => {
                if (cls) { container.classList.add(cls); }
            });
        }
        const TOGGLE_DATASET = ["translateAriaLabel", "translateTitle"];
        Object.keys(selectEl.dataset).forEach(key => {
            if (key === "translateKey") { return; }
            if (TOGGLE_DATASET.includes(key)) {
                toggle.dataset[key] = selectEl.dataset[key];
                return;
            }
            container.dataset[key] = selectEl.dataset[key];
        });
        const contentKey = selectEl.dataset.translateKey;
        if (contentKey) {
            if (toggle.title && !toggle.dataset.translateTitle) { toggle.dataset.translateTitle = contentKey; }
            if (toggle.hasAttribute("aria-label") && !toggle.dataset.translateAriaLabel) {
                toggle.dataset.translateAriaLabel = contentKey;
            }
        }
        const label = labelFor(selectEl.id);
        if (label) {
            if (!label.id) { label.id = (selectEl.id || menuId) + "-label"; }
            toggle.setAttribute("aria-labelledby", label.id);
        }

        const state = bindValueState({
            options, text, optionEls, toggle, container, changeListeners, hasCurrentSize,
            initialValue: selectEl.value
        });

        if (selectEl.parentNode) {
            selectEl.parentNode.replaceChild(container, selectEl);
        }

        state.updateDisplay();

        const proxy = buildInstance({
            container, options, menuId, toggle, menu, optionEls, changeListeners,
            getValue: state.getValue,
            setValue: state.setValue,
            updateDisplay: state.updateDisplay
        });
        state.attachProxy(proxy);
        return proxy;
    }

    function create(optionsList, config = {}) {
        const menuId = (config.id || "cs-" + Math.random().toString(36).slice(2, 8)) + "-menu";

        const changeListeners = [];
        if (config.onChange) { changeListeners.push(config.onChange); }

        const chrome = buildChrome(optionsList, menuId, {});
        const { container, toggle, text, menu, optionEls } = chrome;
        if (config.id) { container.id = config.id; }
        if (config.className) {
            config.className.split(/\s+/).forEach(cls => {
                if (cls) { container.classList.add(cls); }
            });
        }

        const state = bindValueState({
            options: optionsList, text, optionEls, toggle, container, changeListeners,
            hasCurrentSize: false,
            initialValue: config.initialValue || (optionsList.length > 0 ? optionsList[0].value : "")
        });

        state.updateDisplay();

        const proxy = buildInstance({
            container, options: optionsList, menuId, toggle, menu, optionEls, changeListeners,
            getValue: state.getValue,
            setValue: state.setValue,
            updateDisplay: state.updateDisplay
        });
        state.attachProxy(proxy);
        return proxy;
    }

    window.PigcloudCustomSelect = {
        upgrade,
        create,
        closeAll: function () { closeAllCustomSelects(null); },
        getProxy
    };
})();
