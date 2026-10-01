window.PigcloudMenu = (() => {
    'use strict';

    const DEFAULT_ITEMS = '[role="menuitem"], [role="menuitemradio"], [role="menuitemcheckbox"]';
    const VIEWPORT_MARGIN = 8;
    const GEOMETRY = ['position', 'top', 'left', 'right', 'bottom'];
    const OWNED_STYLE = ['display', ...GEOMETRY];

    let seq = 0;
    let openController = null;
    let handingOver = false;

    const scrimUsers = new Set();
    let scrimEl = null;

    const isShown = (el) => !!el && el.matches(':popover-open');

    function ensureScrim() {
        if (scrimEl && scrimEl.isConnected) return scrimEl;
        scrimEl = document.createElement('div');
        scrimEl.className = 'menu-scrim';
        scrimEl.setAttribute('popover', 'manual');
        scrimEl.setAttribute('aria-hidden', 'true');
        document.body.appendChild(scrimEl);
        return scrimEl;
    }

    function showScrim(ctrl, painted) {
        const el = ensureScrim();
        el.classList.toggle('is-clear', !painted);
        scrimUsers.add(ctrl);
        if (scrimUsers.size === 1 && !isShown(el)) el.showPopover();
        return el;
    }

    function hideScrim(ctrl) {
        if (!scrimUsers.delete(ctrl)) return;
        if (scrimUsers.size === 0 && isShown(scrimEl)) scrimEl.hidePopover();
    }

    function cutScrimHole(el, opener) {
        const r = opener.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) { el.style.clipPath = ''; return; }
        const cs = window.getComputedStyle(opener);
        const cap = Math.min(r.width, r.height) / 2;
        const rad = (v) => Math.max(0, Math.min(cap, parseFloat(v) || 0));
        const tl = rad(cs.borderTopLeftRadius), tr = rad(cs.borderTopRightRadius);
        const br = rad(cs.borderBottomRightRadius), bl = rad(cs.borderBottomLeftRadius);
        const arc = (n, x, y) => (n ? `A${n} ${n} 0 0 1 ${x} ${y}` : `L${x} ${y}`);
        const hole = `M${r.left + tl} ${r.top}`
            + `H${r.right - tr}${arc(tr, r.right, r.top + tr)}`
            + `V${r.bottom - br}${arc(br, r.right - br, r.bottom)}`
            + `H${r.left + bl}${arc(bl, r.left, r.bottom - bl)}`
            + `V${r.top + tl}${arc(tl, r.left + tl, r.top)}Z`;
        el.style.clipPath = `path(evenodd, 'M0 0H${window.innerWidth}V${window.innerHeight}H0Z ${hole}')`;
    }

    function placeSurface(opener, surface, placement, offset) {
        surface.style.position = 'fixed';
        surface.style.right = 'auto';
        surface.style.bottom = 'auto';
        const anchor = opener.getBoundingClientRect();
        const box = surface.getBoundingClientRect();
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const [side, align] = String(placement).split('-');

        let below = side !== 'top';
        const fitsBelow = anchor.bottom + offset + box.height <= vh - VIEWPORT_MARGIN;
        const fitsAbove = anchor.top - offset - box.height >= VIEWPORT_MARGIN;
        if (below && !fitsBelow && fitsAbove) below = false;
        else if (!below && !fitsAbove && fitsBelow) below = true;

        let start = align !== 'end';
        const fitsStart = anchor.left + box.width <= vw - VIEWPORT_MARGIN;
        const fitsEnd = anchor.right - box.width >= VIEWPORT_MARGIN;
        if (start && !fitsStart && fitsEnd) start = false;
        else if (!start && !fitsEnd && fitsStart) start = true;

        const top = below ? anchor.bottom + offset : anchor.top - offset - box.height;
        const left = start ? anchor.left : anchor.right - box.width;
        surface.style.top = Math.max(VIEWPORT_MARGIN, Math.min(top, vh - VIEWPORT_MARGIN - box.height)) + 'px';
        surface.style.left = Math.max(VIEWPORT_MARGIN, Math.min(left, vw - VIEWPORT_MARGIN - box.width)) + 'px';
        surface.dataset.menuPlacement = (below ? 'bottom' : 'top') + '-' + (start ? 'start' : 'end');
    }

    function attach(opener, surface, opts) {
        if (surface._pigcloudMenu) surface._pigcloudMenu.destroy();

        const cfg = opts || {};
        const resolvePlacement = typeof cfg.placement === 'function'
            ? () => cfg.placement(opener, surface) || 'bottom-end'
            : () => cfg.placement || 'bottom-end';
        const offset = typeof cfg.offset === 'number' ? cfg.offset : 4;
        const painted = cfg.scrim !== false;
        const ownsOpenerPaint = cfg.toggleIcon !== false;
        const openerLit = cfg.openerLit === undefined ? ownsOpenerPaint : cfg.openerLit === true;
        const closeOnSelect = cfg.closeOnSelect !== false;
        const closeOnTab = cfg.closeOnTab !== false;
        const sheetAllowed = cfg.sheet !== false;
        const isSheetNow = () => sheetAllowed && !!window.PigcloudSheet && window.PigcloudSheet.isSheetViewport();
        const locked = () => typeof cfg.locked === 'function' && cfg.locked() === true;
        let sheetLocked = false;
        const resolveItems = typeof cfg.items === 'function'
            ? () => Array.from(cfg.items(surface) || [])
            : () => Array.from(surface.querySelectorAll(DEFAULT_ITEMS));

        const wantsHistory = () => {
            if (locked()) return false;
            if (typeof cfg.history === 'function') return cfg.history() === true;
            if (cfg.history === undefined) return surface.classList.contains('sheet') || !!levelEl;
            return cfg.history === true;
        };

        const added = {id: false, haspopup: false, controls: false, expanded: false, role: false, popover: false, toggleClass: false};
        const savedInline = {};
        for (const prop of OWNED_STYLE) savedInline[prop] = surface.style[prop];
        const savedHidden = surface.hasAttribute('hidden');
        const restoreGeometry = () => {
            for (const prop of GEOMETRY) surface.style[prop] = savedInline[prop];
            delete surface.dataset.menuPlacement;
        };
        let open = false;
        let stackEntry = null;
        let listening = false;
        let destroyed = false;
        let parentCtl = null;
        let childCtl = null;
        let levelEl = null;
        let levelBack = null;
        let levelHome = null;

        if (!surface.id) { surface.id = 'pc-menu-' + (++seq); added.id = true; }
        if (!opener.hasAttribute('aria-haspopup')) { opener.setAttribute('aria-haspopup', 'menu'); added.haspopup = true; }
        if (!opener.hasAttribute('aria-controls')) { opener.setAttribute('aria-controls', surface.id); added.controls = true; }
        if (!opener.hasAttribute('aria-expanded')) added.expanded = true;
        opener.setAttribute('aria-expanded', 'false');
        if (!surface.hasAttribute('role')) { surface.setAttribute('role', 'menu'); added.role = true; }
        if (!surface.hasAttribute('popover')) { surface.setAttribute('popover', 'manual'); added.popover = true; }
        surface.classList.add('menu-popover');
        surface.removeAttribute('hidden');
        surface.style.display = 'none';
        if (ownsOpenerPaint && !opener.classList.contains('menu-toggle')) {
            opener.classList.add('menu-toggle');
            added.toggleClass = true;
        }

        const ownsScrimHole = () => !!scrimEl && !parentCtl;

        function mountLevel() {
            levelHome = {parent: surface.parentNode, next: surface.nextSibling};
            levelEl = document.createElement('div');
            levelEl.className = 'menu-level';
            levelBack = document.createElement('button');
            levelBack.type = 'button';
            levelBack.tabIndex = -1;
            levelBack.setAttribute('role', 'menuitem');
            levelBack.className = 'context-menu-item context-menu-back hstack';
            const chevron = document.createElement('i');
            chevron.className = 'fas fa-chevron-left';
            chevron.setAttribute('aria-hidden', 'true');
            const label = document.createElement('span');
            label.textContent = String(cfg.drillIn() || '');
            levelBack.append(chevron, label);
            levelBack.addEventListener('click', onLevelBackClick);
            levelEl.append(levelBack, surface);
            parentCtl.surface.appendChild(levelEl);
            parentCtl.surface.classList.add('has-menu-level');
        }

        function unmountLevel() {
            if (!levelEl) return;
            const parentSurface = levelEl.parentNode;
            const home = levelHome && levelHome.parent && levelHome.parent.isConnected ? levelHome.parent : document.body;
            const next = levelHome && levelHome.next && levelHome.next.parentNode === home ? levelHome.next : null;
            home.insertBefore(surface, next);
            levelBack.removeEventListener('click', onLevelBackClick);
            levelEl.remove();
            if (parentSurface) parentSurface.classList.remove('has-menu-level');
            levelEl = null;
            levelBack = null;
            levelHome = null;
        }

        function onLevelBackClick(e) {
            e.preventDefault();
            close();
        }

        function position() {
            if (levelEl) {
                if (!isSheetNow() || !parentCtl || !parentCtl.surface.classList.contains('sheet')) close();
                return;
            }
            const asSheet = isSheetNow();
            surface.classList.toggle('sheet', asSheet);
            opener.classList.toggle('is-sheet-opener', asSheet);
            if (asSheet) {
                restoreGeometry();
                if (ownsScrimHole()) scrimEl.style.clipPath = '';
                return;
            }
            const at = resolvePlacement();
            if (at === 'skin') restoreGeometry();
            else placeSurface(opener, surface, at, offset);
            if (openerLit && ownsScrimHole()) cutScrimHole(scrimEl, opener);
        }

        function warnIfInvisible() {
            if (typeof surface.checkVisibility !== 'function' || surface.checkVisibility()) return;
            console.warn(`PigcloudMenu: #${surface.id} opened invisible. The component owns the open and closed state, so the surface's own rule must drop display: none.`);
        }

        const reposition = () => { if (open) position(); };

        function enabledItems() {
            const rows = levelBack ? [levelBack, ...resolveItems()] : resolveItems();
            return rows.filter(el => !el.disabled
                && !el.hasAttribute('hidden')
                && el.getAttribute('aria-disabled') !== 'true'
                && (typeof el.checkVisibility !== 'function' || el.checkVisibility({visibilityProperty: true})));
        }

        function focusAt(index) {
            const items = enabledItems();
            if (items.length === 0) return;
            items[(index + items.length) % items.length].focus();
        }

        function onSurfaceKeydown(e) {
            if (childCtl && childCtl.isOpen() && childCtl._isLevel()) return;
            const items = enabledItems();
            if (items.length === 0) return;
            const at = items.indexOf(document.activeElement);
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                focusAt(at + 1);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                focusAt(at <= 0 ? items.length - 1 : at - 1);
            } else if (e.key === 'Home') {
                e.preventDefault();
                focusAt(0);
            } else if (e.key === 'End') {
                e.preventDefault();
                focusAt(items.length - 1);
            }
        }

        function onSurfaceClick(e) {
            if (!closeOnSelect) return;
            if (enabledItems().some(el => el === e.target || el.contains(e.target))) close();
        }

        function onScrimClick() {
            if (childCtl && childCtl.isOpen() && !childCtl._isLevel()) return;
            close();
        }

        function onOpenerClick(e) {
            e.preventDefault();
            if (open) close();
            else doOpen(e.detail === 0);
        }

        function onOpenerKeydown(e) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (open) focusAt(0);
                else doOpen(true);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (!open) doOpen(false);
                focusAt(-1);
            }
        }

        function onDocumentTab(e) {
            if (e.key === 'Tab') close();
        }

        let keyTarget = surface;

        function bindOpen() {
            if (listening) return;
            listening = true;
            if (closeOnTab) document.addEventListener('keydown', onDocumentTab, true);
            keyTarget = levelEl || surface;
            keyTarget.addEventListener('keydown', onSurfaceKeydown);
            surface.addEventListener('click', onSurfaceClick, true);
            window.addEventListener('scroll', reposition, {passive: true, capture: true});
            window.addEventListener('resize', reposition, {passive: true});
        }

        function unbindOpen() {
            if (!listening) return;
            listening = false;
            document.removeEventListener('keydown', onDocumentTab, true);
            keyTarget.removeEventListener('keydown', onSurfaceKeydown);
            surface.removeEventListener('click', onSurfaceClick, true);
            window.removeEventListener('scroll', reposition, {capture: true});
            window.removeEventListener('resize', reposition);
        }

        function doOpen(focusFirst) {
            if (open) return;
            if (openController && openController !== controller) {
                if (openController.surface.contains(opener)) {
                    parentCtl = openController;
                    parentCtl._adoptChild(controller);
                } else {
                    handingOver = true;
                    try { openController.close(); } finally { handingOver = false; }
                }
            }
            open = true;
            openController = controller;

            const asLevel = typeof cfg.drillIn === 'function' && !!parentCtl
                && parentCtl.surface.classList.contains('sheet') && isSheetNow();
            if (asLevel) {
                mountLevel();
                surface.style.display = '';
            } else {
                const scrim = showScrim(controller, painted);
                scrim.addEventListener('click', onScrimClick);
                scrim.classList.toggle('is-hidden', locked());
                surface.style.display = '';
                if (!isShown(surface)) surface.showPopover();
            }
            position();
            warnIfInvisible();
            opener.setAttribute('aria-expanded', 'true');
            bindOpen();
            if (surface.classList.contains('sheet') && window.PigcloudScrollLock) {
                window.PigcloudScrollLock.lock();
                sheetLocked = true;
            }

            const stack = window.PigcloudPopupStack;
            if (stack) stackEntry = stack.registerPopup((skipHistory) => { if (!locked()) teardown(skipHistory); }, {history: wantsHistory(), deferEsc: cfg.deferEsc});

            if (focusFirst || asLevel) focusAt(0);
            if (typeof cfg.onOpen === 'function') cfg.onOpen(surface);
        }

        function teardown(skipHistory) {
            stackEntry = null;
            if (!open) return;
            open = false;
            if (childCtl && childCtl.isOpen()) childCtl.close();
            if (openController === controller) openController = parentCtl && parentCtl.isOpen() ? parentCtl : null;
            const ownedHole = ownsScrimHole();
            const levelParent = levelEl ? parentCtl : null;
            if (parentCtl) {
                parentCtl._dropChild(controller);
                parentCtl = null;
            }

            const active = document.activeElement;
            const focusWasInside = !active || active === document.body || surface.contains(active)
                || (!!levelEl && levelEl.contains(active));
            unbindOpen();
            if (scrimEl) {
                scrimEl.removeEventListener('click', onScrimClick);
                if (openerLit && ownedHole) scrimEl.style.clipPath = '';
            }
            if (isShown(surface)) surface.hidePopover();
            hideScrim(controller);
            unmountLevel();
            restoreGeometry();
            surface.style.display = 'none';
            surface.classList.remove('sheet');
            opener.classList.remove('is-sheet-opener');
            opener.setAttribute('aria-expanded', 'false');
            if (sheetLocked) {
                sheetLocked = false;
                if (window.PigcloudScrollLock) window.PigcloudScrollLock.unlock();
            }

            if (!handingOver && focusWasInside) opener.focus();
            if (levelParent && levelParent.isOpen()) levelParent.reposition();
            if (typeof cfg.onClose === 'function') cfg.onClose(skipHistory === true);
        }

        function close(skipHistory) {
            if (!open || locked()) return;
            const entry = stackEntry;
            stackEntry = null;
            if (entry) entry.close(skipHistory === true);
            teardown(skipHistory === true);
        }

        const detachSwipe = sheetAllowed && window.PigcloudSheet
            ? window.PigcloudSheet.attachSwipe(surface, () => close())
            : () => {};
        const openerArrows = cfg.openerArrows !== false;
        opener.addEventListener('click', onOpenerClick);
        if (openerArrows) opener.addEventListener('keydown', onOpenerKeydown);

        const controller = {
            opener,
            surface,
            open: () => doOpen(false),
            close,
            toggle: () => { if (open) close(); else doOpen(false); },
            isOpen: () => open,
            reposition,
            _hasHistory: () => !!(stackEntry && stackEntry.history),
            _onBack: (isPopState) => typeof cfg.onBack === 'function' && cfg.onBack(isPopState) === true,
            _parent: () => parentCtl,
            _isLevel: () => !!levelEl,
            _adoptChild(child) { childCtl = child; },
            _dropChild(child) { if (childCtl === child) childCtl = null; },
            destroy() {
                if (destroyed) return;
                destroyed = true;
                close();
                teardown();
                detachSwipe();
                opener.removeEventListener('click', onOpenerClick);
                if (openerArrows) opener.removeEventListener('keydown', onOpenerKeydown);
                unbindOpen();
                surface.classList.remove('menu-popover');
                restoreGeometry();
                surface.style.display = savedInline.display;
                if (savedHidden) surface.setAttribute('hidden', '');
                if (surface._pigcloudMenu === controller) delete surface._pigcloudMenu;
                if (added.id) surface.removeAttribute('id');
                if (added.haspopup) opener.removeAttribute('aria-haspopup');
                if (added.controls) opener.removeAttribute('aria-controls');
                if (added.expanded) opener.removeAttribute('aria-expanded');
                if (added.role) surface.removeAttribute('role');
                if (added.popover) surface.removeAttribute('popover');
                if (added.toggleClass) opener.classList.remove('menu-toggle');
                for (const el of [opener, surface]) {
                    if (el.getAttribute('class') === '') el.removeAttribute('class');
                    if (el.getAttribute('style') === '') el.removeAttribute('style');
                }
            },
        };
        surface._pigcloudMenu = controller;
        return controller;
    }

    let backEvent = null;

    function handleBack(event) {
        if (event && event === backEvent) return true;
        let target = openController;
        while (target && !target._hasHistory()) target = target._parent();
        if (!target) return false;
        const isPopState = typeof PopStateEvent === 'function' && event instanceof PopStateEvent;
        if (isPopState) backEvent = event;
        if (target._onBack(isPopState)) return true;
        target.close(isPopState);
        return true;
    }

    window.addEventListener('popstate', handleBack);

    return {attach, handleBack};
})();
