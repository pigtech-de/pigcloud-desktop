window.PigcloudModal = (() => {
    'use strict';

    function label(key, fallback) {
        const out = window.t(key);
        if (out && out !== key) return out;
        return fallback || key;
    }

    function build(titleKey, titleId, sizeClass) {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        if (titleId) overlay.setAttribute('aria-labelledby', titleId);
        overlay.style.display = 'flex';

        const content = document.createElement('div');
        content.className = 'modal-content vstack ' + (sizeClass || 'modal-sm');

        const header = document.createElement('div');
        header.className = 'modal-header';

        const title = document.createElement('h3');
        title.className = 'modal-title';
        if (titleId) title.id = titleId;
        title.textContent = label(titleKey);
        header.appendChild(title);

        const closeBtn = document.createElement('button');
        closeBtn.className = 'icon-button is-ghost modal-close';
        closeBtn.type = 'button';
        const closeLabel = label('closeLabel', 'Close');
        closeBtn.setAttribute('aria-label', closeLabel);
        closeBtn.title = closeLabel;
        closeBtn.dataset.translateKey = 'closeLabel';
        const closeIcon = document.createElement('i');
        closeIcon.className = 'fas fa-xmark';
        closeIcon.setAttribute('aria-hidden', 'true');
        closeBtn.appendChild(closeIcon);
        header.appendChild(closeBtn);

        const body = document.createElement('div');
        body.className = 'modal-body vstack';
        const footer = document.createElement('div');
        footer.className = 'modal-footer';

        content.appendChild(header);
        content.appendChild(body);
        content.appendChild(footer);
        overlay.appendChild(content);
        return {overlay, content, header, title, closeBtn, body, footer};
    }

    function mount(opts) {
        const overlay = opts.overlay;
        const trapTarget = opts.trapTarget || overlay;
        const escape = opts.escape === undefined ? 'capture' : opts.escape;
        const opener = opts.restoreFocus ? document.activeElement : null;
        const selects = [];
        let releaseTrap = null;
        let closed = false;

        function onDocKeydown(e) {
            if (e.key !== 'Escape' || !document.body.contains(overlay)) return;
            if (escape === 'capture') e.stopPropagation();
            if (opts.preventEscapeDefault) e.preventDefault();
            close();
        }

        function teardown() {
            if (closed) return;
            closed = true;
            if (escape) document.removeEventListener('keydown', onDocKeydown, escape === 'capture');
            for (const proxy of selects) {
                if (proxy && typeof proxy.destroy === 'function') proxy.destroy();
            }
            if (releaseTrap) releaseTrap();
            overlay.remove();
            if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
            if (typeof opts.onClose === 'function') opts.onClose();
        }

        const popup = typeof opts.registerPopup === 'function' ? opts.registerPopup(teardown) : null;
        const close = () => { if (popup) popup.close(false); else teardown(); };

        if (opts.closeBtn) opts.closeBtn.addEventListener('click', close);
        for (const extra of opts.closers || []) {
            if (extra) extra.addEventListener('click', close);
        }
        if (opts.overlayClick !== false) {
            overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
        }
        if (escape && !popup) document.addEventListener('keydown', onDocKeydown, escape === 'capture');

        document.body.appendChild(overlay);
        releaseTrap = window.trapFocusInModal(trapTarget, {entry: opts.focusEntry !== false});

        return {
            close,
            overlay,
            upgradeSelect(selectEl) {
                const proxy = window.PigcloudCustomSelect && window.PigcloudCustomSelect.upgrade(selectEl);
                if (proxy) {
                    selects.push(proxy);
                    return proxy;
                }
                return selectEl;
            },
        };
    }

    function syncModalOpenClass() {
        const open = [...document.querySelectorAll('.modal-overlay')]
            .some(el => el.style.display === 'flex');
        document.body.classList.toggle('modal-open', open);
    }

    function armOverlayWatch(observer) {
        for (const overlay of document.querySelectorAll('.modal-overlay')) {
            observer.observe(overlay, {attributes: true, attributeFilter: ['style']});
        }
        syncModalOpenClass();
    }

    const touchesOverlay = (nodes) => [...nodes].some(
        node => node.nodeType === 1
            && (node.classList.contains('modal-overlay') || node.querySelector('.modal-overlay')));

    function watchModalOverlays() {
        if (!document.body || typeof MutationObserver !== 'function') return;
        const styleWatch = new MutationObserver(syncModalOpenClass);
        new MutationObserver((records) => {
            if (records.some(r => touchesOverlay(r.addedNodes) || touchesOverlay(r.removedNodes))) {
                armOverlayWatch(styleWatch);
            }
        }).observe(document.body, {childList: true});
        armOverlayWatch(styleWatch);
    }

    watchModalOverlays();

    return {build, mount};
})();
