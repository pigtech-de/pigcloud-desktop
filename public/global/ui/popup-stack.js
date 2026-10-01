(() => {
    'use strict';

    const openPopups = [];

    function popupEscCapture(e) {
        if (e.key !== 'Escape' || openPopups.length === 0) return;
        const target = e.target;
        if (target && target.closest && target.closest('#dialog-modal, .account-password-modal')) return;
        const top = openPopups[openPopups.length - 1];
        if (typeof top.deferEsc === 'function' && top.deferEsc(e)) return;
        e.preventDefault();
        e.stopPropagation();
        top.close(false);
    }

    function registerPopup(teardown, opts) {
        const entry = {
            deferEsc: opts && opts.deferEsc,
            history: !opts || opts.history !== false,
            close(skipHistory) {
                const idx = openPopups.indexOf(entry);
                if (idx === -1) return;
                openPopups.splice(idx, 1);
                if (openPopups.length === 0) document.removeEventListener('keydown', popupEscCapture, true);
                if (entry.history && typeof window.popModalState === 'function') window.popModalState(skipHistory === true);
                teardown(skipHistory === true);
            },
        };
        if (openPopups.length === 0) document.addEventListener('keydown', popupEscCapture, true);
        openPopups.push(entry);
        if (entry.history && typeof window.pushModalState === 'function') window.pushModalState('chat-popup');
        return entry;
    }

    function closeTopPopup(skipHistory) {
        const top = openPopups[openPopups.length - 1];
        if (!top) return false;
        top.close(skipHistory === true);
        return true;
    }

    function depth() {
        return openPopups.length;
    }

    window.PigcloudPopupStack = {registerPopup, closeTopPopup, depth};
})();
