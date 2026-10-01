window.PigcloudDialogManager = {
    modal: null,
    titleEl: null,
    messageEl: null,
    inputEl: null,
    confirmBtn: null,
    cancelBtn: null,
    resolvePromise: null,
    mode: 'alert',
    initialized: false,
    _lastFocusedElement: null,

    init() {
        if (this.initialized) return;

        this.modal = document.getElementById('dialog-modal');
        if (!this.modal && window.PigcloudModal) {
            const built = window.PigcloudModal.build('dialogConfirmTitle', 'dialog-title');
            built.overlay.id = 'dialog-modal';
            built.overlay.classList.add('dialog-modal');
            built.overlay.setAttribute('aria-describedby', 'dialog-message');
            built.overlay.style.display = 'none';
            built.header.classList.add('dialog-header');
            built.title.classList.add('dialog-title');
            built.closeBtn.id = 'dialog-close';
            built.body.classList.add('dialog-body');
            const message = document.createElement('p');
            message.id = 'dialog-message';
            message.className = 'dialog-message';
            const input = document.createElement('input');
            input.id = 'dialog-input';
            input.className = 'form-input dialog-input';
            input.setAttribute('aria-labelledby', 'dialog-title dialog-message');
            input.autocomplete = 'off';
            input.hidden = true;
            built.body.append(message, input);
            for (const [id, variant, icon, key] of [
                ['dialog-tertiary', 'is-start', 'fa-circle-info', ''],
                ['dialog-cancel', '', 'fa-xmark', 'cancel'],
                ['dialog-confirm', 'primary', 'fa-check', 'dialogConfirm'],
            ]) {
                const button = document.createElement('button');
                button.id = id;
                button.type = 'button';
                button.className = 'modal-button ' + variant;
                const glyph = document.createElement('i');
                glyph.className = 'fa-solid ' + icon;
                glyph.setAttribute('aria-hidden', 'true');
                const text = document.createElement('span');
                text.textContent = key ? window.t(key) : '';
                if (key) text.dataset.translateKey = key;
                if (id === 'dialog-tertiary') { button.hidden = true; text.className = 'dialog-tertiary-label'; }
                if (id === 'dialog-cancel') button.setAttribute('data-modal-close', '');
                button.append(glyph, text);
                built.footer.append(button);
            }
            document.body.append(built.overlay);
            this.modal = built.overlay;
        }
        this.titleEl = document.getElementById('dialog-title');
        this.messageEl = document.getElementById('dialog-message');
        this.inputEl = document.getElementById('dialog-input');
        this.confirmBtn = document.getElementById('dialog-confirm');
        this.cancelBtn = document.getElementById('dialog-cancel');
        this.tertiaryBtn = document.getElementById('dialog-tertiary');
        this.closeBtn = document.getElementById('dialog-close');

        if (!this.modal || !this.confirmBtn || !this.cancelBtn) {
            return;
        }

        this.confirmBtn.addEventListener('click', () => this.handleConfirm());
        this.cancelBtn.addEventListener('click', () => this.handleCancel());
        if (this.tertiaryBtn) {
            this.tertiaryBtn.addEventListener('click', () => this.handleTertiary());
        }
        if (this.closeBtn) {
            this.closeBtn.addEventListener('click', () => this.handleCancel());
        }
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.handleCancel();
            }
        });
        this._boundKeydown = (e) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                this.handleCancel();
            } else if (e.key === 'Enter' && this.mode !== 'prompt') {
                e.preventDefault();
                this.handleConfirm();
            } else if (e.key === 'Tab') {
                this.wrapTab(e, this.modal);
            }
        };
        if (this.inputEl) {
            this.inputEl.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.handleConfirm();
                }
            });
        }

        this.initialized = true;
    },

    show(title, message, options = {}) {
        if (!this.modal) {
            this.init();
        }
        if (!this.modal) {
            return Promise.resolve(options.mode === 'prompt' ? null : (options.mode === 'alert' ? undefined : false));
        }

        this.mode = options.mode || 'alert';
        const isDanger = options.danger === true;

        this.modal.classList.toggle('is-alert', this.mode === 'alert');
        this.confirmBtn.classList.toggle('danger', isDanger);
        this.confirmBtn.classList.toggle('primary', !isDanger);

        this.titleEl.textContent = title;
        this.messageEl.textContent = message;

        if (this.mode === 'prompt') {
            this.inputEl.hidden = false;
            this.inputEl.type = options.inputType || 'text';
            this.inputEl.value = options.defaultValue || '';
        } else {
            this.inputEl.hidden = true;
            this.inputEl.type = 'text';
            this.inputEl.value = '';
        }

        const t = window.t || function(key) { return key; };
        const confirmText = options.confirmText || t('dialogConfirm') || 'OK';
        const cancelText = options.cancelText || t('cancel') || 'Cancel';
        const confirmLabel = this.confirmBtn.querySelector('span');
        const cancelLabel = this.cancelBtn.querySelector('span');
        if (confirmLabel) {
            confirmLabel.textContent = confirmText;
        } else {
            this.confirmBtn.textContent = confirmText;
        }
        if (cancelLabel) {
            cancelLabel.textContent = cancelText;
        } else {
            this.cancelBtn.textContent = cancelText;
        }
        const confirmIcon = this.confirmBtn.querySelector('i');
        if (confirmIcon) {
            confirmIcon.classList.remove('fa-check', 'fa-trash-can', 'fa-triangle-exclamation');
            confirmIcon.classList.add(isDanger ? 'fa-triangle-exclamation' : 'fa-check');
        }

        if (this.tertiaryBtn) {
            const hasTertiary = typeof options.tertiaryText === 'string' && options.tertiaryText !== '';
            this.tertiaryBtn.hidden = !hasTertiary || this.mode === 'alert';
            if (hasTertiary) {
                const label = this.tertiaryBtn.querySelector('.dialog-tertiary-label');
                if (label) {
                    label.textContent = options.tertiaryText;
                } else {
                    this.tertiaryBtn.textContent = options.tertiaryText;
                }
            }
        }

        this.cancelBtn.hidden = this.mode === 'alert';
        this._lastFocusedElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        this.modal.style.display = 'flex';
        document.addEventListener('keydown', this._boundKeydown);

        if (typeof window.lockBodyScroll === 'function') {
            window.lockBodyScroll();
        } else {
            document.body.style.overflow = 'hidden';
        }

        if (this.mode === 'prompt') {
            this.inputEl.focus();
            this.inputEl.select();
        } else {
            this.confirmBtn.focus();
        }

        return new Promise((resolve) => {
            this.resolvePromise = resolve;
        });
    },

    handleConfirm() {
        const result = this.mode === 'prompt' ? this.inputEl.value : true;
        this.close();
        if (this.resolvePromise) {
            this.resolvePromise(result);
            this.resolvePromise = null;
        }
    },

    handleCancel() {
        const result = this.mode === 'prompt' ? null : (this.mode === 'alert' ? undefined : false);
        this.close();
        if (this.resolvePromise) {
            this.resolvePromise(result);
            this.resolvePromise = null;
        }
    },

    handleTertiary() {
        this.close();
        if (this.resolvePromise) {
            this.resolvePromise('tertiary');
            this.resolvePromise = null;
        }
    },

    close() {
        document.removeEventListener('keydown', this._boundKeydown);
        if (this.modal) {
            this.modal.style.display = 'none';
        }
        if (typeof window.unlockBodyScroll === 'function') {
            window.unlockBodyScroll();
        } else {
            document.body.style.overflow = '';
        }
        if (this._lastFocusedElement) {
            this.restoreFocus(this._lastFocusedElement);
            this._lastFocusedElement = null;
        }
    },

    alert(title, message, options = {}) {
        return this.show(title, message, {...options, mode: 'alert'});
    },

    confirm(title, message, options = {}) {
        return this.show(title, message, {...options, mode: 'confirm'});
    },

    prompt(title, message, defaultValue = '', options = {}) {
        return this.show(title, message, {...options, mode: 'prompt', defaultValue});
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => window.PigcloudDialogManager.init());
} else {
    window.PigcloudDialogManager.init();
}

(function () {
const DM = window.PigcloudDialogManager;
const MODAL_FOCUSABLE = 'a[href], button:not([disabled]):not([hidden]), textarea:not([disabled]), input:not([disabled]):not([hidden]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
const OVERLAYS = '.modal-overlay, #chat-modal, #settings-page';

function modalFocusables(modal) {
    return Array.from(modal.querySelectorAll(MODAL_FOCUSABLE)).filter(el => !el.closest('[hidden]'));
}

function isShowing(el) {
    if (el.hidden) { return false; }
    const display = el.style.display;
    return display === 'flex' || display === 'block';
}

function topmostOverlay(exclude) {
    const open = Array.from(document.querySelectorAll(OVERLAYS))
        .filter(el => el !== exclude && el.isConnected && isShowing(el));
    return open.length ? open[open.length - 1] : null;
}

DM.focusEntry = function (modal) {
    if (!modal) { return null; }
    if (!modal.hasAttribute('tabindex')) { modal.tabIndex = -1; }
    for (const el of modalFocusables(modal).concat(modal)) {
        el.focus({preventScroll: true});
        if (document.activeElement === el) { return el; }
    }
    return null;
};

DM.restoreFocus = function (node, opts) {
    if (node && node.isConnected && typeof node.focus === 'function') {
        node.focus();
        if (document.activeElement === node) { return true; }
    }
    const overlay = topmostOverlay(opts && opts.exclude);
    if (overlay) { return !!DM.focusEntry(overlay); }
    const tile = document.querySelector('#file-grid [tabindex="0"]');
    if (tile && typeof tile.focus === 'function') {
        tile.focus();
        return true;
    }
    return false;
};

DM.wrapTab = function (e, modal) {
    const focusable = modalFocusables(modal);
    if (!focusable.length) { return; }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    const outside = !active || active === modal || !modal.contains(active);
    if (e.shiftKey) {
        if (active === first || outside) { e.preventDefault(); last.focus(); }
    } else if (active === last || outside) {
        e.preventDefault();
        first.focus();
    }
};

window.trapFocusInModal = function (modal, opts) {
    const lastFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    function handler(e) {
        if (e.key === 'Tab') { DM.wrapTab(e, modal); }
    }
    modal.addEventListener('keydown', handler, true);
    if (!opts || opts.entry !== false) { DM.focusEntry(modal); }
    return function release() {
        modal.removeEventListener('keydown', handler, true);
        if (lastFocused) { DM.restoreFocus(lastFocused, {exclude: modal}); }
    };
};
})();
