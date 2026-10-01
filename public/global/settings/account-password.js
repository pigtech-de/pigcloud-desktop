window.PigcloudAccountPassword = (() => {
    let pending = null;

    function translate(key, fallback) {
        const value = window.t(key);
        if (value && value !== key) return value;
        return fallback || key;
    }

    function makeButton(variant, iconClass, translateKey, fallback) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = `modal-button${variant ? " " + variant : ""}`;
        const icon = document.createElement("i");
        icon.className = `fa-solid ${iconClass}`;
        icon.setAttribute("aria-hidden", "true");
        btn.appendChild(icon);
        const label = document.createElement("span");
        label.dataset.translateKey = translateKey;
        label.textContent = translate(translateKey, fallback);
        btn.appendChild(label);
        return btn;
    }

    function makeFormField(labelText, inputId, inputType, autocomplete) {
        const field = document.createElement("div");
        field.className = "form-field vstack";
        if (labelText) {
            const label = document.createElement("label");
            label.className = "form-label";
            label.setAttribute("for", inputId);
            label.textContent = labelText;
            field.appendChild(label);
        }
        const input = document.createElement("input");
        input.type = inputType;
        input.className = "form-input";
        input.id = inputId;
        if (autocomplete) input.autocomplete = autocomplete;
        field.appendChild(input);
        return {field, input};
    }

    function buildModal(opts) {
        const {overlay, content, header, title: titleEl, closeBtn, body, footer} =
            window.PigcloudModal.build("encryptionPasswordTitle", "account-password-title");
        overlay.classList.add("dialog-modal", "account-password-modal");
        overlay.setAttribute("aria-describedby", "account-password-message");
        header.classList.add("dialog-header");
        titleEl.classList.add("dialog-title");
        titleEl.textContent = opts.title || translate("encryptionPasswordTitle", "Confirm your password");
        body.classList.add("dialog-body", "stack-sm");

        const passwordSection = document.createElement("div");
        passwordSection.className = "stack-sm";
        const messageEl = document.createElement("p");
        messageEl.className = "dialog-message";
        messageEl.id = "account-password-message";
        messageEl.textContent = opts.message || translate("encryptionPasswordPrompt", "Enter your password to continue.");
        passwordSection.appendChild(messageEl);
        const {field: pwField, input: pwInput} = makeFormField(
            translate("sudoPromptPasswordLabel", "Account password"),
            "account-password-input",
            "password",
            "current-password",
        );
        passwordSection.appendChild(pwField);
        const errorEl = document.createElement("p");
        errorEl.className = "text-small status-text status-invalid";
        errorEl.id = "account-password-error";
        errorEl.setAttribute("role", "alert");
        errorEl.hidden = true;
        passwordSection.appendChild(errorEl);

        let passkeyLink = null;
        if (opts.allowPasskey) {
            const passkeyLinkP = document.createElement("p");
            passkeyLinkP.className = "text-small";
            passkeyLink = document.createElement("a");
            passkeyLink.href = "#";
            passkeyLink.className = "link";
            passkeyLink.dataset.role = "passkey-toggle";
            passkeyLink.textContent = translate("sudoPromptUsePasskey", "Use a passkey instead");
            passkeyLinkP.appendChild(passkeyLink);
            passwordSection.appendChild(passkeyLinkP);
        }

        let recoveryLinkP = null;
        if (opts.allowRecovery) {
            recoveryLinkP = document.createElement("p");
            recoveryLinkP.className = "text-small";
            const recoveryLink = document.createElement("a");
            recoveryLink.href = "#";
            recoveryLink.className = "link";
            recoveryLink.dataset.role = "recovery-toggle";
            recoveryLink.textContent = translate("e2eeRecoveryUseRecoveryKey", "Use recovery key instead");
            recoveryLinkP.appendChild(recoveryLink);
            passwordSection.appendChild(recoveryLinkP);
        }
        body.appendChild(passwordSection);

        const recoverySection = document.createElement("div");
        recoverySection.className = "stack-sm";
        recoverySection.hidden = true;
        const recPrompt = document.createElement("p");
        recPrompt.className = "dialog-message";
        recPrompt.textContent = translate("e2eeRecoveryUnlockTitle", "Enter your recovery key and set a new password.");
        recoverySection.appendChild(recPrompt);
        const {field: rkField, input: rkInput} = makeFormField(
            translate("e2eeRecoveryKeyInputLabel", "Recovery key"),
            "account-password-recovery-key",
            "text",
            "off",
        );
        rkInput.placeholder = translate("e2eeRecoveryKeyPlaceholder", "Paste your recovery key here");
        rkInput.spellcheck = false;
        recoverySection.appendChild(rkField);
        const {field: newPwField, input: newPwInput} = makeFormField(
            translate("e2eeRecoveryNewPasswordLabel", "New password"),
            "account-password-new",
            "password",
            "new-password",
        );
        recoverySection.appendChild(newPwField);
        const {field: confirmPwField, input: confirmPwInput} = makeFormField(
            translate("e2eeRecoveryConfirmPasswordLabel", "Confirm new password"),
            "account-password-confirm",
            "password",
            "new-password",
        );
        recoverySection.appendChild(confirmPwField);
        const backLinkP = document.createElement("p");
        backLinkP.className = "text-small";
        const backLink = document.createElement("a");
        backLink.href = "#";
        backLink.className = "link";
        backLink.dataset.role = "password-toggle";
        backLink.textContent = translate("e2eeRecoveryUsePassword", "Use password instead");
        backLinkP.appendChild(backLink);
        recoverySection.appendChild(backLinkP);
        body.appendChild(recoverySection);

        const cancelBtn = makeButton("", "fa-xmark", "cancel", "Cancel");
        cancelBtn.classList.add("dialog-cancel");
        cancelBtn.setAttribute("data-modal-close", "");
        const submitBtn = makeButton("primary", "fa-lock-open", "sudoPromptSubmit", "Unlock");
        submitBtn.classList.add("dialog-confirm");
        const submitLabel = submitBtn.querySelector("span");
        footer.appendChild(cancelBtn);
        footer.appendChild(submitBtn);

        return {
            overlay, content, titleEl, messageEl, errorEl,
            pwInput, rkInput, newPwInput, confirmPwInput,
            cancelBtn, submitBtn, submitLabel, closeBtn, passkeyLink,
            passwordSection, recoverySection, recoveryLinkP, backLink,
            recoveryLink: recoveryLinkP ? recoveryLinkP.querySelector("[data-role='recovery-toggle']") : null,
        };
    }

    function openPrompt(opts) {
        return new Promise((resolve) => {
            const els = buildModal(opts);
            let mode = "password";
            let outcome = null;

            const modal = window.PigcloudModal.mount({
                overlay: els.overlay,
                closeBtn: els.closeBtn,
                closers: [els.cancelBtn],
                escape: false,
                restoreFocus: true,
                onClose: () => resolve(outcome),
            });

            const finish = (result) => {
                outcome = result;
                modal.close();
            };

            const switchToRecovery = () => {
                mode = "recovery";
                els.passwordSection.hidden = true;
                els.recoverySection.hidden = false;
                els.titleEl.textContent = translate("e2eeRecoveryUnlockTitle", "Recover Encryption Keys");
                els.submitLabel.textContent = translate("e2eeRecoverySubmitButton", "Unlock and set new password");
                requestAnimationFrame(() => els.rkInput.focus());
            };

            const switchToPassword = () => {
                mode = "password";
                els.passwordSection.hidden = false;
                els.recoverySection.hidden = true;
                els.titleEl.textContent = opts.title || translate("encryptionPasswordTitle", "Confirm your password");
                els.submitLabel.textContent = translate("sudoPromptSubmit", "Unlock");
                requestAnimationFrame(() => els.pwInput.focus());
            };

            const showError = (key, fallback) => {
                els.errorEl.textContent = translate(key, fallback);
                els.errorEl.hidden = false;
            };

            const submit = () => {
                els.errorEl.hidden = true;
                if (mode === "password") {
                    const password = els.pwInput.value;
                    if (!password) {
                        showError("sudoPasswordRequired", "Password required");
                        return;
                    }
                    finish({mode: "password", password});
                    return;
                }
                const recoveryKey = els.rkInput.value.trim();
                const newPassword = els.newPwInput.value;
                const confirmPassword = els.confirmPwInput.value;
                if (!recoveryKey) {
                    showError("e2eeRecoveryKeyInputLabel", "Recovery key required");
                    return;
                }
                if (!newPassword) {
                    showError("e2eeRecoveryPasswordRequired", "Please enter a new password.");
                    return;
                }
                if (newPassword !== confirmPassword) {
                    showError("e2eeRecoveryPasswordMismatch", "Passwords do not match.");
                    return;
                }
                finish({mode: "recovery", recoveryKey, newPassword});
            };

            const onKey = (event) => {
                if (event.key === "Escape") {
                    event.preventDefault();
                    finish(null);
                    return;
                }
                if (event.key === "Enter") {
                    event.preventDefault();
                    submit();
                    return;
                }
            };

            els.submitBtn.addEventListener("click", submit);
            els.overlay.addEventListener("keydown", onKey);

            if (els.passkeyLink) {
                els.passkeyLink.addEventListener("click", (event) => {
                    event.preventDefault();
                    finish({mode: "passkey"});
                });
            }
            if (els.recoveryLink) {
                els.recoveryLink.addEventListener("click", (event) => {
                    event.preventDefault();
                    switchToRecovery();
                });
            }
            els.backLink.addEventListener("click", (event) => {
                event.preventDefault();
                switchToPassword();
            });

            requestAnimationFrame(() => els.pwInput.focus());
        });
    }

    async function requestPassword(opts = {}) {
        if (pending) return pending;
        pending = openPrompt(opts).finally(() => { pending = null; });
        return pending;
    }

    return {requestPassword};
})();
