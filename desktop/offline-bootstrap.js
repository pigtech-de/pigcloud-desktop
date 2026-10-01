(() => {
    'use strict';
    const language = navigator.language.toLowerCase().startsWith('de') ? 'de' : 'en';
    const translations = window.PigcloudDesktopTranslations[language];
    window.t = (key, replacements = {}) => {
        let value = translations[key] || key;
        for (const [name, replacement] of Object.entries(replacements)) value = value.replaceAll(`{${name}}`, String(replacement));
        return value;
    };
    document.documentElement.lang = language;
    document.addEventListener('DOMContentLoaded', async () => {
        const status = document.getElementById('desktop-status');
        for (const element of document.querySelectorAll('[data-desktop-label]')) element.textContent = window.t(element.dataset.desktopLabel);
        const cloud = document.getElementById('desktop-open-cloud');
        cloud.addEventListener('click', () => {
            cloud.disabled = true;
            window.PigcloudSyncEngine.openCloud().catch(() => {
                status.textContent = window.t('desktopOfflineError');
            }).finally(() => {cloud.disabled = false;});
        });
        try {
            const shell = window.PigcloudSettingsShell.create({defaultSection: 'sync'});
            const {tab, panel} = shell.addSection({id: 'sync', labelKey: 'settingsNavSync', icon: 'fa-sync-alt'});
            const open = () => shell.open({section: 'sync'});
            document.getElementById('desktop-open-sync').addEventListener('click', open);
            const mounting = window.PigcloudSettingsSync.mount({tab, panel});
            open();
            await mounting;
        } catch {
            status.textContent = window.t('desktopOfflineError');
        }
    });
})();
