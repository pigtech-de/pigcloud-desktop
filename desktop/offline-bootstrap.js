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
        document.body.dataset.theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
        document.body.dataset.themeAuto = '1';
        Promise.resolve(window.PigcloudSyncEngine.getAppearance?.()).then(appearance => {
            if (!appearance || appearance.theme === 'auto') return;
            const bundled = ['light', 'dark', 'mocha', 'piggy'].includes(appearance.theme);
            if (!bundled && !['light', 'dark'].includes(appearance.base)) return;
            document.body.dataset.theme = bundled ? appearance.theme : appearance.base;
            delete document.body.dataset.themeAuto;
        }).catch(err => console.warn('stored theme:', err));
        const status = document.getElementById('desktop-status');
        for (const element of document.querySelectorAll('[data-desktop-label], [data-translate-key]')) element.textContent = window.t(element.dataset.desktopLabel || element.dataset.translateKey);
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
