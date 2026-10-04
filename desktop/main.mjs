import * as electron from 'electron';
import electronUpdater from 'electron-updater';
import {createDesktopHost} from './host.mjs';
import {createEngine} from './core/supervisor.mjs';
import {readFile} from 'node:fs/promises';
import {nativeStrings} from './host-tray.mjs';
import {createDiagnostics} from './diagnostics.mjs';

createDesktopHost(electron, createEngine, {updater: electronUpdater.autoUpdater}).catch(async () => {
    await electron.app.whenReady();
    await createDiagnostics(electron.app.getPath('userData')).record('startup_failed');
    const dictionaries = await readFile(new URL('bundle/translations.json', import.meta.url), 'utf8').then(JSON.parse).catch(() => ({en: {desktopNativeBootTitle: 'PigCloud', desktopNativeBootError: 'Reinstall PigCloud.'}}));
    const t = nativeStrings(dictionaries, electron.app.getLocale());
    electron.dialog.showErrorBox(t('desktopNativeBootTitle'), t('desktopNativeBootError'));
    electron.app.exit(1);
});
