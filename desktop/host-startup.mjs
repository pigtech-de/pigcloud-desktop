import {mkdir, readFile, rename, rm, writeFile} from 'node:fs/promises';
import {dirname, join, isAbsolute} from 'node:path';
import {homedir} from 'node:os';
import {createLegacyStartup} from './host-legacy-startup.mjs';

export function createStartup({app, platform = process.platform, env = process.env, executable = process.execPath, legacy}) {
    const config = env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(homedir(), '.config');
    const file = join(config, 'autostart', 'de.pigcloud.desktop.desktop');
    const previousApp = legacy || createLegacyStartup({platform, config, home: homedir()});
    let current = false;
    async function apply(enabled) {
        if (!app.isPackaged && enabled) throw new Error('Install PigCloud before enabling launch on startup.');
        if (platform !== 'linux') {
            app.setLoginItemSettings({openAtLogin: enabled, path: executable, args: ['--minimized']});
            if (app.getLoginItemSettings({path: executable, args: ['--minimized']}).openAtLogin !== enabled) {
                throw new Error('The system did not save launch on startup.');
            }
        } else if (enabled) {
            if (/[\r\n\t]/.test(executable)) throw new Error('Invalid executable path.');
            const quoted = executable.replace(/[\\"`$]/g, value => `\\${value}`).replaceAll('\\', '\\\\').replaceAll('%', '%%');
            const content = `[Desktop Entry]\nType=Application\nName=PigCloud\nExec="${quoted}" --minimized\nTerminal=false\nCategories=Network;\n`;
            await mkdir(dirname(file), {recursive: true, mode: 0o700});
            const temporary = `${file}.${process.pid}.tmp`;
            await writeFile(temporary, content, {mode: 0o600});
            await rename(temporary, file);
        } else {
            await rm(file, {force: true});
        }
        current = enabled;
    }
    return {
        async initialize() {
            if (platform !== 'linux') {
                current = app.getLoginItemSettings({path: executable, args: ['--minimized']}).openAtLogin;
            } else {
                try {
                    current = (await readFile(file, 'utf8')).includes('Name=PigCloud\n');
                } catch (error) {
                    if (error.code !== 'ENOENT') throw error;
                    current = false;
                }
            }
        },
        async applyPreferences(next) {
            const previous = current;
            const legacyState = await previousApp.capture();
            if (next.launchOnStartup === previous && !legacyState) return () => Promise.resolve();
            const rollback = async () => {
                try {
                    await apply(previous);
                } finally {
                    await previousApp.restore(legacyState);
                }
            };
            try {
                await apply(next.launchOnStartup);
                if (legacyState) await previousApp.remove();
            } catch (error) {
                await rollback();
                throw error;
            }
            return rollback;
        },
    };
}
