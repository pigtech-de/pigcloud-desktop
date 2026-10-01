import {readFile, writeFile, rm, stat} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {join} from 'node:path';

const run = promisify(execFile);
const RUN_KEY = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const VALUE_NAME = 'PigCloudSync';

export function createLegacyStartup({platform, config, home, execute = run}) {
    const file = platform === 'darwin'
        ? join(home, 'Library', 'LaunchAgents', 'de.pigtech.pigcloudsync.plist')
        : join(config, 'autostart', 'pigcloudsync.desktop');
    async function registry(body, writable = false) {
        const script = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('${RUN_KEY}',$${writable}); try { ${body} } finally { if ($null -ne $key) { $key.Dispose() } }`;
        const result = await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
            encoding: 'utf8', windowsHide: true, timeout: 10000, maxBuffer: 65536,
        });
        return result.stdout.trim();
    }
    return {
        async capture() {
            if (platform === 'win32') {
                const text = await registry(`if ($null -ne $key -and $key.GetValueNames().Contains('${VALUE_NAME}')) { @{value=$key.GetValue('${VALUE_NAME}',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); kind=[int]$key.GetValueKind('${VALUE_NAME}')} | ConvertTo-Json -Compress }`);
                if (!text) return null;
                const value = JSON.parse(text);
                if (typeof value.value !== 'string' || ![1, 2].includes(value.kind)) throw new Error('The legacy startup registration cannot be migrated.');
                return value;
            }
            try {
                return {data: await readFile(file), mode: (await stat(file)).mode};
            } catch (error) {
                if (error.code === 'ENOENT') return null;
                throw error;
            }
        },
        async remove() {
            if (platform === 'win32') await registry(`if ($null -ne $key) { $key.DeleteValue('${VALUE_NAME}',$false) }`, true);
            else await rm(file, {force: true});
        },
        async restore(snapshot) {
            if (!snapshot) return;
            if (platform === 'win32') {
                const encoded = Buffer.from(snapshot.value, 'utf8').toString('base64');
                await registry(`if ($null -eq $key) { throw 'Startup registry key is missing.' }; $value=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')); $key.SetValue('${VALUE_NAME}',$value,[Microsoft.Win32.RegistryValueKind]${snapshot.kind})`, true);
            } else {
                await writeFile(file, snapshot.data, {mode: snapshot.mode});
            }
        },
    };
}
