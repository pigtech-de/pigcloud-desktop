import {mkdir, stat, writeFile} from 'node:fs/promises';
import {join} from 'node:path';

export const DIAGNOSTIC_LIMIT = 65536;
const EVENTS = new Set(['startup_failed', 'renderer_gone', 'renderer_reload_failed', 'native_action_failed', 'shutdown_failed']);

export function createDiagnostics(directory) {
    let queue = Promise.resolve();
    return {
        record(event) {
            const code = EVENTS.has(event) ? event : 'unknown_error';
            const line = `${new Date().toISOString()} ${code}\n`;
            queue = queue.then(async () => {
                await mkdir(directory, {recursive: true, mode: 0o700});
                const file = join(directory, 'desktop.log');
                const size = await stat(file).then(value => value.size).catch(error => {
                    if (error.code === 'ENOENT') return 0;
                    throw error;
                });
                await writeFile(file, line, {flag: size + Buffer.byteLength(line) > DIAGNOSTIC_LIMIT ? 'w' : 'a', mode: 0o600});
                return true;
            }).catch(() => false);
            return queue;
        },
    };
}
