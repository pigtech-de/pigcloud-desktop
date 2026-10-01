import { spawn, execFile } from 'node:child_process';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { SyncError, requireString } from './errors.mjs';

function terminateProcess(child) {
    if (process.platform === 'win32' && child.pid) {
        return new Promise(resolve => {
            execFile(path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'),
                ['/pid', String(child.pid), '/t', '/f'], { windowsHide: true, timeout: 5000 }, () => resolve());
        });
    }
    try {
        if (child.pid) process.kill(-child.pid, 'SIGKILL');
        else child.kill();
    } catch {
        return Promise.resolve();
    }
    return Promise.resolve();
}

export async function locateCli({ override, bundledCliPath, platform = process.platform, env = process.env, home = os.homedir(), io = fs } = {}) {
    const windows = platform === 'win32';
    const paths = windows ? path.win32 : path.posix;
    const exe = windows ? 'pc.exe' : 'pc';
    const defaults = windows
        ? [paths.join(env.LOCALAPPDATA || paths.join(home, 'AppData', 'Local'), 'pigcloud', exe)]
        : ['/usr/local/bin/pc', paths.join(home, '.local', 'bin', exe)];
    const candidates = [override, bundledCliPath,
        ...(env.PATH || '').split(windows ? ';' : ':').filter(Boolean).map(dir => paths.join(dir.trim(), exe)), ...defaults];
    for (const candidate of candidates) {
        if (!candidate || !paths.isAbsolute(candidate)) continue;
        try {
            if (!(await io.stat(candidate)).isFile()) continue;
            await io.access(candidate, windows ? fs.constants.F_OK : fs.constants.X_OK);
            return candidate;
        } catch {
            continue;
        }
    }
    return null;
}

export class CliRunner {
    constructor(executable, { spawnProcess = spawn, outputLimit = 1024 * 1024, killProcess = terminateProcess } = {}) {
        this.executable = executable;
        this.spawnProcess = spawnProcess;
        this.outputLimit = outputLimit;
        this.killProcess = killProcess;
    }

    run(args, { stdin = '', timeoutMs = 30000, signal, onLine } = {}) {
        return new Promise((resolve, reject) => {
            if (signal?.aborted) { reject(new SyncError('loginCancelled')); return; }
            let child;
            let settled = false;
            let bytes = 0;
            let timer;
            let stopping = false;
            let lines = '';
            let callbacks = Promise.resolve();
            let abort;
            const finish = error => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                if (abort) signal?.removeEventListener('abort', abort);
                if (error) reject(error);
                else resolve();
            };
            try {
                child = this.spawnProcess(this.executable, args, {
                    shell: false, windowsHide: true, detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'],
                });
            } catch {
                finish(new SyncError('cliFailed'));
                return;
            }
            const stop = code => {
                if (stopping || settled) return;
                stopping = true;
                this.killProcess(child).then(() => finish(new SyncError(code)), () => finish(new SyncError(code)));
            };
            timer = setTimeout(() => stop('cliTimeout'), timeoutMs);
            abort = () => stop('loginCancelled');
            signal?.addEventListener('abort', abort, { once: true });
            for (const stream of [child.stdout, child.stderr]) {
                stream.on('data', chunk => {
                    bytes += chunk.length;
                    if (bytes > this.outputLimit) stop('cliOutputLimit');
                });
                stream.on('error', () => stop('cliFailed'));
            }
            if (onLine) child.stdout.on('data', chunk => {
                if (stopping || settled) return;
                lines += chunk.toString('utf8');
                const complete = lines.split('\n');
                lines = complete.pop();
                for (const line of complete) callbacks = callbacks.then(() => {
                    if (!stopping && !settled) return onLine(line);
                });
                callbacks.catch(() => stop('loginFailed'));
            });
            child.once('error', () => finish(new SyncError('cliFailed')));
            child.once('close', code => {
                callbacks.then(() => {
                    if (!stopping) finish(code === 0 ? null : new SyncError('cliFailed'));
                }, () => stop('loginFailed'));
            });
            child.stdin.on('error', () => stop('cliFailed'));
            child.stdin.end(stdin);
        });
    }

    async probe() {
        try {
            await this.run(['uk', '--stdin'], { timeoutMs: 15000 });
            return true;
        } catch {
            return false;
        }
    }

    unlock(password) {
        requireString(password, { max: 4096 });
        return this.run(['uk', '--stdin'], { stdin: password + '\n' });
    }

    async start(pair) {
        const flags = pair.sync_dir ? ['--sync-dir', pair.sync_dir] : [];
        let moveRequired = false;
        try {
            await this.run(['mn', 'start', '--json', ...flags, '--', pair.remote_path, pair.mount_point], {
                timeoutMs: 120000,
                onLine: line => {
                    try {
                        const result = JSON.parse(line);
                        if (result.success === false && result.code === 'sync_folder_move_required') moveRequired = true;
                    } catch {
                        return;
                    }
                },
            });
        } catch (error) {
            if (moveRequired) throw new SyncError('moveRequired');
            throw error;
        }
    }

    async loginDevice({ openVerification, signal, timeoutMs = 930000 }) {
        let authorized = false;
        let complete = false;
        try {
            await this.run(['li', '--device', '--json', '--quiet'], { signal, timeoutMs, onLine: async line => {
                const event = JSON.parse(line);
                if (event.event === 'login_complete' && authorized && !complete && Object.keys(event).length === 1) {
                    complete = true;
                    return;
                }
                if (authorized || complete || event.event !== 'device_authorization'
                    || Object.keys(event).sort().join(',') !== 'event,userCode,verificationUrl') throw new SyncError('loginFailed');
                const url = new URL(event.verificationUrl);
                const query = [...url.searchParams];
                const fragment = new URLSearchParams(url.hash.slice(1));
                if (url.origin !== 'https://pigcloud.de' || url.pathname !== '/activate' || url.username || url.password
                    || query.length !== 1 || query[0][0] !== 'code' || query[0][1] !== event.userCode
                    || typeof event.userCode !== 'string' || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/u.test(event.userCode)
                    || [...fragment].length !== 1 || !/^[A-Za-z0-9_-]{43}$/u.test(fragment.get('k') || '')) throw new SyncError('loginFailed');
                authorized = true;
                await openVerification({ verificationUrl: url.href, userCode: event.userCode });
            } });
        } catch (error) {
            if (error.code === 'loginCancelled') throw error;
            throw new SyncError(error.code === 'cliTimeout' ? 'loginTimeout' : 'loginFailed');
        }
        if (!authorized || !complete) throw new SyncError('loginFailed');
    }
}
