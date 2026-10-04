import * as fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { SyncError, requireObject, requireString } from './errors.mjs';

export const DEFAULT_SETTINGS = Object.freeze({
    pairs: [], poll_interval: 5, launch_on_startup: true, minimize_to_tray: true, pc_path: null,
    allow_prerelease: false, appearance: null,
});

const THEME_ID = /^[a-z][a-z0-9-]{0,39}$/u;
const HEX_COLOR = /^#[0-9a-f]{6}$/iu;

export function validateAppearance(raw) {
    if (raw === null || raw === undefined) return null;
    if (typeof raw !== 'object' || Array.isArray(raw)) throw new SyncError('invalidArgument');
    if (!THEME_ID.test(String(raw.theme))) throw new SyncError('invalidArgument');
    if (raw.base !== 'light' && raw.base !== 'dark') throw new SyncError('invalidArgument');
    if (!HEX_COLOR.test(String(raw.background)) || !HEX_COLOR.test(String(raw.surface))) {
        throw new SyncError('invalidArgument');
    }
    return { theme: raw.theme, base: raw.base, background: raw.background.toUpperCase(), surface: raw.surface.toUpperCase() };
}

export function configDirectory({ platform = process.platform, env = process.env, home = os.homedir() } = {}) {
    return platform === 'win32'
        ? path.win32.join(env.APPDATA || path.win32.join(home, 'AppData', 'Roaming'), 'pigcloud')
        : path.posix.join(env.XDG_CONFIG_HOME || path.posix.join(home, '.config'), 'pigcloud');
}

export function normalizeRemote(remote) {
    return remote.startsWith('/') ? remote.slice(1) : remote;
}

export function normalizeLocal(local, platform = process.platform) {
    const paths = platform === 'win32' ? path.win32 : path.posix;
    const normalized = paths.normalize(local);
    const stripped = normalized.replace(/[\\/]+$/u, '') || paths.parse(normalized).root;
    return platform === 'win32' ? stripped.toLowerCase() : stripped;
}

function validatePair(pair, platform) {
    if (!pair || typeof pair !== 'object' || Array.isArray(pair)) throw new SyncError('invalidArgument');
    const remote = requireString(pair.remote_path, { empty: true });
    const local = requireString(pair.mount_point);
    const paths = platform === 'win32' ? path.win32 : path.posix;
    if ((!paths.isAbsolute(local) && !(platform === 'win32' && /^[a-z]:$/iu.test(local)))
        || normalizeRemote(remote).split('/').some(part => part === '.' || part === '..')
        || remote.includes('\\') || remote.startsWith('//')) throw new SyncError('invalidArgument');
    if (pair.sync_dir !== undefined && (typeof pair.sync_dir !== 'string' || !paths.isAbsolute(pair.sync_dir)
        || normalizeLocal(pair.sync_dir, platform) !== normalizeLocal(local, platform))) throw new SyncError('invalidArgument');
    return { ...pair, remote_path: remote || '/', mount_point: local };
}

function appearanceOrNull(raw) {
    try {
        return validateAppearance(raw);
    } catch {
        return null;
    }
}

export function validateConfig(raw, platform = process.platform) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new SyncError('invalidArgument');
    const config = { ...DEFAULT_SETTINGS, ...raw };
    if (!Array.isArray(config.pairs) || config.pairs.length > 100) throw new SyncError('invalidArgument');
    config.pairs = config.pairs.map(pair => validatePair(pair, platform));
    if (raw.pair && typeof raw.pair === 'object' && raw.pair.mount_point) {
        const legacy = validatePair(raw.pair, platform);
        if (!config.pairs.some(pair => normalizeLocal(pair.mount_point, platform) === normalizeLocal(legacy.mount_point, platform))) {
            config.pairs.unshift(legacy);
        }
    }
    delete config.pair;
    const remotes = config.pairs.map(pair => normalizeRemote(pair.remote_path));
    const locals = config.pairs.map(pair => normalizeLocal(pair.mount_point, platform));
    if (new Set(remotes).size !== remotes.length || new Set(locals).size !== locals.length) {
        throw new SyncError('invalidArgument');
    }
    if (!Number.isInteger(config.poll_interval)) throw new SyncError('invalidArgument');
    config.poll_interval = Math.max(5, Math.min(3600, config.poll_interval));
    for (const field of ['launch_on_startup', 'minimize_to_tray', 'allow_prerelease']) {
        if (typeof config[field] !== 'boolean') throw new SyncError('invalidArgument');
    }
    if (config.pc_path !== null) requireString(config.pc_path);
    config.appearance = appearanceOrNull(config.appearance);
    return config;
}

export async function readAppearance({ directory = configDirectory(), io = fs } = {}) {
    try {
        return validateAppearance(JSON.parse(await io.readFile(path.join(directory, 'sync.json'), 'utf8')).appearance);
    } catch {
        return null;
    }
}

export class ConfigStore {
    constructor({ directory = configDirectory(), io = fs, platform = process.platform } = {}) {
        this.directory = directory;
        this.io = io;
        this.platform = platform;
        this.file = path.join(directory, 'sync.json');
        this.current = structuredClone(DEFAULT_SETTINGS);
        this.revision = 0;
        this.notice = null;
        this.writable = true;
    }

    async load() {
        try {
            this.current = validateConfig(JSON.parse(await this.io.readFile(this.file, 'utf8')), this.platform);
        } catch (error) {
            if (error.code === 'ENOENT') return this.snapshot();
            this.notice = 'configUnreadable';
            this.writable = false;
            if (error instanceof SyntaxError || error instanceof SyncError) {
                try {
                    await this.io.rename(this.file, `${this.file}.${randomUUID()}.bad`);
                    this.writable = true;
                } catch {
                    this.writable = false;
                }
            }
        }
        return this.snapshot();
    }

    snapshot() {
        return { revision: this.revision, config: structuredClone(this.current), notice: this.notice };
    }

    async write(next) {
        const temp = `${this.file}.${randomUUID()}.tmp`;
        let handle;
        try {
            await this.io.mkdir(this.directory, { recursive: true, mode: 0o700 });
            handle = await this.io.open(temp, 'wx', 0o600);
            await handle.writeFile(JSON.stringify(next, null, 2) + '\n', 'utf8');
            await handle.sync();
            await handle.close();
            handle = null;
            await this.io.rename(temp, this.file);
        } catch {
            if (handle) await handle.close().catch(() => null);
            await this.io.unlink(temp).catch(() => null);
            throw new SyncError('saveFailed');
        }
        this.current = next;
    }

    async save(candidate, revision) {
        if (revision !== this.revision) throw new SyncError('staleSettings');
        if (!this.writable) throw new SyncError('configUnreadable');
        await this.write(validateConfig(candidate, this.platform));
        this.revision++;
        this.notice = null;
        return this.snapshot();
    }

    async saveAppearance(appearance) {
        const next = validateAppearance(appearance);
        if (!this.writable) throw new SyncError('configUnreadable');
        if (JSON.stringify(this.current.appearance) === JSON.stringify(next)) return next;
        await this.write({ ...structuredClone(this.current), appearance: next });
        return next;
    }

    candidate(settings) {
        requireObject(settings, ['revision', 'pairs', 'pollInterval', 'launchOnStartup', 'minimizeToTray', 'allowPrerelease']);
        if (!Array.isArray(settings.pairs)) throw new SyncError('invalidArgument');
        const next = structuredClone(this.current);
        next.pairs = settings.pairs.map(pair => {
            requireObject(pair, ['id', 'remotePath', 'mountPoint']);
            const old = next.pairs.find(item => normalizeRemote(item.remote_path) === normalizeRemote(requireString(pair.remotePath, { empty: true })));
            const unchanged = old && normalizeLocal(old.mount_point, this.platform) === normalizeLocal(requireString(pair.mountPoint), this.platform);
            return { ...old, remote_path: pair.remotePath, mount_point: pair.mountPoint,
                ...(!unchanged ? { sync_dir: pair.mountPoint } : {}) };
        });
        next.poll_interval = settings.pollInterval;
        next.launch_on_startup = settings.launchOnStartup;
        next.minimize_to_tray = settings.minimizeToTray;
        next.allow_prerelease = settings.allowPrerelease ?? next.allow_prerelease ?? false;
        return validateConfig(next, this.platform);
    }
}
