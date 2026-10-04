import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { ConfigStore, normalizeRemote, normalizeLocal } from './config.mjs';
import { locateCli, CliRunner } from './cli.mjs';
import { readAccount, listRegistry, findPairEntry, DESKTOP_ENDPOINT } from './registry.mjs';
import { requestDaemon } from './ipc.mjs';
import { SyncError, publicError, requireObject, requireString } from './errors.mjs';

const STATE_RANK = ['stopped', 'running', 'starting', 'locked', 'mismatch', 'stale', 'failed', 'notConfigured', 'noCli', 'unsupportedEndpoint'];
const COUNT_FIELDS = {
    pendingCount: 'pending_count', failedCount: 'failed_count', failedDownloadCount: 'failed_download_count',
    deferredCount: 'deferred_count', nextDueSeconds: 'next_due_seconds', cacheUsed: 'cache_used', cacheMax: 'cache_max',
};

function projectStatus(raw) {
    const status = { online: raw.online === true, lastPoll: raw.last_poll || '', uptime: raw.uptime || '' };
    for (const [field, wire] of Object.entries(COUNT_FIELDS)) status[field] = Math.max(0, raw[wire] || 0);
    return status;
}

function preferences(config) {
    return { launchOnStartup: config.launch_on_startup, minimizeToTray: config.minimize_to_tray,
        allowPrerelease: config.allow_prerelease === true };
}

export function createEngine(options) {
    return new SyncSupervisor(options);
}

export class SyncSupervisor {
    constructor({ directory, store = new ConfigStore({ directory }), bundledCliPath,
        locate = locateCli, runnerFactory = executable => new CliRunner(executable),
        accountReader = readAccount, registryReader = listRegistry, request = requestDaemon,
        platform = process.platform, applyPreferences = async () => null,
        polling = true, wait = delay, stopAttempts = 240 } = {}) {
        this.store = store;
        this.bundledCliPath = bundledCliPath;
        this.locate = locate;
        this.runnerFactory = runnerFactory;
        this.accountReader = accountReader;
        this.registryReader = registryReader;
        this.request = request;
        this.platform = platform;
        this.applyPreferences = applyPreferences;
        this.polling = polling;
        this.wait = wait;
        this.stopAttempts = stopAttempts;
        this.queue = Promise.resolve();
        this.listeners = new Set();
        this.pairs = [];
        this.account = null;
        this.accountKey = '';
        this.cliPath = null;
        this.runner = null;
        this.notice = null;
        this.timer = null;
        this.closing = false;
        this.initialized = false;
        this.sequence = 0;
        this.probe = null;
        this.unsupportedEndpoint = false;
        this.loginController = null;
        this.loginPromise = null;
    }

    enqueue(operation) {
        if (this.closing) return Promise.reject(new SyncError('shutdown'));
        const pending = this.queue.then(operation).catch(error => {
            throw error instanceof SyncError ? error : new SyncError('unavailable');
        });
        this.queue = pending.catch(() => null);
        return pending;
    }

    initialize() {
        return this.enqueue(async () => {
            if (this.initialized) return this.snapshot();
            await this.store.load();
            this.initialized = true;
            await this.refresh();
            this.schedule();
            return this.snapshot();
        });
    }

    schedule() {
        clearTimeout(this.timer);
        if (!this.polling || this.closing) return;
        this.timer = setTimeout(() => {
            this.status().catch(error => {
                this.notice = publicError(error);
                this.publish();
            }).finally(() => this.schedule());
        }, this.store.current.poll_interval * 1000);
        this.timer.unref?.();
    }

    async discover() {
        const account = await this.accountReader(this.store.directory);
        const key = account ? `${account.endpoint}|${account.owner}` : '';
        if (key !== this.accountKey) {
            this.pairs = [];
            this.probe = null;
            this.accountKey = key;
            this.store.revision++;
        }
        this.unsupportedEndpoint = !!account && account.endpoint !== DESKTOP_ENDPOINT;
        this.account = this.unsupportedEndpoint || !account?.owner ? null : account;
        const cliPath = await this.locate({ override: this.store.current.pc_path, bundledCliPath: this.bundledCliPath });
        if (cliPath !== this.cliPath) {
            this.cliPath = cliPath;
            this.runner = cliPath ? this.runnerFactory(cliPath) : null;
            this.probe = null;
        }
        this.reconcile();
    }

    requireAccount() {
        if (this.unsupportedEndpoint) throw new SyncError('unsupportedEndpoint');
        if (!this.account) throw new SyncError('notConfigured');
    }

    reconcile() {
        this.pairs = this.store.current.pairs.map(config => {
            const previous = this.pairs.find(pair => normalizeRemote(pair.config.remote_path) === normalizeRemote(config.remote_path)
                && normalizeLocal(pair.config.mount_point, this.platform) === normalizeLocal(config.mount_point, this.platform));
            if (previous) {
                previous.config = config;
                return previous;
            }
            return { id: randomUUID(), config, state: 'stopped', error: null, status: null };
        });
    }

    async unlocked(force = false) {
        if (!this.runner || !this.account) return false;
        if (!force && this.probe && Date.now() - this.probe.at < 30000) return this.probe.value;
        const value = await this.runner.probe();
        this.probe = { value, at: Date.now() };
        return value;
    }

    async refresh() {
        await this.discover();
        let entries;
        try {
            entries = await this.registryReader(this.store.directory);
        } catch {
            this.notice = publicError(new SyncError('unavailable'));
            for (const pair of this.pairs) {
                pair.state = 'stale';
                pair.status = null;
            }
            this.publish();
            return;
        }
        for (const pair of this.pairs) {
            pair.status = null;
            if (this.unsupportedEndpoint) pair.state = 'unsupportedEndpoint';
            else if (!this.runner) pair.state = 'noCli';
            else if (!this.account) pair.state = 'notConfigured';
            else {
                const entry = findPairEntry(entries, pair.config, this.account, this.platform);
                if (!entry) {
                    const incompatible = entries.some(item => normalizeRemote(item.remote_path) === normalizeRemote(pair.config.remote_path));
                    pair.state = incompatible ? 'mismatch' : await this.unlocked() ? 'stopped' : 'locked';
                } else {
                    try {
                        const raw = await this.request(entry, 'status');
                        if (raw.mode !== 'sync' || normalizeRemote(raw.remote_path) !== normalizeRemote(pair.config.remote_path)
                            || normalizeLocal(raw.mount_point, this.platform) !== normalizeLocal(pair.config.mount_point, this.platform)) {
                            throw new SyncError('identityMismatch');
                        }
                        pair.status = projectStatus(raw);
                        pair.state = 'running';
                    } catch (error) {
                        pair.state = error.code === 'identityMismatch' ? 'mismatch' : 'stale';
                    }
                }
            }
        }
        this.publish();
    }

    snapshot() {
        const pairs = this.pairs.map(pair => ({
            id: pair.id, remotePath: pair.config.remote_path, mountPoint: pair.config.mount_point,
            state: pair.state, error: pair.error, status: pair.status,
        }));
        let state = this.unsupportedEndpoint ? 'unsupportedEndpoint' : this.runner ? this.account ? 'stopped' : 'notConfigured' : 'noCli';
        for (const pair of pairs) if (STATE_RANK.indexOf(pair.state) > STATE_RANK.indexOf(state)) state = pair.state;
        const result = { revision: this.store.revision, sequence: this.sequence, state,
            notice: this.notice || (this.store.notice ? publicError(new SyncError(this.store.notice)) : null),
            cliAvailable: !!this.cliPath, accountOwner: this.account?.owner || '', pairs };
        return structuredClone(result);
    }

    publish() {
        this.sequence++;
        const snapshot = this.snapshot();
        for (const listener of this.listeners) {
            try {
                listener(structuredClone(snapshot));
            } catch {
                this.listeners.delete(listener);
            }
        }
    }

    subscribe(callback) {
        if (typeof callback !== 'function') throw new SyncError('invalidArgument');
        this.listeners.add(callback);
        return () => this.listeners.delete(callback);
    }

    status() {
        return this.enqueue(async () => {
            await this.refresh();
            return this.snapshot();
        });
    }

    settings() {
        return { revision: this.store.revision,
            pairs: this.pairs.map(pair => ({ id: pair.id, remotePath: pair.config.remote_path, mountPoint: pair.config.mount_point })),
            pollInterval: this.store.current.poll_interval, ...preferences(this.store.current),
            cliAvailable: !!this.cliPath, cliPath: this.cliPath, accountOwner: this.account?.owner || '' };
    }

    getSettings() {
        return this.enqueue(async () => {
            await this.discover();
            return this.settings();
        });
    }

    saveSettings(settings) {
        return this.enqueue(async () => {
            await this.discover();
            if (settings?.revision !== this.store.revision) throw new SyncError('staleSettings');
            const candidate = this.store.candidate(settings);
            const removed = this.pairs.some(pair => !candidate.pairs.some(item => normalizeRemote(item.remote_path) === normalizeRemote(pair.config.remote_path)
                && normalizeLocal(item.mount_point, this.platform) === normalizeLocal(pair.config.mount_point, this.platform)));
            const rollback = await this.applyPreferences(preferences(candidate), preferences(this.store.current));
            try {
                await this.store.save(candidate, settings.revision);
            } catch (error) {
                if (typeof rollback === 'function') {
                    try { await rollback(); } catch { this.notice = { code: 'preferencesRollbackFailed', message: 'Settings were not saved, and startup preferences could not be restored.' }; }
                }
                throw error;
            }
            this.reconcile();
            if (removed) this.notice = { code: 'pairRemoved', message: 'Removed mappings no longer appear here. Their running daemons remain active until Stop All.' };
            this.schedule();
            this.publish();
            return this.settings();
        });
    }

    reportAppearance(appearance) {
        return this.enqueue(() => this.store.saveAppearance(appearance));
    }

    setCliPath(executable) {
        return this.enqueue(async () => {
            if (executable !== null) requireString(executable);
            await this.store.save({ ...this.store.current, pc_path: executable }, this.store.revision);
            await this.refresh();
            return this.settings();
        });
    }

    pair(args, optional = false) {
        requireObject(args, ['pairId']);
        if (optional && args.pairId === undefined) return null;
        requireString(args.pairId, { max: 100 });
        const pair = this.pairs.find(item => item.id === args.pairId);
        if (!pair) throw new SyncError('stalePair');
        return pair;
    }

    folderPath(args) {
        return this.enqueue(async () => {
            await this.discover();
            return this.pair(args).config.mount_point;
        });
    }

    start(args = {}) {
        return this.enqueue(async () => {
            await this.discover();
            const pair = this.pair(args, true);
            if (!this.runner) throw new SyncError('noCli');
            this.requireAccount();
            if (!await this.unlocked(true)) throw new SyncError('locked');
            this.notice = null;
            const failures = [];
            for (const item of pair ? [pair] : this.pairs) {
                item.state = 'starting';
                item.error = null;
                this.publish();
                try {
                    await this.runner.start(item.config);
                } catch (error) {
                    item.state = 'failed';
                    item.error = publicError(error);
                    failures.push({ pairId: item.id, error: item.error });
                }
            }
            await this.refresh();
            for (const item of pair ? [pair] : this.pairs) {
                if (item.state !== 'running' && !failures.some(failure => failure.pairId === item.id)) {
                    item.error = publicError(new SyncError('unavailable'));
                    failures.push({ pairId: item.id, error: item.error });
                }
            }
            if (failures.length) this.notice = { code: 'startFailed', message: 'Some sync folders could not start.', failures };
            this.publish();
            return { ok: failures.length === 0, failures, status: this.snapshot() };
        });
    }

    unlock(args) {
        return this.enqueue(async () => {
            requireObject(args, ['password']);
            requireString(args.password, { max: 4096 });
            await this.discover();
            if (!this.runner) throw new SyncError('noCli');
            this.requireAccount();
            try {
                await this.runner.unlock(args.password);
            } catch {
                throw new SyncError('unlockFailed');
            }
            this.probe = { value: true, at: Date.now() };
            await this.refresh();
            return { ok: true };
        });
    }

    async stopEntry(entry) {
        await this.request(entry, 'shutdown');
        for (let attempt = 0; attempt < this.stopAttempts; attempt++) {
            await this.wait(250);
            try {
                await this.request(entry, 'ping');
            } catch (error) {
                if (error.code === 'unavailable') return;
                throw error;
            }
        }
        throw new SyncError('daemonFailed');
    }

    stop(args = {}) {
        return this.enqueue(async () => {
            await this.discover();
            const pair = this.pair(args, true);
            if (pair) this.requireAccount();
            const entries = await this.registryReader(this.store.directory);
            const found = pair ? findPairEntry(entries, pair.config, this.account, this.platform) : null;
            if (pair && !found && entries.some(entry => normalizeRemote(entry.remote_path) === normalizeRemote(pair.config.remote_path))) {
                throw new SyncError('identityMismatch');
            }
            const targets = pair ? found ? [found] : [] : entries;
            const failures = [];
            for (const entry of targets) {
                try {
                    await this.stopEntry(entry);
                } catch (error) {
                    const configured = this.pairs.find(item => findPairEntry([entry], item.config, this.account, this.platform));
                    failures.push({ pairId: configured?.id || null, error: publicError(error) });
                }
            }
            this.notice = failures.length ? { code: 'stopFailed', message: 'Some sync daemons could not stop.', failures } : null;
            await this.refresh();
            return { ok: failures.length === 0, stoppedCount: targets.length - failures.length, failures, status: this.snapshot() };
        });
    }

    async entryFor(pair) {
        this.requireAccount();
        const entries = await this.registryReader(this.store.directory);
        const entry = findPairEntry(entries, pair.config, this.account, this.platform);
        if (!entry) throw new SyncError('unavailable');
        return entry;
    }

    readFeed(action, args) {
        return this.enqueue(async () => {
            await this.discover();
            const pair = this.pair(args);
            const entry = await this.entryFor(pair);
            const response = await this.request(entry, action);
            const result = { pairId: pair.id, revision: this.store.revision };
            if (action === 'activity') {
                result.activity = (response.activity || []).map(item => ({
                    path: item.path, direction: item.direction, bytes: item.bytes, timestamp: item.timestamp, error: item.error || '',
                }));
            } else {
                result[action] = (response.files || []).map(item => ({
                    path: item.path, status: item.status, dirty: item.dirty || false, size: item.size || 0,
                    pinned: item.pinned || false, reason: item.reason || '',
                }));
            }
            return result;
        });
    }

    activity(args) { return this.readFeed('activity', args); }
    conflicts(args) { return this.readFeed('conflicts', args); }
    files(args) { return this.readFeed('files', args); }

    mutateDaemon(action, args) {
        return this.enqueue(async () => {
            requireObject(args, action === 'resolve' ? ['pairId', 'path', 'choice'] : action === 'retry' ? ['pairId', 'path'] : ['pairId']);
            if (action === 'resolve') {
                requireString(args.path);
                if (!['local', 'remote', 'both'].includes(args.choice)) throw new SyncError('invalidArgument');
            } else if (args.path !== undefined) requireString(args.path, { empty: true });
            await this.discover();
            const pair = this.pair({ pairId: args.pairId });
            const entry = await this.entryFor(pair);
            const fields = {};
            if (args.path) fields.path = args.path;
            if (action === 'resolve') {
                const conflicts = await this.request(entry, 'conflicts');
                if (!conflicts.files?.some(item => item.path === args.path && item.status === 'conflict')) throw new SyncError('stalePair');
                fields.choice = args.choice;
            }
            const response = await this.request(entry, action, fields);
            return { ok: true, pairId: pair.id, retried: response.retried || 0,
                deferredCount: response.deferred_count || 0, nextDueSeconds: response.next_due_seconds || 0 };
        });
    }

    resolve(args) { return this.mutateDaemon('resolve', args); }
    retry(args) { return this.mutateDaemon('retry', args); }
    flush(args) { return this.mutateDaemon('flush', args); }

    loginCli({ openVerification, signal } = {}) {
        if (this.loginPromise) return this.loginPromise;
        if (typeof openVerification !== 'function') return Promise.reject(new SyncError('invalidArgument'));
        const controller = new AbortController();
        this.loginController = controller;
        const abort = () => controller.abort();
        if (signal?.aborted) abort();
        signal?.addEventListener('abort', abort, { once: true });
        const pending = (async () => {
            const runner = await this.enqueue(async () => {
                await this.discover();
                if (this.unsupportedEndpoint) throw new SyncError('unsupportedEndpoint');
                if (!this.runner) throw new SyncError('noCli');
                return this.runner;
            });
            await runner.loginDevice({ openVerification, signal: controller.signal });
            return this.enqueue(async () => {
                await this.refresh();
                this.requireAccount();
                return { ok: true, status: this.snapshot() };
            });
        })().finally(() => {
            signal?.removeEventListener('abort', abort);
            this.loginController = null;
            this.loginPromise = null;
        });
        this.loginPromise = pending;
        return pending;
    }

    cancelLoginCli() {
        this.loginController?.abort();
        return { ok: true };
    }

    async dispose() {
        this.closing = true;
        this.cancelLoginCli();
        if (this.loginPromise) await this.loginPromise.catch(() => null);
        clearTimeout(this.timer);
        await this.queue;
        this.listeners.clear();
    }
}
