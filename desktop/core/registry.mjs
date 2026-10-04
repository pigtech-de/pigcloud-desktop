import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { decodeWire } from './wire.mjs';
import { normalizeRemote, normalizeLocal } from './config.mjs';

export const DESKTOP_ENDPOINT = 'https://pigcloud.de/cloud/actions.php';
const LEGACY_ENDPOINT = 'https://pigtech.de/cloud/actions.php';

export function canonicalEndpoint(value) {
    return value === LEGACY_ENDPOINT ? DESKTOP_ENDPOINT : value;
}

export async function readAccount(directory, io = fs) {
    try {
        const stat = await io.stat(path.join(directory, 'config.json'));
        if (stat.size > 1024 * 1024) return null;
        const raw = JSON.parse(await io.readFile(path.join(directory, 'config.json'), 'utf8'));
        const endpoint = typeof raw.endpoint === 'string' ? canonicalEndpoint(raw.endpoint) : DESKTOP_ENDPOINT;
        if (endpoint !== DESKTOP_ENDPOINT) return { owner: '', endpoint };
        if (typeof raw.public_key !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/u.test(raw.public_key)) return null;
        const key = Buffer.from(raw.public_key, 'base64');
        if (key.length !== 32 || key.toString('base64') !== raw.public_key) return null;
        const parsed = new URL(endpoint);
        if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
        return { owner: createHash('sha256').update(key).digest('hex').slice(0, 16), endpoint };
    } catch {
        return null;
    }
}

export async function listRegistry(directory, io = fs) {
    let names;
    try {
        names = (await io.readdir(path.join(directory, 'mounts.d'))).filter(name => name.endsWith('.json')).sort();
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        names = [];
    }
    const files = [...names.slice(0, 1000).map(name => path.join(directory, 'mounts.d', name)), path.join(directory, 'mount.json')];
    const entries = [];
    const seen = new Set();
    for (const file of files) {
        try {
            if ((await io.stat(file)).size > 65536) continue;
            const entry = decodeWire('MountInfo', JSON.parse(await io.readFile(file, 'utf8')));
            if (entry.port < 1 || entry.port > 65535 || !entry.token || entry.pid < 1) continue;
            const identity = `${entry.port}:${entry.token}`;
            if (!seen.has(identity)) entries.push(entry);
            seen.add(identity);
        } catch {
            continue;
        }
    }
    return entries;
}

export function matchesPair(entry, pair, account, platform = process.platform) {
    return !!account?.owner && account.endpoint === DESKTOP_ENDPOINT && canonicalEndpoint(entry.endpoint) === DESKTOP_ENDPOINT
        && entry.owner === account.owner && entry.mode === 'sync'
        && normalizeRemote(entry.remote_path) === normalizeRemote(pair.remote_path)
        && normalizeLocal(entry.mount_point, platform) === normalizeLocal(pair.mount_point, platform)
        && (!pair.sync_dir || normalizeLocal(entry.sync_dir, platform) === normalizeLocal(pair.sync_dir, platform));
}

export function findPairEntry(entries, pair, account, platform) {
    return entries.find(entry => matchesPair(entry, pair, account, platform)) || null;
}
