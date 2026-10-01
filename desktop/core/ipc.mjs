import net from 'node:net';
import { decodeWire, encodeWire, MOUNT_PROTOCOL } from './wire.mjs';
import { SyncError } from './errors.mjs';

const ACTIONS = new Set(['ping', 'status', 'shutdown', 'flush', 'files', 'conflicts', 'activity', 'resolve', 'retry']);

export function requestDaemon(entry, action, fields = {}, { connect = net.createConnection, maxBytes = 4 * 1024 * 1024 } = {}) {
    if (!ACTIONS.has(action) || !Number.isInteger(entry.port) || entry.port < 1 || entry.port > 65535) {
        return Promise.reject(new SyncError('invalidArgument'));
    }
    const payload = encodeWire('DaemonRequest', { token: entry.token, action, ...fields }) + '\n';
    return new Promise((resolve, reject) => {
        let socket;
        let settled = false;
        let timer;
        let chunks = [];
        let bytes = 0;
        const finish = (error, response) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (socket) socket.destroy();
            chunks = [];
            if (error) reject(error);
            else resolve(response);
        };
        const parse = () => {
            try {
                const raw = Buffer.concat(chunks).toString('utf8');
                const response = decodeWire('DaemonResponse', JSON.parse(raw));
                if (!response.ok || response.error) finish(new SyncError('daemonFailed'));
                else finish(null, response);
            } catch {
                finish(new SyncError('invalidResponse'));
            }
        };
        try {
            socket = connect({ host: '127.0.0.1', port: entry.port });
        } catch {
            finish(new SyncError('unavailable'));
            return;
        }
        timer = setTimeout(() => finish(new SyncError('unavailable')), MOUNT_PROTOCOL.connectTimeoutMs);
        socket.once('connect', () => {
            clearTimeout(timer);
            timer = setTimeout(() => finish(new SyncError('unavailable')),
                action === 'flush' ? MOUNT_PROTOCOL.flushReadTimeoutMs : MOUNT_PROTOCOL.readTimeoutMs);
            socket.write(payload);
        });
        socket.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > maxBytes) {
                finish(new SyncError('invalidResponse'));
                return;
            }
            chunks.push(chunk);
            if (chunk.includes(10)) parse();
        });
        socket.once('end', () => { if (!settled) parse(); });
        socket.once('error', () => finish(new SyncError('unavailable')));
        socket.once('close', () => { if (!settled) finish(new SyncError('unavailable')); });
    });
}
