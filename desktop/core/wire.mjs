export const MOUNT_PROTOCOL = Object.freeze({
    connectTimeoutMs: 5000,
    readTimeoutMs: 10000,
    flushBudgetMs: 30000,
    flushDeadlineMs: 35000,
    flushReadTimeoutMs: 40000,
});

export const WIRE_SCHEMAS = Object.freeze(Object.fromEntries(Object.entries({
    MountInfo: {
        port: 'int', token: 'string', pid: 'int', mount_point: 'string',
        remote_path: 'string', cache_dir: 'string', sync_dir: 'string?',
        mode: 'string', owner: 'string?', endpoint: 'string?', started_at: 'time.Time',
    },
    DaemonRequest: { token: 'string', action: 'string', path: 'string?', choice: 'string?' },
    FileEntry: {
        path: 'string', status: 'string', dirty: 'bool?', size: 'int64?',
        pinned: 'bool?', reason: 'string?',
    },
    ActivityEvent: { path: 'string', direction: 'string', bytes: 'int64', timestamp: 'int64', error: 'string?' },
    DaemonResponse: {
        ok: 'bool', error: 'string?', online: 'bool?', mount_point: 'string?',
        remote_path: 'string?', mode: 'string?', sync_dir: 'string?', cache_used: 'int64?',
        cache_max: 'int64?', pending_count: 'int?', failed_count: 'int?', deferred_count: 'int?',
        next_due_seconds: 'int?', retried: 'int?', failed_download_count: 'int?',
        last_poll: 'string?', uptime: 'string?', cleaned: 'int?',
        files: '[]FileEntry?', activity: '[]ActivityEvent?',
    },
    mountStatusJSON: {
        running: 'bool', stale: 'bool?', mode: 'string', mount_point: 'string',
        remote_path: 'string', sync_dir: 'string?', owner: 'string?', online: 'bool',
        cache_used: 'int64', cache_max: 'int64', pending: 'int', failed: 'int',
        deferred: 'int?', next_due_seconds: 'int?', stalled_downloads: 'int?',
        last_poll: 'string', uptime: 'string',
    },
    mountStatusListJSON: { running: 'bool', mounts: '[]mountStatusJSON' },
}).map(([name, fields]) => [name, Object.freeze(fields)])));

function zeroValue(type) {
    if (type.startsWith('[]')) return [];
    if (type === 'bool') return false;
    if (type === 'int' || type === 'int64') return 0;
    return '';
}

function fieldValue(type, value, label) {
    if (type.startsWith('[]')) {
        if (!Array.isArray(value)) throw new TypeError(`Invalid daemon field: ${label}`);
        return value.map(entry => decodeWire(type.slice(2), entry));
    }
    const valid = type === 'bool' ? typeof value === 'boolean'
        : type === 'int' || type === 'int64' ? Number.isSafeInteger(value)
            : typeof value === 'string';
    if (!valid) throw new TypeError(`Invalid daemon field: ${label}`);
    return value;
}

export function decodeWire(type, value) {
    const schema = WIRE_SCHEMAS[type];
    if (!schema || !value || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError('Invalid daemon message');
    }
    const result = {};
    for (const [key, declaration] of Object.entries(schema)) {
        const optional = declaration.endsWith('?');
        const fieldType = optional ? declaration.slice(0, -1) : declaration;
        if (!Object.hasOwn(value, key) && optional) {
            result[key] = zeroValue(fieldType);
        } else if (fieldType.startsWith('[]') && value[key] === null) {
            result[key] = [];
        } else {
            result[key] = fieldValue(fieldType, value[key], `${type}.${key}`);
        }
    }
    return result;
}

export function encodeWire(type, value) {
    const parsed = decodeWire(type, value);
    for (const [key, declaration] of Object.entries(WIRE_SCHEMAS[type])) {
        if (!declaration.endsWith('?')) continue;
        const field = parsed[key];
        if (field === '' || field === false || field === 0 || (Array.isArray(field) && field.length === 0)) delete parsed[key];
    }
    return JSON.stringify(parsed);
}
