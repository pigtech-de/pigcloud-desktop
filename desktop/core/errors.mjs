const MESSAGES = Object.freeze({
    invalidArgument: 'The sync request is invalid.',
    staleSettings: 'Settings changed. Reload them before saving.',
    stalePair: 'This sync folder changed. Select it again.',
    noCli: 'Install the PigCloud CLI or choose its executable.',
    notConfigured: 'Sign in to the PigCloud CLI to configure sync.',
    unsupportedEndpoint: 'The desktop app supports pigcloud.de only. Set the CLI endpoint to https://pigcloud.de/cloud/actions.php before connecting it.',
    loginFailed: 'The PigCloud CLI sign-in could not finish.',
    loginCancelled: 'PigCloud CLI sign-in was cancelled.',
    loginTimeout: 'PigCloud CLI sign-in expired. Start it again.',
    moveRequired: 'This remote already has a sync folder. Move it with pc mn mv before choosing a different folder.',
    locked: 'Unlock your PigCloud account to start sync.',
    unlockFailed: 'The account could not be unlocked.',
    cliFailed: 'The PigCloud CLI command failed.',
    cliTimeout: 'The PigCloud CLI command timed out.',
    cliOutputLimit: 'The PigCloud CLI response exceeded its size limit.',
    unavailable: 'The sync daemon could not be reached.',
    daemonFailed: 'The sync daemon refused the request.',
    invalidResponse: 'The sync daemon returned an invalid response.',
    identityMismatch: 'A different mapping or account owns this mount.',
    saveFailed: 'Settings could not be saved. Your previous settings remain active.',
    configUnreadable: 'Sync settings could not be read. Repair the settings file before saving.',
    shutdown: 'The desktop controller is shutting down.',
});

export class SyncError extends Error {
    constructor(code) {
        super(MESSAGES[code] || MESSAGES.invalidArgument);
        this.name = 'SyncError';
        this.code = Object.hasOwn(MESSAGES, code) ? code : 'invalidArgument';
    }
}

export function publicError(error) {
    const safe = error instanceof SyncError ? error : new SyncError('unavailable');
    return { code: safe.code, message: safe.message };
}

export function requireObject(value, keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).some(key => !keys.includes(key))) throw new SyncError('invalidArgument');
}

export function requireString(value, { max = 4096, empty = false } = {}) {
    if (typeof value !== 'string' || value.length > max || (!empty && !value.length)
        || /[\0\r\n]/u.test(value)) throw new SyncError('invalidArgument');
    return value;
}
