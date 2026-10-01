export function queueEngine(engine) {
    let resolveReady;
    let rejectReady;
    let closed = false;
    let initialized;
    const readiness = new Promise((resolve, reject) => {resolveReady = resolve; rejectReady = reject;});
    readiness.catch(() => {});
    const queued = {};
    for (const name of ['getSettings', 'saveSettings', 'status', 'start', 'stop', 'unlock', 'files', 'activity', 'conflicts', 'resolve', 'retry', 'flush', 'setCliPath', 'folderPath', 'loginCli']) {
        queued[name] = async (...args) => {
            await readiness;
            if (closed) throw new Error('Desktop sync is shutting down.');
            return engine[name](...args);
        };
    }
    queued.subscribe = callback => engine.subscribe(callback);
    queued.initialize = () => {
        if (!initialized) {
            initialized = Promise.resolve().then(() => {
                if (closed) throw new Error('Desktop sync is shutting down.');
                return engine.initialize();
            });
            initialized.then(resolveReady, rejectReady);
        }
        return initialized;
    };
    queued.dispose = () => {
        closed = true;
        rejectReady(new Error('Desktop sync is shutting down.'));
        return engine.dispose();
    };
    return queued;
}
