import {randomBytes, createHash} from 'node:crypto';
import {CLOUD_ORIGIN} from './host-policy.mjs';

export function createDesktopLogin({session, openExternal, onComplete, onState = () => {}, clock = Date.now, schedule = setTimeout, cancel = clearTimeout}) {
    let active = null;
    let starting = null;
    async function post(action, body, signal) {
        const response = await session.fetch(`${CLOUD_ORIGIN}/cloud/actions.php?action=${action}`, {
            method: 'POST', credentials: 'include', redirect: 'error',
            headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
            signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
        });
        const data = await response.json();
        if (!response.ok && typeof data.error !== 'string') throw new Error('Desktop sign-in is unavailable.');
        return data;
    }
    function finish(attempt, state) {
        if (active !== attempt) return;
        cancel(attempt.timer);
        attempt.controller.abort();
        active = null;
        onState(state);
    }
    async function poll(attempt) {
        if (active !== attempt) return;
        if (clock() >= attempt.expires) return finish(attempt, 'expired');
        try {
            const data = await post('desktop-token', {code: attempt.code, verifier: attempt.verifier}, attempt.controller.signal);
            if (active !== attempt) return;
            if (data.success === true) {
                finish(attempt, 'complete');
                await onComplete();
                return;
            }
            if (!['authorization_pending', 'slow_down'].includes(data.error)) return finish(attempt, 'failed');
            if (data.error === 'slow_down') attempt.interval = Math.min(attempt.interval + 5000, 30000);
        } catch {
            if (active !== attempt) return;
            onState('waiting');
        }
        attempt.timer = schedule(() => poll(attempt).catch(() => finish(attempt, 'failed')), attempt.interval);
    }
    async function begin() {
            if (active) return {verificationCode: active.verificationCode};
            const verifier = randomBytes(32).toString('hex');
            const attempt = {verifier, controller: new AbortController(), timer: null};
            active = attempt;
            try {
                const data = await post('desktop-authorize', {challenge: createHash('sha256').update(verifier).digest('hex')}, attempt.controller.signal);
                if (active !== attempt) throw new Error('Desktop sign-in was cancelled.');
                if (data.error === 'already_signed_in') throw new Error('Sign out before switching accounts.');
                if (data.success !== true || !/^[a-f0-9]{64}$/.test(data.code)) throw new Error('Invalid desktop sign-in response.');
                const expected = `${CLOUD_ORIGIN}/desktop-login/?code=${data.code}`;
                if (data.verificationUri !== expected) throw new Error('Invalid desktop sign-in destination.');
                attempt.code = data.code;
                attempt.verificationCode = data.code.slice(0, 8).toUpperCase();
                attempt.interval = Math.max(5000, Math.min(30000, (Number(data.interval) || 5) * 1000));
                attempt.expires = clock() + Math.min(300000, Math.max(1000, (Number(data.expiresIn) || 300) * 1000));
                await openExternal(expected);
                onState('waiting');
                attempt.timer = schedule(() => poll(attempt).catch(() => finish(attempt, 'failed')), attempt.interval);
                return {verificationCode: attempt.verificationCode};
            } catch (error) {
                finish(attempt, 'failed');
                throw error;
            }
    }
    return {
        login() {
            if (starting) return starting;
            starting = begin().finally(() => {starting = null;});
            return starting;
        },
        dispose() {
            if (active) finish(active, 'cancelled');
        },
    };
}
