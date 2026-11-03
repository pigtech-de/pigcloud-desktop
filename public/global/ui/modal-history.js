(() => {
    'use strict';
    const stack = [];
    const redo = [];
    let baseUrlFn = null;
    let restoreStateFn = null;
    function setBaseUrlProvider(urlFn, stateFn) {
        baseUrlFn = typeof urlFn === 'function' ? urlFn : null;
        restoreStateFn = typeof stateFn === 'function' ? stateFn : null;
    }
    function baseUrl() {
        return baseUrlFn ? baseUrlFn() : location.pathname + location.search;
    }
    function restoreState() {
        return restoreStateFn ? restoreStateFn() : {path: location.pathname};
    }
    function routeUrl(route) {
        return location.pathname + location.search + '#!' + route;
    }
    function onModalEntry() {
        return !!(history.state && history.state.modal);
    }
    function ownsEntry() {
        return onModalEntry() && stack.length > 0;
    }
    function topModal() {
        return stack.length ? stack[stack.length - 1].modal : null;
    }
    function isForward(state) {
        const target = state && state.modal;
        return !!target && redo.length > 0 && redo[redo.length - 1].modal === target && topModal() !== target;
    }
    let traverse = null;
    function isDeadEntry(state) {
        const modal = state && state.modal;
        return !!modal && !stack.some(entry => entry.modal === modal);
    }
    function startTraverse(deliver) {
        traverse = {deliver};
        history.back();
    }
    window.addEventListener('popstate', (e) => {
        if (traverse) {
            const dead = isDeadEntry(e.state);
            if (dead || !traverse.deliver) e.stopImmediatePropagation();
            if (dead) history.back();
            else traverse = null;
            return;
        }
        if (isDeadEntry(e.state) && !isForward(e.state)) {
            e.stopImmediatePropagation();
            startTraverse(true);
        }
    });
    function push(modal, manageHistory = true, route = null) {
        if (!manageHistory) return;
        if (isForward(history.state) && history.state.modal === modal) {
            stack.push(redo.pop());
            if (route) history.replaceState(history.state, '', routeUrl(route));
            return;
        }
        redo.length = 0;
        const stale = onModalEntry() && !ownsEntry();
        stack.push(ownsEntry()
            ? {modal, state: history.state, url: location.pathname + location.search + location.hash}
            : {modal, state: null, url: null});
        if (stack.length > 50) stack.shift();
        const state = {modal};
        const url = route ? routeUrl(route) : undefined;
        if (stale) history.replaceState(state, '', url);
        else history.pushState(state, '', url);
    }
    function pop(skipHistory = false, modal = null) {
        if (modal) {
            let index = stack.length - 1;
            while (index >= 0 && stack[index].modal !== modal) index--;
            if (index === -1) return;
            if (index !== stack.length - 1) {
                stack[index + 1].state = stack[index].state;
                stack[index + 1].url = stack[index].url;
                stack.splice(index, 1);
                return;
            }
        }
        const prev = stack.pop();
        if (skipHistory) {
            if (prev) redo.push(prev);
            if (redo.length > 50) redo.shift();
            if (prev && isDeadEntry(history.state)) startTraverse(false);
            return;
        }
        if (onModalEntry()) {
            history.replaceState(prev && prev.state ? prev.state : restoreState(), '', prev && prev.url ? prev.url : baseUrl());
        }
    }
    function popThrough(modal, skipHistory = false) {
        let index = stack.length - 1;
        while (index >= 0 && stack[index].modal !== modal) index--;
        const above = index < 0 ? 0 : stack.length - 1 - index;
        if (above === 0 || skipHistory || !onModalEntry()) {
            if (index >= 0) stack.length = index + 1;
            pop(skipHistory);
            return;
        }
        const ownUrl = stack[index + 1].url;
        stack.length = index + 1;
        if (ownUrl) history.replaceState(history.state, '', ownUrl);
        window.addEventListener('popstate', () => pop(false), {once: true});
        history.go(-above);
    }
    function reflect(route) {
        if (ownsEntry()) {
            const below = stack[stack.length - 1].url;
            history.replaceState(history.state, '', route ? routeUrl(route) : (below || baseUrl()));
        }
    }
    window.PigcloudModalHistory = {push, pop, popThrough, reflect, setBaseUrlProvider, ownsEntry, isForward, topModal};
    window.pushModalState = push;
    window.popModalState = pop;
})();

(() => {
    'use strict';
    let count = 0;
    let prevOverflow = '';
    let prevPaddingRight = '';
    function lock() {
        count += 1;
        if (count > 1) return;
        prevOverflow = document.body.style.overflow;
        prevPaddingRight = document.body.style.paddingRight;
        const gap = window.innerWidth - document.documentElement.clientWidth;
        if (gap > 0) {
            document.body.style.paddingRight = gap + 'px';
        }
        document.body.style.overflow = 'hidden';
    }
    function unlock() {
        if (count === 0) return;
        count -= 1;
        if (count > 0) return;
        document.body.style.overflow = prevOverflow;
        document.body.style.paddingRight = prevPaddingRight;
    }
    window.PigcloudScrollLock = {lock, unlock};
})();
