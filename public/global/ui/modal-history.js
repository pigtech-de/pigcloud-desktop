(() => {
    'use strict';
    const stack = [];
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
    function push(modal, manageHistory = true, route = null) {
        if (!manageHistory) return;
        stack.push({state: history.state || restoreState(), url: baseUrl()});
        if (stack.length > 50) stack.shift();
        history.pushState({modal}, '', route ? routeUrl(route) : undefined);
    }
    function pop(skipHistory = false) {
        const prev = stack.pop();
        if (skipHistory) return;
        if (history.state && history.state.modal) {
            const entry = prev !== undefined ? prev : {state: restoreState(), url: baseUrl()};
            history.replaceState(entry.state, '', entry.url);
        }
    }
    function reflect(route) {
        if (history.state && history.state.modal) {
            history.replaceState(history.state, '', routeUrl(route));
        }
    }
    window.PigcloudModalHistory = {push, pop, reflect, setBaseUrlProvider};
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
