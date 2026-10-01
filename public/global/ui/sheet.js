(() => {
    'use strict';

    const QUERY = '(max-width: 640px)';
    const SLOP_PX = 10;
    const DISMISS_PX = 100;
    const FLICK_PX = 32;
    const FLICK_PX_PER_MS = 0.6;
    const mq = typeof window.matchMedia === 'function' ? window.matchMedia(QUERY) : null;

    function isSheetViewport() {
        return !!mq && mq.matches;
    }

    function isScrollable(el) {
        if (!(el instanceof Element) || el.scrollHeight <= el.clientHeight) return false;
        const overflow = window.getComputedStyle(el).overflowY;
        return overflow === 'auto' || overflow === 'scroll';
    }

    function scrollerFor(surface, target) {
        let el = target instanceof Element ? target : null;
        while (el && el !== surface) {
            if (isScrollable(el)) return el;
            el = el.parentElement;
        }
        return surface;
    }

    function attachSwipe(surface, onDismiss) {
        if (!surface || typeof onDismiss !== 'function') return () => {};
        let startX = 0;
        let startY = 0;
        let lastY = 0;
        let lastAt = 0;
        let velocity = 0;
        let dy = 0;
        let swiping = false;
        let dragging = false;
        let scroller = surface;
        const reset = () => {
            swiping = false;
            dragging = false;
            dy = 0;
            velocity = 0;
            scroller = surface;
            surface.classList.remove('is-dragging');
            surface.style.removeProperty('--sheet-drag');
        };
        const onStart = (e) => {
            if (!surface.classList.contains('sheet')) return;
            const t = e.touches[0];
            if (!t) return;
            startX = t.clientX;
            startY = t.clientY;
            lastY = startY;
            lastAt = Date.now();
            dy = 0;
            velocity = 0;
            dragging = false;
            scroller = scrollerFor(surface, e.target);
            swiping = surface.scrollTop <= 0 && scroller.scrollTop <= 0;
        };
        const onMove = (e) => {
            if (!swiping || !surface.classList.contains('sheet')) return;
            const t = e.touches[0];
            if (!t) return;
            dy = t.clientY - startY;
            const dx = t.clientX - startX;
            if (surface.scrollTop > 0 || scroller.scrollTop > 0) {
                reset();
                return;
            }
            if (!dragging) {
                if (dy < -SLOP_PX || (Math.abs(dx) > SLOP_PX && Math.abs(dx) > dy)) {
                    reset();
                    return;
                }
                if (dy <= SLOP_PX) return;
                dragging = true;
                surface.classList.add('is-dragging');
            }
            const now = Date.now();
            if (now > lastAt) velocity = (t.clientY - lastY) / (now - lastAt);
            lastY = t.clientY;
            lastAt = now;
            surface.style.setProperty('--sheet-drag', `${Math.max(0, Math.round(dy))}px`);
        };
        const onEnd = () => {
            if (!dragging) {
                reset();
                return;
            }
            const flick = dy > FLICK_PX && velocity > FLICK_PX_PER_MS;
            const dismiss = dy > DISMISS_PX || flick;
            reset();
            if (dismiss) onDismiss();
        };
        const onCancel = () => reset();
        surface.addEventListener('touchstart', onStart, {passive: true});
        surface.addEventListener('touchmove', onMove, {passive: true});
        surface.addEventListener('touchend', onEnd, {passive: true});
        surface.addEventListener('touchcancel', onCancel, {passive: true});
        return () => {
            reset();
            surface.removeEventListener('touchstart', onStart);
            surface.removeEventListener('touchmove', onMove);
            surface.removeEventListener('touchend', onEnd);
            surface.removeEventListener('touchcancel', onCancel);
        };
    }

    window.PigcloudSheet = {QUERY, isSheetViewport, attachSwipe};
})();
