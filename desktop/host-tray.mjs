export function nativeStrings(dictionaries, locale) {
    const language = String(locale).toLowerCase().startsWith('de') ? 'de' : 'en';
    return (key, values = {}) => {
        let text = dictionaries[language]?.[key] || dictionaries.en?.[key] || key;
        for (const [name, value] of Object.entries(values)) text = text.replaceAll(`{${name}}`, String(value));
        return text;
    };
}

export function traySummary(snapshot, t) {
    let pending = 0;
    let failed = 0;
    for (const pair of snapshot.pairs || []) {
        pending += Number(pair.status?.pendingCount) || 0;
        failed += (Number(pair.status?.failedCount) || 0) + (Number(pair.status?.failedDownloadCount) || 0);
    }
    const key = {noCli: 'syncMissingCli', notConfigured: 'syncLoginRequired', failed: 'syncError'}[snapshot.state]
        || `sync${snapshot.state?.[0]?.toUpperCase() || ''}${snapshot.state?.slice(1) || ''}`;
    return t('desktopNativeSummary', {state: t(key), pending, failed});
}

export function trayMenu(snapshot, t, actions) {
    const items = [
        {label: traySummary(snapshot, t), enabled: false},
        {type: 'separator'},
        {label: t('desktopNativeOpen'), click: actions.open},
        {label: t('desktopNativeSettings'), click: actions.settings},
        {label: t('desktopNativeStartAll'), click: () => actions.start()},
        {label: t('desktopNativeStopAll'), click: () => actions.stop()},
    ];
    for (const pair of snapshot.pairs || []) {
        const name = Array.from(String(pair.remotePath || '/')).filter(character => {
            const code = character.codePointAt(0);
            return code >= 0x20 && !(code >= 0x7f && code <= 0x9f)
                && !(code >= 0x202a && code <= 0x202e) && !(code >= 0x2066 && code <= 0x2069);
        }).join('').replaceAll('&', '&&');
        items.push({label: name, submenu: [
            {label: t('desktopNativeStart'), enabled: pair.state !== 'running' && pair.state !== 'starting', click: () => actions.start(pair.id)},
            {label: t('desktopNativeStop'), click: () => actions.stop(pair.id)},
            {label: t('desktopNativeOpenFolder'), click: () => actions.folder(pair.id)},
        ]});
    }
    items.push({type: 'separator'}, {label: t('desktopNativeQuit'), click: actions.quit});
    return items;
}

export function statusBitmap(bitmap, width, height, state) {
    const result = Buffer.from(bitmap);
    if (result.length !== width * height * 4 || width < 12 || height < 12) return result;
    const left = width - 11;
    const top = height - 11;
    const pixel = (x, y, shade) => {
        const offset = ((top + y) * width + left + x) * 4;
        result[offset] = result[offset + 1] = result[offset + 2] = shade;
        result[offset + 3] = 255;
    };
    for (let y = 0; y < 11; y++) for (let x = 0; x < 11; x++) {
        const distance = (x - 5) ** 2 + (y - 5) ** 2;
        if (distance <= 25) pixel(x, y, distance > 16 ? 0 : 255);
    }
    const marks = state === 'running' ? [[2, 5], [3, 6], [4, 7], [5, 6], [6, 5], [7, 4], [8, 3]]
        : state === 'stopped' ? [[4, 3], [4, 4], [4, 5], [4, 6], [4, 7], [6, 3], [6, 4], [6, 5], [6, 6], [6, 7]]
            : state === 'starting' ? [[5, 3], [5, 4], [5, 5], [6, 5], [7, 5]]
                : [[5, 3], [5, 4], [5, 5], [5, 7]];
    for (const [x, y] of marks) pixel(x, y, 0);
    return result;
}
