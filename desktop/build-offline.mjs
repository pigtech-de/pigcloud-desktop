import {mkdir, readFile, writeFile, copyFile} from 'node:fs/promises';
import {dirname, join, extname, resolve, isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const sourceIndex = process.argv.indexOf('--source');
const suppliedSource = sourceIndex < 0 ? root : process.argv[sourceIndex + 1];
if (!suppliedSource || !isAbsolute(suppliedSource)) throw new Error('The web source must be an absolute repository path.');
const source = resolve(suppliedSource);
const {scripts, styles} = JSON.parse(await readFile(join(source, 'desktop', 'offline-assets.json'), 'utf8'));
if (![scripts, styles].every(paths => Array.isArray(paths) && paths.length > 0
    && paths.every(path => typeof path === 'string' && /^global\/[a-zA-Z0-9/_.-]+$/.test(path)
        && !path.split('/').includes('..')))) throw new Error('Invalid offline asset manifest.');
const output = join(root, 'desktop', 'bundle');
const mime = {'.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.png': 'image/png', '.html': 'text/html; charset=utf-8'};
const manifest = Object.create(null);
async function emit(path, contents) {
    await mkdir(dirname(join(output, path)), {recursive: true});
    await writeFile(join(output, path), contents);
    manifest[path] = mime[extname(path)] || 'application/octet-stream';
}
async function copy(path, input = join(source, 'public', path)) {
    await mkdir(dirname(join(output, path)), {recursive: true});
    await copyFile(input, join(output, path));
    manifest[path] = mime[extname(path)] || 'application/octet-stream';
}
await mkdir(output, {recursive: true});
await copy('LICENSE', join(root, 'LICENSE'));
const credits = JSON.parse(await readFile(join(source, 'private', 'third-party.json'), 'utf8'));
for (const component of credits.components.filter(item => item.group === 'fonts' || ['fontawesome', 'catppuccin'].includes(item.id))) {
    for (const text of component.texts) await copy(`licenses/${text}`, join(source, 'public', 'global', 'licenses', text));
}
for (const path of [...scripts, ...styles]) await copy(path);
const icons = await readFile(join(source, 'public', styles[0]), 'utf8');
for (const match of icons.matchAll(/url\((?:["'])?(?<url>[^)'"?]+)(?:\?[^)'" ]*)?(?:["'])?\)/g)) {
    const path = new URL(match.groups.url, `https://bundle.invalid/${styles[0]}`).pathname.slice(1);
    if (path.endsWith('.woff2')) await copy(path);
}
const registry = spawnSync('php', ['-r', 'require $argv[1]; echo json_encode(["fonts" => FontConfig::FONTS, "default" => FontConfig::DEFAULT_FONT], JSON_THROW_ON_ERROR);', join(source, 'private', 'platform', 'FontConfig.php')], {
    encoding: 'utf8', timeout: 10000, windowsHide: true,
});
if (registry.status !== 0) throw new Error('PHP could not read the shared font registry.');
const fontConfig = JSON.parse(registry.stdout);
const fontCss = [];
for (const [key, font] of Object.entries(fontConfig.fonts)) {
    if (font.fileName) {
        await copy(`global/fonts/${font.fileName}`);
        fontCss.push(`@font-face{font-family:"${key}_font";src:url("/global/fonts/${font.fileName}") format("woff2");font-display:swap}`);
    }
    fontCss.push(`:root{--font-${key}:${font.fileName ? `"${key}_font",` : ''}${font.fallback}}`);
}
fontCss.push(`:root{--font-body:var(--font-${fontConfig.default})}`);
await emit('fonts.css', fontCss.join('\n'));
const translations = {};
for (const language of ['en', 'de']) {
    translations[language] = {};
    for (const namespace of ['base', 'account']) {
        Object.assign(translations[language], JSON.parse(await readFile(join(source, 'i18n', namespace, `${language}.json`), 'utf8')));
    }
}
await emit('translations.js', `window.PigcloudDesktopTranslations = ${JSON.stringify(translations)};\n`);
await emit('translations.json', JSON.stringify(translations));
await copy('bootstrap.js', join(root, 'desktop', 'offline-bootstrap.js'));
await copy('icon.png', join(root, 'sync', 'packaging', 'icons', 'pigcloud-sync-128.png'));
await emit('index.html', `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PigCloud</title>
${[...styles, 'fonts.css'].map(path => `<link rel="stylesheet" href="/${path}">`).join('\n')}
<script src="/translations.js"></script><script src="/bootstrap.js" defer></script>
${scripts.map(path => `<script src="/${path}" defer></script>`).join('\n')}
</head><body class="native-app native-electron"><main class="vstack stack-md">
<h1 data-desktop-label="desktopOfflineTitle"></h1><p data-desktop-label="desktopOfflineDescription"></p>
<div class="hstack stack-sm"><button id="desktop-open-cloud" class="btn btn-primary" type="button" data-desktop-label="desktopOpenCloud"></button><button id="desktop-open-sync" class="btn" type="button" data-desktop-label="desktopOpenSync"></button></div>
<p id="desktop-status" class="field-status" role="status" aria-live="polite"></p>
</main></body></html>\n`);
await writeFile(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Bundled ${Object.keys(manifest).length} shared assets.`);
