import {closeSync, openSync, readSync, readdirSync, statSync} from 'node:fs';
import {readFile} from 'node:fs/promises';
import {basename, join} from 'node:path';

export const REGISTRY_PREFIX = 'npm-';

export function packagedEntries(lock) {
    const found = new Map();
    for (const [path, entry] of Object.entries(lock?.packages || {})) {
        if (!path.startsWith('node_modules/') || entry?.dev || entry?.devOptional) continue;
        const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
        const depth = path.split('node_modules/').length;
        const previous = found.get(name);
        if (!previous || depth > previous.depth) found.set(name, {path, depth, version: entry?.version || ''});
    }
    return found;
}

export function packagedDependencies(lock) {
    return [...packagedEntries(lock).keys()].sort();
}

export function missingRegistryRows(lock, registry) {
    const rows = new Set((registry?.components || []).map(component => component.id));
    return packagedDependencies(lock).filter(name => !rows.has(REGISTRY_PREFIX + name));
}

export function asarHeader(file) {
    const handle = openSync(file, 'r');
    try {
        const prefix = Buffer.alloc(16);
        readSync(handle, prefix, 0, 16, 0);
        const body = Buffer.alloc(prefix.readUInt32LE(12));
        readSync(handle, body, 0, body.length, 16);
        return JSON.parse(body.toString('utf8').replace(/\0+$/u, ''));
    } finally {
        closeSync(handle);
    }
}

export function asarModules(file) {
    const names = new Set();
    const walk = node => {
        for (const [name, child] of Object.entries(node?.files || {})) {
            if (name !== 'node_modules') continue;
            for (const [module, contents] of Object.entries(child.files || {})) {
                if (module.startsWith('@')) {
                    for (const scoped of Object.keys(contents.files || {})) names.add(`${module}/${scoped}`);
                    continue;
                }
                names.add(module);
                walk(contents);
            }
        }
        for (const child of Object.values(node?.files || {})) {
            if (child?.files) walk(child);
        }
    };
    walk(asarHeader(file));
    return [...names].sort();
}

export function findAsar(root) {
    const found = [];
    const walk = directory => {
        for (const entry of readdirSync(directory)) {
            const path = join(directory, entry);
            if (statSync(path).isDirectory()) walk(path);
            else if (entry === 'app.asar') found.push(path);
        }
    };
    walk(root);
    if (!found.length) throw new Error(`No app.asar under ${root}`);
    return found;
}

export async function collectNotice({source, desktop}) {
    const lock = JSON.parse(await readFile(join(desktop, 'package-lock.json'), 'utf8'));
    const registry = JSON.parse(await readFile(join(source, 'private', 'third-party.json'), 'utf8'));
    const rows = new Map(registry.components.map(component => [component.id, component]));
    const entries = packagedEntries(lock);
    const packages = [...entries.keys()].sort();
    const missing = missingRegistryRows(lock, registry);
    if (missing.length) {
        throw new Error(`private/third-party.json has no row for packaged dependencies: ${missing.join(', ')}`);
    }
    const sections = [];
    for (const name of packages) {
        const component = rows.get(REGISTRY_PREFIX + name);
        const version = entries.get(name).version;
        const texts = [];
        for (const text of component.texts) {
            texts.push((await readFile(join(source, 'public', 'global', 'licenses', text), 'utf8')).trimEnd());
        }
        sections.push([
            `${name}${version ? ` ${version}` : ''}`,
            `${component.homepage}`,
            `SPDX-License-Identifier: ${component.license}`,
            '',
            texts.join('\n\n'),
        ].join('\n'));
    }
    const header = [
        'PigCloud desktop bundles the npm packages below. Each one is listed with',
        'its licence in full. PigCloud itself is covered by the LICENSE file beside',
        'this notice.',
    ].join('\n');
    return {packages, entries, notice: `${header}\n\n${sections.join(`\n\n${'='.repeat(70)}\n\n`)}\n`};
}

export async function verifyPackaged({desktop, dist}) {
    const lock = JSON.parse(await readFile(join(desktop, 'package-lock.json'), 'utf8'));
    const credited = packagedDependencies(lock);
    const reports = [];
    for (const file of findAsar(dist)) {
        const shipped = asarModules(file);
        const uncredited = shipped.filter(name => !credited.includes(name));
        const absent = credited.filter(name => !shipped.includes(name));
        if (uncredited.length || absent.length) {
            throw new Error(`${file} ships ${shipped.length} npm packages, the notice credits ${credited.length}.`
                + (uncredited.length ? `\n  shipped but not credited: ${uncredited.join(', ')}` : '')
                + (absent.length ? `\n  credited but not shipped: ${absent.join(', ')}` : ''));
        }
        reports.push(`${file}: ${shipped.length} npm packages, all credited`);
    }
    return reports;
}

if (process.argv[1] && basename(process.argv[1]) === 'build-notices.mjs') {
    const at = process.argv.indexOf('--verify');
    if (at === -1 || !process.argv[at + 1]) {
        console.error('Usage: node desktop/build-notices.mjs --verify <dist-dir>');
        process.exit(2);
    }
    const desktop = join(basename(process.cwd()) === 'desktop' ? process.cwd() : join(process.cwd(), 'desktop'));
    for (const line of await verifyPackaged({desktop, dist: process.argv[at + 1]})) console.log(line);
}
