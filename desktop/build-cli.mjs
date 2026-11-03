import {mkdir, copyFile, readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';

const platform = process.env.PIGCLOUD_TARGET_OS || process.platform;
const architecture = process.env.PIGCLOUD_TARGET_ARCH || process.arch;
const goos = {win32: 'windows', windows: 'windows', darwin: 'darwin', linux: 'linux'}[platform];
const goarch = {x64: 'amd64', amd64: 'amd64', arm64: 'arm64'}[architecture];
if (!goos || !goarch) throw new Error('Unsupported desktop build target.');
const cgo = process.env.CGO_ENABLED || (goos === 'linux' ? '0' : '1');
if (cgo !== '0' && cgo !== '1') throw new Error('CGO_ENABLED must be 0 or 1.');
if (goos === 'windows' && cgo !== '1') {
    if (process.env.PIGCLOUD_SYNC_ONLY_PREVIEW !== '1') throw new Error('Windows desktop builds require CGO_ENABLED=1 and WinFsp headers.');
    console.warn('Building a sync-only local preview without Windows virtual mounts. Do not publish this build.');
}
const include = goos === 'windows' && cgo === '1'
    ? {CPATH: process.env.CPATH || join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'WinFsp', 'inc', 'fuse')}
    : {};
const output = new URL(`resources/pc${goos === 'windows' ? '.exe' : ''}`, import.meta.url);
await mkdir(new URL('resources/', import.meta.url), {recursive: true});
await copyFile(new URL('../private/file-types.json', import.meta.url), new URL('../cli/internal/filetypes/file-types.json', import.meta.url));
const versionShape = /^[0-9A-Za-z.-]+$/;
const cliDir = fileURLToPath(new URL('../cli/', import.meta.url));
const described = spawnSync('git', ['describe', '--tags', '--match', 'cli-v*', '--abbrev=0'], {cwd: cliDir, encoding: 'utf8', timeout: 30000});
let cliVersion = described.status === 0 ? described.stdout.trim().replace(/^cli-v/, '') : '';
if (!versionShape.test(cliVersion)) {
    const main = await readFile(new URL('../cli/main.go', import.meta.url), 'utf8').catch(() => '');
    cliVersion = (main.match(/version\s*=\s*"([^"]+)"/) || [])[1] || '';
}
let desktopVersion = process.env.PIGCLOUD_DESKTOP_VERSION || '';
if (!desktopVersion) {
    desktopVersion = await readFile(new URL('package.json', import.meta.url), 'utf8')
        .then((text) => JSON.parse(text).version || '')
        .catch(() => '');
}
const stamp = versionShape.test(cliVersion)
    ? ` -X main.version=${cliVersion}+desktop${versionShape.test(desktopVersion) ? `.${desktopVersion}` : ''}`
    : '';
if (!stamp) console.warn('build-cli: no usable version to stamp, building unstamped');
const result = spawnSync('go', ['build', '-trimpath', `-ldflags=-s -w${stamp}`, '-o', fileURLToPath(output), '.'], {
    cwd: cliDir,
    env: {...process.env, ...include, GOOS: goos, GOARCH: goarch, CGO_ENABLED: cgo},
    stdio: 'inherit',
    timeout: 300000,
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status || 1);
