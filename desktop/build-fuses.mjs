import {join} from 'node:path';
import {flipFuses, FuseVersion, FuseV1Options} from '@electron/fuses';

export default async function afterPack(context) {
    const platform = context.electronPlatformName;
    const name = platform === 'linux' ? context.packager.executableName : context.packager.appInfo.productFilename;
    const executable = platform === 'darwin'
        ? join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`)
        : join(context.appOutDir, `${name}${platform === 'win32' ? '.exe' : ''}`);
    await flipFuses(executable, {
        version: FuseVersion.V1,
        [FuseV1Options.RunAsNode]: false,
        [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
        [FuseV1Options.EnableNodeCliInspectArguments]: false,
        [FuseV1Options.OnlyLoadAppFromAsar]: true,
        [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    });
}
