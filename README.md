# PigCloud Desktop

Desktop access to PigCloud with local folder sync and a bundled CLI.

## Commands

- Requires Node.js 22+, PHP 8.5 and the Go toolchain in `cli/go.mod`.
- Windows also needs a C compiler and WinFsp development headers; macOS needs Xcode command-line tools.
- Build: `cd desktop && npm ci && npm run build`
- Package: `npm run package` from `desktop/`.
- Target architecture: set `PIGCLOUD_TARGET_ARCH` to `x64` or `arm64`.

## References

- [Downloads](https://github.com/pigtech-de/pigcloud-desktop/releases)
- [CLI commands](cli/README.md)
- [Third-party notices](public/global/licenses/)
- [Report an issue](https://github.com/pigtech-de/pigcloud-issues/issues)
- [Source license](LICENSE)
