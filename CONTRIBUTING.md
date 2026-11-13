# Contributing

Contributions welcome. Here's what helps most:

## Good first issues

- Test on a kernel version not yet listed in CI
- Add relocation support for CBZ/TBZ/B.cc in trampoline builder
- Add LDR-literal relocation
- Improve classifier heuristics for additional hook patterns

## Submitting changes

1. Fork and branch from `main`
2. One logical change per commit
3. Run the test module on an arm64 kernel before submitting
4. Include `dmesg` output showing test results in the PR description

## Code style

Follow the kernel coding style (`scripts/checkpatch.pl` should be clean).
SPDX headers on every file.

## Reporting issues

Open an issue with:
- Kernel version and config (especially `CONFIG_CFI_CLANG`, `CONFIG_KASAN`)
- Full `dmesg` output from the test module
- Device or VM details
