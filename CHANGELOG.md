# Changelog

## v0.1.0 — 2026-11-13

Initial release.

- ARM64 inline-hook engine with trampoline-based function interception
- BTI/PAC prologue detection and preservation
- ADRP and ADR instruction relocation for trampolines
- Atomic multi-hook install with rollback on failure
- Pre-existing hook classifier (BRK, branch, LDR+BR veneer detection)
- CONFIG_STRICT_MODULE_RWX safe via fixmap text patching
- CONFIG_CFI_CLANG safe with kcfi annotations
- 10-test kernel self-test harness (T1–T10)
- Hot-path stress test: 8 threads, 10 seconds
