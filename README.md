# ihook — ARM64 Inline-Hook Engine for Linux

A lightweight kernel module library for safe runtime function interception on arm64 Linux (5.10+).

## Features

- **BTI/PAC aware** — detects and preserves BTI C, PACIASP/PACIBSP prologues
- **Instruction relocation** — ADRP and ADR operands are recalculated for the trampoline address
- **Atomic rollback** — partial install failures restore all previously patched targets
- **Pre-existing hook classifier** — detects BRK breakpoints, out-of-range branches, and LDR+BR veneers before install, preventing double-hook corruption
- **CONFIG_STRICT_MODULE_RWX safe** — trampoline slots live in `.text` (const), written via `aarch64_insn_patch_text` through fixmap
- **CONFIG_CFI_CLANG safe** — handler calls annotated `no_sanitize("kcfi")`
- **16 slots** — up to 16 concurrent hooks per module instance
- **10-test harness** — symbol resolution, trampoline execution, hot-path stress (8 threads, 10s), fail-safe, classifier accuracy

## Use cases

- Kernel function tracing and instrumentation
- Security research and audit tooling
- Dynamic kernel module testing
- Rootkit/hook detection via the classifier

## Quick start

```c
#include "ihook.h"

static struct ihook_target my_hook;

static long my_handler(struct pt_regs *regs)
{
    long (*orig)(struct pt_regs *) = (void *)my_hook.original;
    pr_info("intercepted!\n");
    return orig(regs);
}

static int __init my_init(void)
{
    ihook_init();
    my_hook.name = "sys_example";
    my_hook.handler = my_handler;
    return ihook_install(&my_hook, 1);
}

static void __exit my_exit(void)
{
    ihook_uninstall(&my_hook, 1);
    ihook_cleanup();
}
```

## Building

```bash
# Build the library module
make KDIR=/path/to/kernel/build ARCH=arm64

# Build and run tests
make test KDIR=/path/to/kernel/build ARCH=arm64
insmod tests/ihook_test.ko
dmesg | grep ihook_test
```

## API

| Function | Description |
|---|---|
| `ihook_init()` | Bootstrap symbol resolution and locate `aarch64_insn_patch_text` |
| `ihook_install(targets, count)` | Install 1–16 hooks atomically; rolls back on any failure |
| `ihook_uninstall(targets, count)` | Restore original instructions; verifies text integrity first |
| `ihook_classify(sym, result)` | Check if a symbol is already hooked (BRK, branch, veneer) |
| `ihook_cleanup()` | Warn about any hooks still active at module unload |
| `ihook_patch_text(addr, vals, n)` | Low-level text patcher via fixmap |

## Classifier

`ihook_classify()` inspects the first two instructions of a kernel symbol and returns:

- `IHOOK_CLEAN` — no evidence of prior hooking
- `IHOOK_ALREADY_HOOKED` — detected one of: BRK at position 0 or 1, unconditional branch with offset outside the function, LDR X16 + BR X16 veneer

This prevents double-hooking and can be used standalone to audit kernel text integrity.

## Limitations

- Phase 1: only PC-independent prologues and ADRP/ADR relocation. CBZ/TBZ/B.cc/LDR-literal in the first 4 instructions will be rejected (`-EOPNOTSUPP`).
- Maximum 16 hooks per module load.
- Requires `kallsyms_lookup_name` to be resolvable via kprobe (standard on most configs).
- Tested on kernel 6.1–6.12 with Clang/LLVM. GCC builds should work but are not CI-tested.

## License

GPL-2.0-only — required for kernel module code using `EXPORT_SYMBOL_GPL`.
