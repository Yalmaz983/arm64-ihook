// SPDX-License-Identifier: GPL-2.0-only
/*
 * ihook_test.c — kernel self-test harness for the inline-hook engine.
 *
 * Runs T1–T10 at module load, covering: symbol resolution, init,
 * trampoline install/verify/uninstall, hot-path stress, branch-both-sides,
 * fail-safe, classifier on clean targets, and classifier on pre-planted hooks.
 *
 * Build: make -C /path/to/kernel M=$(pwd)/tests ARCH=arm64 LLVM=1 modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include "../ihook.h"

#ifdef CONFIG_CFI_CLANG
#define TEST_NOCFI __attribute__((no_sanitize("kcfi")))
#else
#define TEST_NOCFI
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Inline-hook engine test harness (T1-T10)");

static int tests_run, tests_passed, tests_failed;

#define T_PASS(name) do { \
	pr_info("ihook_test: [PASS] %s\n", name); \
	tests_run++; tests_passed++; \
} while (0)

#define T_FAIL(name, fmt, ...) do { \
	pr_err("ihook_test: [FAIL] %s: " fmt "\n", name, ##__VA_ARGS__); \
	tests_run++; tests_failed++; \
} while (0)

static unsigned long (*test_kln)(const char *name);

static void *resolve_sym(const char *name)
{
	if (test_kln)
		return (void *)test_kln(name);
	{
		struct kprobe kp = {};
		void *addr;
		int ret;

		kp.symbol_name = name;
		ret = register_kprobe(&kp);
		if (ret < 0)
			return NULL;
		addr = (void *)kp.addr;
		unregister_kprobe(&kp);
		return addr;
	}
}

static void bootstrap_test_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&kp);

	if (ret < 0)
		return;
	test_kln = (unsigned long (*)(const char *))kp.addr;
	unregister_kprobe(&kp);
}

/* T1: Symbol resolution */
static void test_t1(void)
{
	static const char * const syms[] = {
		"aarch64_insn_patch_text",
		"__arm64_sys_reboot",
		"__arm64_sys_prctl",
		"do_exit",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(syms); i++) {
		void *addr = resolve_sym(syms[i]);

		if (!addr) {
			T_FAIL("T1-resolve", "%s: not found", syms[i]);
			continue;
		}
		T_PASS("T1-resolve");
	}
}

/* T2: Init + patch-text resolution */
static void test_t2(void)
{
	int ret = ihook_init();

	if (ret)
		T_FAIL("T2-init", "ihook_init failed (%d)", ret);
	else
		T_PASS("T2-init");
}

/* T3: Trampoline install/verify/uninstall */
static struct ihook_target t3_hook;

static TEST_NOCFI long t3_handler(struct pt_regs *regs)
{
	long (*orig)(struct pt_regs *) = (void *)t3_hook.original;
	return orig(regs);
}

static bool insn_is_b(u32 insn)
{
	return (insn & 0xFC000000) == 0x14000000;
}

static void test_t3(void)
{
	int ret;

	t3_hook.name = "__arm64_sys_prctl";
	t3_hook.handler = t3_handler;
	t3_hook.original = NULL;

	ret = ihook_install(&t3_hook, 1);
	if (ret) {
		T_FAIL("T3-install", "install failed (%d)", ret);
		return;
	}
	T_PASS("T3-install");

	if (!t3_hook.original)
		T_FAIL("T3-original", "original pointer is NULL");
	else
		T_PASS("T3-original-set");

	{
		u32 *target = (u32 *)resolve_sym("__arm64_sys_prctl");

		if (target) {
			u32 i0 = READ_ONCE(target[0]);
			u32 i1 = READ_ONCE(target[1]);

			if (insn_is_b(i0) || i0 == 0x58000050 ||
			    (i0 == 0xd503245f && insn_is_b(i1)))
				T_PASS("T3-patch-verified");
			else
				T_FAIL("T3-patch-verify", "unexpected insns %08x %08x", i0, i1);
		}
	}

	ret = ihook_uninstall(&t3_hook, 1);
	if (ret)
		T_FAIL("T3-uninstall", "uninstall failed (%d)", ret);
	else
		T_PASS("T3-uninstall");
}

/* T4: Hot-path stress */
#define T4_THREADS    8
#define T4_DURATION_S 10

static struct ihook_target t4_hook;
static atomic_t t4_hook_calls = ATOMIC_INIT(0);
static atomic_t t4_stop = ATOMIC_INIT(0);

static TEST_NOCFI void t4_handler_fn(long code)
{
	void (*orig)(long) = (void *)t4_hook.original;

	atomic_inc(&t4_hook_calls);
	orig(code);
}

static int t4_worker(void *data)
{
	while (!atomic_read(&t4_stop)) {
		cond_resched();
		schedule_timeout_interruptible(1);
	}
	return 0;
}

static void test_t4(void)
{
	struct task_struct *threads[T4_THREADS];
	int i, ret;
	unsigned long start;

	t4_hook.name = "do_exit";
	t4_hook.handler = t4_handler_fn;
	t4_hook.original = NULL;
	atomic_set(&t4_stop, 0);
	atomic_set(&t4_hook_calls, 0);

	ret = ihook_install(&t4_hook, 1);
	if (ret) {
		T_FAIL("T4-install", "do_exit install failed (%d)", ret);
		return;
	}
	T_PASS("T4-install");

	for (i = 0; i < T4_THREADS; i++) {
		threads[i] = kthread_run(t4_worker, NULL, "ihook_t4_%d", i);
		if (IS_ERR(threads[i]))
			threads[i] = NULL;
	}

	start = jiffies;
	while (time_before(jiffies, start + T4_DURATION_S * HZ))
		msleep(500);

	atomic_set(&t4_stop, 1);
	msleep(2000);

	pr_info("ihook_test: T4: hook fired %d times\n", atomic_read(&t4_hook_calls));

	ret = ihook_uninstall(&t4_hook, 1);
	if (ret)
		T_FAIL("T4-uninstall", "uninstall failed (%d)", ret);
	else
		T_PASS("T4-stress-survived");
}

/* T5: Branch-both-sides */
static struct ihook_target t5_hook;

static TEST_NOCFI long t5_handler_fn(struct pt_regs *regs)
{
	long (*orig)(struct pt_regs *) = (void *)t5_hook.original;

	return orig(regs);
}

static void test_t5(void)
{
	int ret;

	t5_hook.name = "__arm64_sys_prctl";
	t5_hook.handler = t5_handler_fn;
	t5_hook.original = NULL;

	ret = ihook_install(&t5_hook, 1);
	if (ret) {
		T_FAIL("T5-install", "install failed (%d)", ret);
		return;
	}

	{
		u32 *target = resolve_sym("__arm64_sys_prctl");
		bool patched = false;

		if (target) {
			u32 i0 = READ_ONCE(target[0]);
			u32 i1 = READ_ONCE(target[1]);

			patched = insn_is_b(i0) || (i0 == 0x58000050) ||
				  (i0 == 0xd503245f && insn_is_b(i1));
		}
		if (patched) T_PASS("T5-hook-side");
		else T_FAIL("T5-hook-side", "target not patched");
	}

	if (t5_hook.original) {
		u32 *tramp = (u32 *)t5_hook.original;
		if (tramp[0] != 0 && (tramp[0] & 0xFFE0001F) != 0xd4200000)
			T_PASS("T5-original-side");
		else
			T_FAIL("T5-original-side", "trampoline invalid");
	} else {
		T_FAIL("T5-original-side", "no trampoline pointer");
	}

	ihook_uninstall(&t5_hook, 1);
}

/* T6: Fail-safe */
static void test_t6(void)
{
	struct ihook_target bad;
	int ret;

	bad.name = NULL;
	bad.handler = (void *)0xDEAD;
	bad.original = NULL;
	ret = ihook_install(&bad, 1);
	if (ret == -EINVAL) T_PASS("T6-null-name");
	else T_FAIL("T6-null-name", "expected -EINVAL, got %d", ret);

	bad.name = "__arm64_sys_prctl";
	bad.handler = NULL;
	ret = ihook_install(&bad, 1);
	if (ret == -EINVAL) T_PASS("T6-null-handler");
	else T_FAIL("T6-null-handler", "expected -EINVAL, got %d", ret);

	bad.name = "nonexistent_symbol_xyz_12345";
	bad.handler = (void *)0xDEAD;
	ret = ihook_install(&bad, 1);
	if (ret == -ENOENT) T_PASS("T6-bad-symbol");
	else T_FAIL("T6-bad-symbol", "expected -ENOENT, got %d", ret);
}

/* T7: Classifier — clean targets */
static void test_t7(void)
{
	int result, ret;

	ret = ihook_classify("__arm64_sys_prctl", &result);
	if (ret)
		T_FAIL("T7-clean-prctl", "classify failed (%d)", ret);
	else if (result == IHOOK_CLEAN)
		T_PASS("T7-clean-prctl");
	else
		T_FAIL("T7-clean-prctl", "expected CLEAN, got %d", result);

	ret = ihook_classify("nonexistent_symbol_xyz", &result);
	if (ret == -ENOENT) T_PASS("T7-enoent");
	else T_FAIL("T7-enoent", "expected -ENOENT, got %d", ret);
}

/* T8: Classifier — pre-planted BRK detected as ALREADY_HOOKED */
static void test_t8(void)
{
	void *addr;
	u32 *target;
	u32 orig_insn;
	u32 brk_insn = 0xd4200080;
	int result, ret;

	addr = resolve_sym("__arm64_sys_reboot");
	if (!addr) {
		T_FAIL("T8-resolve", "cannot find __arm64_sys_reboot");
		return;
	}
	target = (u32 *)addr;
	orig_insn = READ_ONCE(target[0]);

	ret = ihook_patch_text(addr, &brk_insn, 1);
	if (ret) {
		T_FAIL("T8-plant-brk", "patch_text failed (%d)", ret);
		return;
	}
	T_PASS("T8-brk-planted");

	ret = ihook_classify("__arm64_sys_reboot", &result);
	if (ret)
		T_FAIL("T8-classify", "classify returned %d", ret);
	else if (result == IHOOK_ALREADY_HOOKED)
		T_PASS("T8-classify-hooked");
	else
		T_FAIL("T8-classify-hooked", "expected ALREADY_HOOKED, got %d", result);

	ihook_patch_text(addr, &orig_insn, 1);
}

/* T9: Install refused on already-hooked target */
static void test_t9(void)
{
	void *addr;
	u32 *target;
	u32 orig_insn;
	u32 brk_insn = 0xd4200080;
	struct ihook_target probe;
	int ret;

	addr = resolve_sym("__arm64_sys_reboot");
	if (!addr) {
		T_FAIL("T9-resolve", "cannot find __arm64_sys_reboot");
		return;
	}
	target = (u32 *)addr;
	orig_insn = READ_ONCE(target[0]);

	ihook_patch_text(addr, &brk_insn, 1);

	probe.name = "__arm64_sys_reboot";
	probe.handler = (void *)0xDEAD;
	probe.original = NULL;
	ret = ihook_install(&probe, 1);
	if (ret != 0)
		T_PASS("T9-install-refused");
	else {
		T_FAIL("T9-install-refused", "install should fail on hooked target");
		ihook_uninstall(&probe, 1);
	}

	ihook_patch_text(addr, &orig_insn, 1);
}

/* T10: BRK not clobbered by refused install */
static void test_t10(void)
{
	void *addr;
	u32 *target;
	u32 orig_insn;
	u32 brk_insn = 0xd4200080;
	struct ihook_target probe;
	int ret;

	addr = resolve_sym("__arm64_sys_reboot");
	if (!addr) {
		T_FAIL("T10-resolve", "cannot find __arm64_sys_reboot");
		return;
	}
	target = (u32 *)addr;
	orig_insn = READ_ONCE(target[0]);

	ihook_patch_text(addr, &brk_insn, 1);

	probe.name = "__arm64_sys_reboot";
	probe.handler = (void *)0xDEAD;
	probe.original = NULL;
	ihook_install(&probe, 1);

	{
		u32 cur = READ_ONCE(target[0]);
		if (cur == brk_insn) T_PASS("T10-no-clobber");
		else T_FAIL("T10-no-clobber", "BRK was clobbered: %08x", cur);
	}

	ret = ihook_patch_text(addr, &orig_insn, 1);
	if (ret)
		T_FAIL("T10-restore", "restore failed (%d)", ret);
	else
		T_PASS("T10-restored");
}

static int __init ihook_test_init(void)
{
	pr_info("ihook_test: ===== ARM64 INLINE-HOOK ENGINE TEST =====\n");
	pr_info("ihook_test: KASAN=%s LOCKDEP=%s CFI=%s\n",
		IS_ENABLED(CONFIG_KASAN) ? "on" : "off",
		IS_ENABLED(CONFIG_LOCKDEP) ? "on" : "off",
		IS_ENABLED(CONFIG_CFI_CLANG) ? "on" : "off");

	tests_run = tests_passed = tests_failed = 0;

	bootstrap_test_kln();

	pr_info("ihook_test: --- T1: Symbol Resolution ---\n");
	test_t1();
	pr_info("ihook_test: --- T2: Init ---\n");
	test_t2();
	pr_info("ihook_test: --- T3: Trampoline ---\n");
	test_t3();
	pr_info("ihook_test: --- T4: Hot-Path Stress ---\n");
	test_t4();
	pr_info("ihook_test: --- T5: Branch Both Sides ---\n");
	test_t5();
	pr_info("ihook_test: --- T6: Fail-Safe ---\n");
	test_t6();
	pr_info("ihook_test: --- T7: Classifier Clean ---\n");
	test_t7();
	pr_info("ihook_test: --- T8: Classifier BRK ---\n");
	test_t8();
	pr_info("ihook_test: --- T9: Install Refused ---\n");
	test_t9();
	pr_info("ihook_test: --- T10: No-Clobber ---\n");
	test_t10();

	pr_info("ihook_test: ===== RESULTS =====\n");
	pr_info("ihook_test: %d/%d passed, %d failed\n",
		tests_passed, tests_run, tests_failed);
	if (tests_failed == 0)
		pr_info("ihook_test: *** ALL TESTS PASSED ***\n");
	else
		pr_err("ihook_test: *** %d TEST(S) FAILED ***\n", tests_failed);

	ihook_cleanup();
	return 0;
}

static void __exit ihook_test_exit(void)
{
	pr_info("ihook_test: unloaded\n");
}

module_init(ihook_test_init);
module_exit(ihook_test_exit);
