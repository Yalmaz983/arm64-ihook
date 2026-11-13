// SPDX-License-Identifier: GPL-2.0-only
/*
 * ihook.c — ARM64 inline-hook engine with pre-existing hook classifier.
 *
 * Text-patch via aarch64_insn_patch_text (resolved dynamically).
 * Static .text trampoline slots (const -> no W flag, written via fixmap).
 * PC-independent prologues only; entry redirect uses B (not BL) to
 * preserve the caller's LR.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/bug.h>
#include <linux/cpu.h>
#include <asm/cacheflush.h>
#include "ihook.h"

#ifdef CONFIG_CFI_CLANG
#define IHOOK_NOCFI __attribute__((no_sanitize("kcfi")))
#else
#define IHOOK_NOCFI
#endif

/* ===== trampoline memory ===== */

#define SLOT_SIZE       256
#define SLOT_WORDS      (SLOT_SIZE / sizeof(u32))
#define SLOT_COUNT      IHOOK_MAX_SLOTS
#define TRAMP_AREA_SIZE (SLOT_SIZE * SLOT_COUNT)

/*
 * const -> .text has AX flags only (no W). Survives CONFIG_STRICT_MODULE_RWX.
 * Written at install time via aarch64_insn_patch_text (fixmap bypass).
 */
static const u32 trampoline_slots[TRAMP_AREA_SIZE / sizeof(u32)]
	__attribute__((section(".text"), aligned(64)));

/* ===== per-hook state ===== */

struct ihook_entry {
	bool                  active;
	void                 *target_addr;
	u32                   orig_insns[4];
	u32                   patch_insns[4];
	int                   has_bti;
	struct ihook_target  *desc;
	const u32            *slot;
};

static struct ihook_entry hooks[SLOT_COUNT];
static int hooks_installed;
static DEFINE_MUTEX(ihook_mutex);

/* ===== resolved kernel functions ===== */

static int (*fn_patch_text)(void *addrs[], u32 *insns, int cnt);
static unsigned long (*k_lookup_name)(const char *name);

/* ===== symbol resolution ===== */

static IHOOK_NOCFI int bootstrap_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;
	k_lookup_name = (unsigned long (*)(const char *))kp.addr;
	unregister_kprobe(&kp);
	return k_lookup_name ? 0 : -ENOENT;
}

static IHOOK_NOCFI void *resolve_symbol(const char *name)
{
	if (!k_lookup_name)
		return NULL;
	return (void *)k_lookup_name(name);
}

/* ===== ARM64 instruction helpers ===== */

static inline bool is_bti_or_pac(u32 insn)
{
	switch (insn) {
	case 0xd503233f: /* PACIASP */
	case 0xd503237f: /* PACIBSP */
	case 0xd503245f: /* BTI C   */
	case 0xd503249f: /* BTI J   */
	case 0xd50324df: /* BTI JC  */
	case 0xd503201f: /* NOP     */
		return true;
	}
	return false;
}

#define BTI_C 0xd503245f

static int encode_b(u64 from, u64 to, u32 *out)
{
	s64 off = (s64)(to - from);

	if (off > 0x7FFFFFC || off < -0x8000000)
		return -ERANGE;
	if (off & 3)
		return -EINVAL;
	*out = 0x14000000 | (((u32)(off >> 2)) & 0x03FFFFFF);
	return 0;
}

static inline u32 encode_brk(u16 imm)
{
	return 0xd4200000 | ((u32)imm << 5);
}

static bool is_pc_relative(u32 insn)
{
	u32 op = insn >> 24;

	if ((insn & 0x9F000000) == 0x90000000) return true;  /* ADRP */
	if ((insn & 0x9F000000) == 0x10000000) return true;  /* ADR  */
	if ((op & 0xFC) == 0x14) return true;                 /* B/BL */
	if (op == 0x54) return true;                          /* B.cc */
	if ((op & 0x7E) == 0x34) return true;                 /* CBZ/CBNZ */
	if ((op & 0x7E) == 0x36) return true;                 /* TBZ/TBNZ */
	if ((op & 0x3B) == 0x18) return true;                 /* LDR literal */
	return false;
}

static int relocate_adrp(u32 insn, u64 orig_pc, u64 new_pc, u32 *out)
{
	u32 immlo = (insn >> 29) & 3;
	u32 immhi = (insn >> 5) & 0x7FFFF;
	s64 imm21 = (s64)(((u64)immhi << 2) | immlo);
	u64 target_page;
	s64 new_page_off, new_imm21;

	if (imm21 & (1 << 20))
		imm21 -= (1 << 21);
	target_page = (orig_pc & ~0xFFFULL) + (imm21 << 12);
	new_page_off = (s64)(target_page - (new_pc & ~0xFFFULL));
	new_imm21 = new_page_off >> 12;
	if (new_imm21 >= (1 << 20) || new_imm21 < -(1 << 20))
		return -ERANGE;

	immlo = (u32)new_imm21 & 3;
	immhi = ((u32)new_imm21 >> 2) & 0x7FFFF;
	*out = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
	return 0;
}

static int relocate_adr(u32 insn, u64 orig_pc, u64 new_pc, u32 *out)
{
	u32 immlo = (insn >> 29) & 3;
	u32 immhi = (insn >> 5) & 0x7FFFF;
	s64 imm21 = (s64)(((u64)immhi << 2) | immlo);
	u64 target;
	s64 new_off;

	if (imm21 & (1 << 20))
		imm21 -= (1 << 21);
	target = orig_pc + imm21;
	new_off = (s64)(target - new_pc);
	if (new_off >= (1 << 20) || new_off < -(1 << 20))
		return -ERANGE;

	immlo = (u32)new_off & 3;
	immhi = ((u32)new_off >> 2) & 0x7FFFF;
	*out = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
	return 0;
}

static void emit_abs_jump(u32 *buf, u64 target)
{
	buf[0] = 0x58000050;           /* LDR X16, [PC, #8] */
	buf[1] = 0xd61f0200;           /* BR  X16            */
	buf[2] = (u32)(target);        /* addr lo            */
	buf[3] = (u32)(target >> 32);  /* addr hi            */
}

/* ===== text patcher ===== */

static IHOOK_NOCFI int patch_text_n(void *start, u32 *values, int n)
{
	void **addrs;
	int i, ret;

	if (!fn_patch_text)
		return -ENOENT;

	addrs = kmalloc_array(n, sizeof(void *), GFP_KERNEL);
	if (!addrs)
		return -ENOMEM;

	for (i = 0; i < n; i++)
		addrs[i] = start + i * 4;

	cpus_read_lock();
	ret = fn_patch_text(addrs, values, n);
	cpus_read_unlock();

	kfree(addrs);
	return ret;
}

static int patch_text_4(void *target, u32 *insns)
{
	return patch_text_n(target, insns, 4);
}

/* ===== trampoline builder ===== */

/*
 * Slot layout (64 u32 words = 256 bytes):
 *   [0..3]    Entry: LDR X16, #8; BR X16; .quad handler
 *   [16..19]  Original insns (4 words, relocated if PC-relative)
 *   [20..23]  Return: LDR X16, #8; BR X16; .quad target+16
 */

#define ENTRY_W  0
#define ORIG_W   16
#define RET_W    20

static int build_trampoline(struct ihook_entry *h)
{
	u32 buf[SLOT_WORDS];
	u64 target = (u64)h->target_addr;
	u64 slot_base = (u64)h->slot;
	int i, ret;

	memset(buf, 0, sizeof(buf));

	emit_abs_jump(&buf[ENTRY_W], (u64)h->desc->handler);

	for (i = 0; i < 4; i++) {
		u32 insn = h->orig_insns[i];
		u64 orig_pc = target + i * 4;
		u64 new_pc  = slot_base + (ORIG_W + i) * 4;
		u32 relocated;

		if (!is_pc_relative(insn)) {
			buf[ORIG_W + i] = insn;
			continue;
		}

		if ((insn & 0x9F000000) == 0x90000000) {
			ret = relocate_adrp(insn, orig_pc, new_pc, &relocated);
			if (ret) {
				pr_err("ihook: ADRP relocation failed for %s insn[%d]\n",
				       h->desc->name, i);
				return ret;
			}
			buf[ORIG_W + i] = relocated;
			continue;
		}

		if ((insn & 0x9F000000) == 0x10000000) {
			ret = relocate_adr(insn, orig_pc, new_pc, &relocated);
			if (ret) {
				pr_err("ihook: ADR relocation failed for %s insn[%d]\n",
				       h->desc->name, i);
				return ret;
			}
			buf[ORIG_W + i] = relocated;
			continue;
		}

		pr_err("ihook: unsupported PC-relative insn %08x at %s+%d\n",
		       insn, h->desc->name, i * 4);
		return -EOPNOTSUPP;
	}

	emit_abs_jump(&buf[RET_W], target + 16);

	ret = patch_text_n((void *)h->slot, buf, SLOT_WORDS);
	if (ret) {
		pr_err("ihook: trampoline write failed for %s (%d)\n",
		       h->desc->name, ret);
		return ret;
	}

	h->desc->original = (void *)&h->slot[ORIG_W];
	return 0;
}

/* ===== install ===== */

static IHOOK_NOCFI int install_one(struct ihook_entry *h,
				   struct ihook_target *t)
{
	u32 *target;
	u64 entry_addr;
	int i, ret, cls;

	h->target_addr = resolve_symbol(t->name);
	if (!h->target_addr) {
		pr_err("ihook: symbol '%s' not found\n", t->name);
		return -ENOENT;
	}
	target = (u32 *)h->target_addr;

	ret = ihook_classify(t->name, &cls);
	if (ret)
		return ret;
	if (cls == IHOOK_ALREADY_HOOKED) {
		pr_warn("ihook: %s is already hooked — refusing install\n", t->name);
		return -EEXIST;
	}

	for (i = 0; i < 4; i++)
		h->orig_insns[i] = READ_ONCE(target[i]);

	h->has_bti = is_bti_or_pac(h->orig_insns[0]) ? 1 : 0;
	h->desc = t;

	ret = build_trampoline(h);
	if (ret)
		return ret;

	entry_addr = (u64)&h->slot[ENTRY_W];

	if (h->has_bti) {
		h->patch_insns[0] = BTI_C;
		ret = encode_b((u64)h->target_addr + 4, entry_addr, &h->patch_insns[1]);
		if (ret) {
			pr_err("ihook: B out of range for %s with BTI\n", t->name);
			return ret;
		}
		h->patch_insns[2] = encode_brk(4);
		h->patch_insns[3] = encode_brk(4);
	} else {
		ret = encode_b((u64)h->target_addr, entry_addr, &h->patch_insns[0]);
		if (ret) {
			pr_warn("ihook: B out of range for %s, using abs jump\n", t->name);
			h->patch_insns[0] = 0x58000050;
			h->patch_insns[1] = 0xd61f0200;
			h->patch_insns[2] = (u32)(entry_addr);
			h->patch_insns[3] = (u32)(entry_addr >> 32);
			goto skip_fillers;
		}
		for (i = 1; i < 4; i++)
			h->patch_insns[i] = encode_brk(4);
	}

skip_fillers:
	for (i = 0; i < 4; i++) {
		u32 cur = READ_ONCE(target[i]);

		if (cur != h->orig_insns[i]) {
			pr_err("ihook: text changed during install of %s (word %d: %08x != %08x)\n",
			       t->name, i, cur, h->orig_insns[i]);
			return -EAGAIN;
		}
	}

	ret = patch_text_4(h->target_addr, h->patch_insns);
	if (ret) {
		pr_err("ihook: patch_text failed for %s (%d)\n", t->name, ret);
		return ret;
	}

	for (i = 0; i < 4; i++) {
		u32 cur = READ_ONCE(target[i]);

		if (cur != h->patch_insns[i]) {
			pr_err("ihook: post-patch verify failed for %s (word %d: %08x != %08x)\n",
			       t->name, i, cur, h->patch_insns[i]);
			return -EIO;
		}
	}

	h->active = true;
	pr_info("ihook: installed on %s @ %px (slot %d, bti=%d)\n",
		t->name, h->target_addr, (int)(h - hooks), h->has_bti);
	return 0;
}

int IHOOK_NOCFI ihook_install(struct ihook_target *targets, int count)
{
	int i, ret;

	if (count < 1 || count > SLOT_COUNT)
		return -EINVAL;

	mutex_lock(&ihook_mutex);

	if (hooks_installed + count > SLOT_COUNT) {
		mutex_unlock(&ihook_mutex);
		return -ENOSPC;
	}

	for (i = 0; i < count; i++) {
		struct ihook_entry *h = &hooks[hooks_installed + i];

		if (!targets[i].name || !targets[i].handler) {
			ret = -EINVAL;
			goto rollback;
		}

		h->slot = &trampoline_slots[(hooks_installed + i) * SLOT_WORDS];
		ret = install_one(h, &targets[i]);
		if (ret)
			goto rollback;
	}

	hooks_installed += count;
	mutex_unlock(&ihook_mutex);
	return 0;

rollback:
	while (--i >= 0) {
		struct ihook_entry *h = &hooks[hooks_installed + i];

		if (h->active) {
			int rc = patch_text_4(h->target_addr, h->orig_insns);

			if (rc)
				pr_err("ihook: rollback failed for %s (%d)\n",
				       h->desc->name, rc);
			h->active = false;
		}
	}
	mutex_unlock(&ihook_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(ihook_install);

/* ===== uninstall ===== */

int IHOOK_NOCFI ihook_uninstall(struct ihook_target *targets, int count)
{
	int i, failures = 0;

	mutex_lock(&ihook_mutex);

	for (i = count - 1; i >= 0; i--) {
		struct ihook_entry *h = NULL;
		u32 *target;
		int j, ret;

		for (j = 0; j < hooks_installed; j++) {
			if (hooks[j].desc == &targets[i] && hooks[j].active) {
				h = &hooks[j];
				break;
			}
		}
		if (!h)
			continue;

		target = (u32 *)h->target_addr;

		for (j = 0; j < 4; j++) {
			u32 cur = READ_ONCE(target[j]);

			if (cur != h->patch_insns[j]) {
				pr_err("ihook: text under %s word %d changed (%08x != %08x); refusing\n",
				       h->desc->name, j, cur, h->patch_insns[j]);
				failures++;
				goto next;
			}
		}

		ret = patch_text_4(h->target_addr, h->orig_insns);
		if (ret) {
			pr_err("ihook: failed to restore %s (%d); module must stay loaded\n",
			       h->desc->name, ret);
			failures++;
			goto next;
		}

		for (j = 0; j < 4; j++) {
			u32 cur = READ_ONCE(target[j]);

			if (cur != h->orig_insns[j]) {
				pr_err("ihook: post-restore verify failed for %s word %d\n",
				       h->desc->name, j);
				failures++;
				goto next;
			}
		}

		h->active = false;
		h->desc->original = NULL;
		pr_info("ihook: uninstalled from %s\n", h->desc->name);
next:;
	}

	mutex_unlock(&ihook_mutex);

	if (failures) {
		pr_err("ihook: %d hook(s) still live; module must stay loaded\n", failures);
		return -EBUSY;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ihook_uninstall);

/* ===== init / cleanup ===== */

int IHOOK_NOCFI ihook_init(void)
{
	int ret;

	ret = bootstrap_kln();
	if (ret) {
		pr_err("ihook: kallsyms_lookup_name bootstrap failed (%d)\n", ret);
		return ret;
	}

	fn_patch_text = resolve_symbol("aarch64_insn_patch_text");
	if (!fn_patch_text) {
		pr_err("ihook: aarch64_insn_patch_text not found\n");
		return -ENOENT;
	}

	memset(hooks, 0, sizeof(hooks));
	hooks_installed = 0;

	pr_info("ihook: init ok, %d slots (%d bytes each)\n",
		SLOT_COUNT, SLOT_SIZE);
	return 0;
}
EXPORT_SYMBOL_GPL(ihook_init);

void ihook_cleanup(void)
{
	int i;

	for (i = 0; i < hooks_installed; i++) {
		if (hooks[i].active)
			pr_warn("ihook: cleanup with hook %d still active (%s)\n",
				i, hooks[i].desc ? hooks[i].desc->name : "?");
	}
}
EXPORT_SYMBOL_GPL(ihook_cleanup);

/* ===== pre-existing hook classifier ===== */

static inline bool is_brk_any(u32 insn)
{
	return (insn & 0xFFE0001F) == 0xD4200000;
}

static inline bool is_uncond_branch(u32 insn)
{
	u32 top = insn & 0xFC000000;
	return top == 0x14000000 || top == 0x94000000;
}

static inline s64 decode_branch_imm(u32 insn)
{
	s32 imm26 = (s32)((insn & 0x03FFFFFF) << 6) >> 6;
	return (s64)imm26 * 4;
}

static inline bool is_abs_jump_veneer(u32 i0, u32 i1)
{
	return i0 == 0x58000050 && i1 == 0xd61f0200;
}

int IHOOK_NOCFI ihook_classify(const char *sym_name, int *result)
{
	void *addr;
	u32 *code;
	u32 insn0, insn1;
	int eff;

	if (!sym_name || !result)
		return -EINVAL;
	if (!k_lookup_name)
		return -ENODEV;

	addr = resolve_symbol(sym_name);
	if (!addr)
		return -ENOENT;

	code = (u32 *)addr;
	insn0 = READ_ONCE(code[0]);
	insn1 = READ_ONCE(code[1]);

	eff = is_bti_or_pac(insn0) ? 1 : 0;

	if (is_brk_any(insn0)) {
		*result = IHOOK_ALREADY_HOOKED;
		return 0;
	}
	if (eff == 1 && is_brk_any(insn1)) {
		*result = IHOOK_ALREADY_HOOKED;
		return 0;
	}

	{
		u32 check = (eff == 0) ? insn0 : insn1;

		if (is_uncond_branch(check)) {
			s64 off = decode_branch_imm(check);
			if (off < 0 || off >= 4096) {
				*result = IHOOK_ALREADY_HOOKED;
				return 0;
			}
		}

		if (is_abs_jump_veneer(insn0, insn1)) {
			*result = IHOOK_ALREADY_HOOKED;
			return 0;
		}
	}

	*result = IHOOK_CLEAN;
	return 0;
}
EXPORT_SYMBOL_GPL(ihook_classify);

int ihook_patch_text(void *addr, u32 *values, int count)
{
	return patch_text_n(addr, values, count);
}
EXPORT_SYMBOL_GPL(ihook_patch_text);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ARM64 inline-hook engine with instruction relocation and hook classifier");
MODULE_AUTHOR("Yalmaz Imran");
