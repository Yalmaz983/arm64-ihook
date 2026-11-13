/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ihook.h — ARM64 inline-hook engine API.
 *
 * Safe runtime function interception for arm64 Linux kernels (5.10+).
 * Handles BTI/PAC prologues, ADRP/ADR relocation, atomic rollback,
 * and pre-existing hook detection.
 */
#ifndef IHOOK_H
#define IHOOK_H

#include <linux/types.h>

#define IHOOK_MAX_SLOTS  16

/* Classifier results. */
#define IHOOK_CLEAN          0
#define IHOOK_ALREADY_HOOKED 1

struct ihook_target {
	const char *name;       /* kernel symbol to intercept */
	void       *handler;    /* replacement function */
	void       *original;   /* OUT: trampoline calling the real function */
};

int  ihook_install(struct ihook_target *targets, int count);
int  ihook_uninstall(struct ihook_target *targets, int count);
int  ihook_init(void);
void ihook_cleanup(void);

int  ihook_classify(const char *sym_name, int *result);
int  ihook_patch_text(void *addr, u32 *values, int count);

#endif
