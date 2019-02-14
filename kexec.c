/*-
 * Copyright (c) 2015 xhyve developers
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ???, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <machine/vmm.h>
#include <vmmapi.h>
#include <assert.h>
#include "kexec.h"

#ifndef ALIGNUP
#define ALIGNUP(x, a) (((x - 1) & ~(a - 1)) + a)
#endif

#ifndef ALIGNDOWN
#define ALIGNDOWN(x, a) (-(a) & (x))
#endif

#define BASE_GDT 0x2000ull
#define BASE_ZEROPAGE 0x3000ull
#define BASE_CMDLINE 0x4000ull
#define BASE_KERNEL 0x100000ull
#define HDRS 0x53726448 /* SrdH */

static struct {
	uintptr_t base;
	size_t size;
} lowmem, kernel, ramdisk;

static struct {
	char *kernel;
	char *initrd;
	char *cmdline;
} config;

static int
kexec_load_kernel(struct vmctx *ctx, char *path, char *cmdline) {
	uint64_t kernel_offset, kernel_size, kernel_init_size, kernel_start, mem_k;
	size_t sz, cmdline_len;
	volatile struct zero_page *zp;
	FILE *f;

	if ((lowmem.size < (BASE_ZEROPAGE + sizeof(struct zero_page))) ||
		((BASE_ZEROPAGE + sizeof(struct zero_page)) > BASE_CMDLINE))
	{
		return -1;
	}

	zp = ((struct zero_page *) (lowmem.base + ((off_t) BASE_ZEROPAGE)));

	memset(((void *) ((uintptr_t) zp)), 0, sizeof(struct zero_page));

	if (!(f = fopen(path, "r"))) {
		return -1;
	}

	fseek(f, 0L, SEEK_END);
	sz = (size_t) ftell(f);

	if (sz < (0x01f1 + sizeof(struct setup_header))) {
		fclose(f);
		return -1;
	}

	fseek(f, 0x01f1, SEEK_SET);

	if (!fread(((void *) ((uintptr_t) &zp->setup_header)), 1,
		sizeof(zp->setup_header), f))
	{
		fclose(f);
		return -1;
	}

	if ((zp->setup_header.setup_sects == 0) ||    /* way way too old */
		(zp->setup_header.boot_flag != 0xaa55) || /* no boot magic */
		(zp->setup_header.header != HDRS) ||      /* way too old */
		(zp->setup_header.version < 0x020a) ||    /* too old */
		(!(zp->setup_header.loadflags & 1)) ||    /* no bzImage */
		(sz < (((zp->setup_header.setup_sects + 1) * 512) +
		(zp->setup_header.syssize * 16))))        /* too small */
	{
		/* we can't boot this kernel */
		fclose(f);
		return -1;
	}

	kernel_offset = ((zp->setup_header.setup_sects + 1) * 512);
	kernel_size = (sz - kernel_offset);
	kernel_init_size = ALIGNUP(zp->setup_header.init_size, 0x1000ull);
	kernel_start = (zp->setup_header.relocatable_kernel) ?
		ALIGNUP(BASE_KERNEL, zp->setup_header.kernel_alignment) :
		zp->setup_header.pref_address;

	if ((kernel_start < BASE_KERNEL) ||
		 (kernel_size > kernel_init_size) || /* XXX: always true? */
		 ((kernel_start + kernel_init_size) > lowmem.size)) /* oom */
	{
		fclose(f);
		return -1;
	}

	/* copy kernel */
	fseek(f, ((long) kernel_offset), SEEK_SET);
	if (!fread(((void *) (lowmem.base + kernel_start)), 1, kernel_size, f)) {
		fclose(f);
		return -1;
	}

	fclose(f);

	/* copy cmdline */
	cmdline_len = strlen(cmdline);
	if (((cmdline_len + 1)> zp->setup_header.cmdline_size) ||
		((BASE_CMDLINE + (cmdline_len + 1)) > kernel_start))
	{
		return -1;
	}

	memcpy(((void *) (lowmem.base + BASE_CMDLINE)), cmdline, cmdline_len);
	memset(((void *) (lowmem.base + BASE_CMDLINE + cmdline_len)), '\0', 1);
	zp->setup_header.cmd_line_ptr = ((uint32_t) BASE_CMDLINE);
	zp->ext_cmd_line_ptr = ((uint32_t) (BASE_CMDLINE >> 32));

	zp->setup_header.hardware_subarch = 0; /* PC */
	zp->setup_header.type_of_loader = 0xd; /* kexec */

	mem_k = (lowmem.size - 0x100000) >> 10; /* assume lowmem base is at 0 */
	zp->alt_mem_k = (mem_k > 0xffffffff) ? 0xffffffff : ((uint32_t) mem_k);

	zp->e820_map[0].addr = 0x0000000000000000;
	zp->e820_map[0].size = 0x000000000009fc00;
	zp->e820_map[0].type = 1;
	zp->e820_map[1].addr = 0x0000000000100000;
	zp->e820_map[1].size = (lowmem.size - 0x0000000000100000);
	zp->e820_map[1].type = 1;
	if (vm_get_highmem_size(ctx) == 0) {
		zp->e820_entries = 2;
	} else {
		zp->e820_map[2].addr = 0x0000000100000000;
		zp->e820_map[2].size = vm_get_highmem_size(ctx);
		zp->e820_map[2].type = 1;
		zp->e820_entries = 3;
	}

	kernel.base = kernel_start;
	kernel.size = kernel_init_size;

	return 0;
}

static int
kexec_load_ramdisk(char *path) {
	uint64_t ramdisk_start;
	uint32_t initrd_max;
	volatile struct zero_page *zp;
	size_t sz;
	FILE *f;

	zp = ((struct zero_page *) (lowmem.base + BASE_ZEROPAGE));

	if (!(f = fopen(path, "r"))) {;
		return -1;
	}

	fseek(f, 0L, SEEK_END);
	sz = (size_t) ftell(f);
	fseek(f, 0, SEEK_SET);

	/* highest address for loading the initrd */
	if (zp->setup_header.version >= 0x203) {
		initrd_max = zp->setup_header.initrd_addr_max;
	} else {
		initrd_max = 0x37ffffff; /* Hardcoded value for older kernels */
	}

	if (initrd_max >= lowmem.size) {
		initrd_max = ((uint32_t) lowmem.size - 1);
	}

	ramdisk_start = ALIGNDOWN(initrd_max - sz, 0x1000ull);

	if ((ramdisk_start + sz) > lowmem.size) {
		/* not enough lowmem */
		fclose(f);
		return -1;
	}

	/* copy ramdisk */
	if (!fread(((void *) (lowmem.base + ramdisk_start)), 1, sz, f)) {
		fclose(f);
		return -1;
	}

	fclose(f);

	zp->setup_header.ramdisk_image = ((uint32_t) ramdisk_start);
	zp->ext_ramdisk_image = ((uint32_t) (ramdisk_start >> 32));
	zp->setup_header.ramdisk_size = ((uint32_t) sz);
	zp->ext_ramdisk_size = ((uint32_t) (sz >> 32));

	ramdisk.base = ramdisk_start;
	ramdisk.size = sz;

	return 0;
}

int
kexec_init(char *kernel_path, char *initrd_path, char *cmdline) {
	if (!kernel_path)
		return 1;

	config.kernel = kernel_path;
	config.initrd = initrd_path;
	config.cmdline = cmdline;

	return 0;
}

uint64_t
kexec(struct vmctx *ctx)
{
	uint64_t *gdt_entry;
	void *gpa_map;
	int error;

	gpa_map = vm_map_gpa(ctx, 0, vm_get_lowmem_size(ctx));
	lowmem.base = (uintptr_t) gpa_map;
	lowmem.size = vm_get_lowmem_size(ctx);

	if (kexec_load_kernel(ctx, config.kernel,
		config.cmdline ? config.cmdline : "auto"))
	{
		fprintf(stderr, "kexec: failed to load kernel %s\n", config.kernel);
		abort();
	}

	if (config.initrd && kexec_load_ramdisk(config.initrd)) {
		fprintf(stderr, "kexec: failed to load initrd %s\n", config.initrd);
		abort();
	}

	gdt_entry = ((uint64_t *) (lowmem.base + BASE_GDT));
	gdt_entry[0] = 0x0000000000000000; /* null */
	gdt_entry[1] = 0x0000000000000000; /* null */
	gdt_entry[2] = 0x00cf9a000000ffff; /* code */
	gdt_entry[3] = 0x00cf92000000ffff; /* data */
	gdt_entry[4] = 0x0080890000000000; /* tss */

	vcpu_reset(ctx, 0);

	error = vm_set_capability(ctx, 0, VM_CAP_UNRESTRICTED_GUEST, 1);
	assert(error == 0);

	vm_set_desc(ctx, 0, VM_REG_GUEST_GDTR, BASE_GDT, 0x1f, 0);
	vm_set_desc(ctx, 0, VM_REG_GUEST_CS, 0, 0xffffffff, 0xc09b);
	vm_set_desc(ctx, 0, VM_REG_GUEST_DS, 0, 0xffffffff, 0xc093);
	vm_set_desc(ctx, 0, VM_REG_GUEST_ES, 0, 0xffffffff, 0xc093);
	vm_set_desc(ctx, 0, VM_REG_GUEST_SS, 0, 0xffffffff, 0xc093);
	vm_set_desc(ctx, 0, VM_REG_GUEST_TR, 0x1000, 0x67, 0x8b);
	vm_set_desc(ctx, 0, VM_REG_GUEST_LDTR, 0, 0xffff, 0x10082);

	vm_set_register(ctx, 0, VM_REG_GUEST_CS, 0x10);
	vm_set_register(ctx, 0, VM_REG_GUEST_DS, 0x18);
	vm_set_register(ctx, 0, VM_REG_GUEST_ES, 0x18);
	vm_set_register(ctx, 0, VM_REG_GUEST_SS, 0x18);
	vm_set_register(ctx, 0, VM_REG_GUEST_TR, 0x20);
	vm_set_register(ctx, 0, VM_REG_GUEST_LDTR, 0);
	vm_set_register(ctx, 0, VM_REG_GUEST_CR0, 0x21); /* enable protected mode */
	vm_set_register(ctx, 0, VM_REG_GUEST_CR4, 0);
	vm_set_register(ctx, 0, VM_REG_GUEST_RBP, 0);
	vm_set_register(ctx, 0, VM_REG_GUEST_RDI, 0);
	vm_set_register(ctx, 0, VM_REG_GUEST_RBX, 0);
	vm_set_register(ctx, 0, VM_REG_GUEST_RFLAGS, 0x2);
	vm_set_register(ctx, 0, VM_REG_GUEST_RSI, BASE_ZEROPAGE);
	vm_set_register(ctx, 0, VM_REG_GUEST_RIP, kernel.base);

	return kernel.base;
}

int
kexec_parse(const char *opt) {
	char *fw, *opt1, *opt2, *opt3, *cp;
	opt1 = opt2 = opt3 = cp = NULL;

	fw = strdup(opt);

	if (strncmp(fw, "kexec", strlen("kexec")) != 0) {
                goto fail;
        }

// Gets first comma-separated option from cur and stores it in next.
#define NEXTARG(cur, next, scratch) do {                        \
        if (cur && (scratch = strchr(cur, ',')) != NULL) {      \
                *scratch = '\0';                                \
                next = scratch + 1;                             \
        }                                                       \
} while(0)

	NEXTARG(fw, opt1, cp);
	NEXTARG(opt1, opt2, cp);
	NEXTARG(opt2, opt3, cp);

#undef NEXTARG

        // Replace zero length options with NULLs
        opt1 = opt1 && strlen(opt1) ? opt1 : NULL;
        opt2 = opt2 && strlen(opt2) ? opt2 : NULL;
        opt3 = opt3 && strlen(opt3) ? opt3 : NULL;

        int ret;
	ret = kexec_init(opt1, opt2, opt3);
        if (ret)
                goto fail;

        return 0;

fail:
        fprintf(stderr, "Invalid kexec argument\n"
                "    -f kexec,'kernel'[,'initrd'][,'\"cmdline\"']\n");

        return -1;
}

