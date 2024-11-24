/*
 * Copyright (C) 2010 LunarG Inc.
 * Copyright (c) 2015, NVIDIA CORPORATION.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Chia-I Wu <olv@lunarg.com>
 *    Kyle Brenneman <kbrenneman@nvidia.com>
 */

#include "entry.h"
#include "entry_common.h"

#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>

#include "glapi.h"
#include "u_macros.h"
#include "u_current.h"
#include "utils_misc.h"

static int entry_patch_mprotect(int prot)
{
#if GLDISPATCH_ENABLE_PATCHING
    size_t size;
    size_t pageSize = (size_t) sysconf(_SC_PAGESIZE);

    if (((uintptr_t) public_entry_start) % pageSize != 0
            || ((uintptr_t) public_entry_end) % pageSize != 0) {
        assert(((uintptr_t) public_entry_start) % pageSize == 0);
        assert(((uintptr_t) public_entry_end) % pageSize == 0);
        return 0;
    }

    size = ((uintptr_t) public_entry_end) - ((uintptr_t) public_entry_start);

    if (mprotect(public_entry_start, size, prot) != 0) {
        return 0;
    }
    return 1;
#else // GLDISPATCH_ENABLE_PATCHING
    return 0;
#endif
}

int entry_patch_start(void)
{
    // Set the memory protections to read/write/exec.
    // Since this only gets called when no thread has a current context, this
    // could also just be read/write, without exec, and then set it back to
    // read/exec afterward. But then, if the first mprotect succeeds and the
    // second fails, we'll be left with un-executable entrypoints.
    return entry_patch_mprotect(PROT_READ | PROT_WRITE | PROT_EXEC);
}

int entry_patch_finish(void)
{
    return entry_patch_mprotect(PROT_READ | PROT_EXEC);
}

void *entry_get_patch_address(int index)
{
#if defined(__CHERI_PURE_CAPABILITY__)
    const ptraddr_t sentry_addr = __builtin_cheri_address_get(public_entry_start);
    const ptraddr_t stub_addr = sentry_addr + (index * entry_stub_size);
    const void* pcc = __builtin_cheri_program_counter_get();
    uintptr_t result_cap = (uintptr_t) __builtin_cheri_address_set(pcc, stub_addr);
    return (void *) __builtin_cheri_seal_entry(result_cap | 1);
#else   // !__CHERI_PURE_CAPABILITY__
    return (void *) (public_entry_start + (index * entry_stub_size));
#endif  // !__CHERI_PURE_CAPABILITY__
}

void *entry_save_entrypoints(void)
{
    size_t size = ((uintptr_t) public_entry_end) - ((uintptr_t) public_entry_start);
    void *buf = malloc(size);
    if (buf != NULL) {
#if defined(__CHERI_PURE_CAPABILITY__)
        const ptraddr_t sentry_addr = __builtin_cheri_address_get(public_entry_start);
        const void* pcc = __builtin_cheri_program_counter_get();
        uintptr_t src_cap = (uintptr_t) __builtin_cheri_address_set(pcc, sentry_addr);
        memcpy(buf, src_cap, size);
#else   // !__CHERI_PURE_CAPABILITY__
        memcpy(buf, public_entry_start, size);
#endif  // !__CHERI_PURE_CAPABILITY__
    }
    return buf;
}

#if defined(USE_ARMV7_ASM) || defined(USE_AARCH64_ASM)
static void InvalidateCache(void)
{
    // See http://community.arm.com/groups/processors/blog/2010/02/17/caches-and-self-modifying-code
    __builtin___clear_cache(public_entry_start, public_entry_end);
}
#elif defined(USE_PPC64_ASM)
static void InvalidateCache(void)
{
    // Note: We might be able to get away with only invalidating each cache
    // block, instead of every single 32-bit increment. If that works, we'd
    // need to query the AT_DCACHEBSIZE and AT_ICACHEBSIZE values at runtime
    // with getauxval(3).
    size_t dataBlockSize = 4;
    size_t instructionBlockSize = 4;
    char *ptr;

    for (ptr = public_entry_start;
            (uintptr_t) ptr < (uintptr_t) public_entry_end;
            ptr += dataBlockSize) {
        __asm__ __volatile__("dcbst 0, %0" : : "r" (ptr));
    }
    __asm__ __volatile__("sync");

    for (ptr = public_entry_start;
            (uintptr_t) ptr < (uintptr_t) public_entry_end;
            ptr += instructionBlockSize) {
        __asm__ __volatile__("icbi 0, %0" : : "r" (ptr));
    }
    __asm__ __volatile__("isync");
}
#elif defined(USE_LOONGARCH64_ASM)
static void InvalidateCache(void)
{
    __builtin___clear_cache(public_entry_start, public_entry_end);
}
#else
static void InvalidateCache(void)
{
    // Nothing to do here.
}
#endif

void entry_restore_entrypoints(void *saved)
{
    size_t size = ((uintptr_t) public_entry_end) - ((uintptr_t) public_entry_start);
#if defined(__CHERI_PURE_CAPABILITY__)
    const ptraddr_t sentry_addr = __builtin_cheri_address_get(public_entry_start);
    const void* pcc = __builtin_cheri_program_counter_get();
    uintptr_t dst_cap = (uintptr_t) __builtin_cheri_address_set(pcc, sentry_addr);
    memcpy(dst_cap, saved, size);
#else   // !__CHERI_PURE_CAPABILITY__
    memcpy(public_entry_start, saved, size);
#endif  // !__CHERI_PURE_CAPABILITY__
    InvalidateCache();
}

