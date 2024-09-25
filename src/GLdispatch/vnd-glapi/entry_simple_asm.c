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

/**
 * \file
 *
 * Common functions for assembly stubs other than ARMv7.
 *
 * These functions are used for the assembly stubs on every architecture except
 * for ARMv7.
 *
 * ARMv7 is different because the ARM stubs have to add 1 to the address of
 * each entrypoint to force switching to Thumb mode.
 */

mapi_func entry_get_public(int index)
{
#if defined(__CHERI_PURE_CAPABILITY__)
    const ptraddr_t sentry_addr = __builtin_cheri_address_get(public_entry_start);
    const ptraddr_t stub_addr = sentry_addr + (index * entry_stub_size);
    const void* pcc = __builtin_cheri_program_counter_get();
    uintptr_t result_cap = (uintptr_t) __builtin_cheri_address_set(pcc, stub_addr);
    return (mapi_func) __builtin_cheri_seal_entry(result_cap | 1);
#else   // !__CHERI_ PURE_CAPABILITY__
    return (mapi_func)(public_entry_start + (index * entry_stub_size));
#endif  // !__CHERI_PURE_CAPABILITY__
}
