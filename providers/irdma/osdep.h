/*******************************************************************************
 *
 * Copyright (c) 2018 - 2019 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *    - Redistributions of source code must retain the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 ******************************************************************************/

#ifndef IRDMA_OSDEP_H
#define IRDMA_OSDEP_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <util/udma_barrier.h>
#include <linux/types.h>
#include <inttypes.h>

#define u8  __u8
#define u16 __u16
#define u32 __u32
#define u64 __u64

#define MAKEMASK(m, s) ((m) << (s))
#define BIT(x)	       (1UL << (x))
#define BIT_ULL(x)     (1ULL << (x))

static inline void db_wr32(u32 val, u32 *wqe_word)
{
	*wqe_word = val;
}

#endif /* IRDMA_OSDEP_H */
