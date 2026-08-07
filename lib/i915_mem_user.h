/*
 * Copyright (C) 2023 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef I915_MEM_USER_H
#define I915_MEM_USER_H

#ifdef __cplusplus
extern "C" {
#endif

#define INTEL_REGION_SMEM 0
#define INTEL_REGION_LMEM 1
#define INTEL_REGION_STOLEN_SMEM 5

// from trace point format
#define  MEM_REGION_DESC_SIZE 16
// fomr bpf spec TASK_COMM_LEN 16
#define  PROC_NAME_STR_SIZE 16

struct obj_migrate_time_trace_record
{
    __u64 pid;
    __u64 time;
    __u64 end_time;
    char proc_name[PROC_NAME_STR_SIZE];
};

struct obj_migrate_cnt_trace_record
{
    __u64 pid;
    __u64 time;
    __s32 dev;
    __u64 obj;
    __u64 size;
    char src_region[MEM_REGION_DESC_SIZE];
    char dst_region[MEM_REGION_DESC_SIZE];
    bool has_pages;
};

// cpu page fault counting structures
struct cpu_pagefault_trace_record
{
    __u64 pid;
    __u64 time;
    __u64 mem_obj;
    __u64 addr;
};

// gpu page fault counting structures
struct gpu_pagefault_trace_record
{
    __u64 pid;
    __u64 time;
    __s32 dev;
    __u64 vm;
    __u64 obj;
    char region[MEM_REGION_DESC_SIZE];
    __u64 obj_size;
    __u64 addr;
    __u64 vma_size;
    __u32 asid;
    __u32 pg_sz_mask;
    __u16 pdata;
    __u8  access_type;
    __u8  fault_type;
    __u8  fault_level;
    __u8  engine_class;
    __u8  engine_instance;
    bool  is_bound;
};

// i915 intel_pagefault.h
enum access_type {
    ACCESS_TYPE_READ = 0,
    ACCESS_TYPE_WRITE = 1,
    ACCESS_TYPE_ATOMIC = 2,
    ACCESS_TYPE_RESERVED = 3,
};



typedef enum
{
    trace = 0,
    check,
    debug
} mem_mode_t;

static inline __u32 get_pid_from_pid_tgid(__u64 pid)
{
    return pid >> 32;
}

static inline __u32 get_tid_from_pid_tgid(__u64 pid)
{
    return (__u32)pid;
}

int init_bpf_mem(const char *path, mem_mode_t mode);

int destroy_bpf_mem();

void print_bpf_mem();

void read_bpf_mem();

int read_cpu_fault(size_t size, struct cpu_pagefault_trace_record *buf, int *count, int *oversize);

int read_gpu_fault(size_t size, struct gpu_pagefault_trace_record *buf, int *count, int *oversize);

int read_object_migrate_counter(size_t size, struct obj_migrate_cnt_trace_record *buf, int *count, int *oversize);

int read_object_migrate_time(size_t size, struct obj_migrate_time_trace_record *buf, int *count, int *oversize);

#ifdef __cplusplus
}
#endif

#endif // I915_MEM_USER_H
