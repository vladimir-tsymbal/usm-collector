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

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/bpf.h>

#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// defined in enum intel_region_id at intel_memory_region.h
#define INTEL_REGION_SMEM 0
#define INTEL_REGION_LMEM 1
#define INTEL_REGION_STOLEN_SMEM 5

// from trace point format
#define  MEM_REGION_DESC_SIZE 16

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

struct migrate_time_key
{
    u64 pid;
    u64 time;
};

struct migrate_time_rec
{
    u64 end_time;
    char proc_name[TASK_COMM_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct migrate_key);
    __type(value, struct migrate_time_rec);
    __uint(max_entries, 4096);
} object_migrate_time_map SEC(".maps");

u64 start_time_migrate = 0;
SEC("kprobe/i915_gem_object_migrate")
int migrate_start(struct pt_regs *ctx)
{
    // To be used for matching pid of migrate_end function
    // u64 pid = bpf_get_current_pid_tgid();
    start_time_migrate = bpf_ktime_get_ns();
    return 0;
}

SEC("kretprobe/i915_gem_object_migrate")
int migrate_end(struct pt_regs *ctx)
{
    u64 pid = bpf_get_current_pid_tgid();
    u64 end_time_migrate = bpf_ktime_get_ns();
    struct migrate_time_rec zero = {0};
    struct migrate_time_rec *val;

    // Possible use of fetching object size form the context
    // u64 size = 0;
    // struct drm_i915_gem_object *obj = (struct drm_i915_gem_object *)PT_REGS_PARM1(ctx);
    // size = obj->base.size;

    // protect from missing start migration
    if (!start_time_migrate)
        return 0;
    ///TODO: protect from pid mismatch
    struct migrate_time_key key = {pid, start_time_migrate};

    val = bpf_map_lookup_elem(&object_migrate_time_map, &key);
    if (!val)
    {
        bpf_map_update_elem(&object_migrate_time_map, &key, &zero, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&object_migrate_time_map, &key);
        if (!val)
            return 0;
    }

    val->end_time = end_time_migrate;
    start_time_migrate = 0;

    bpf_get_current_comm(&val->proc_name, sizeof(val->proc_name));

    return 0;
}

struct migrate_key
{
    u64 pid;
    u64 time;
};

struct migrate_rec
{
    int dev;
    u64 obj;
    u64 size;
    char src_region[MEM_REGION_DESC_SIZE];
    char dst_region[MEM_REGION_DESC_SIZE];
    bool has_pages;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct migrate_key);
    __type(value, struct migrate_rec);
    __uint(max_entries, 4096);
} object_migrate_map SEC(".maps");

struct i915_gem_object_migrate_ctx
{
    u64 pad;
    int dev;
    u64 obj;
    u64 size;
    char src_region[MEM_REGION_DESC_SIZE];
    char dst_region[MEM_REGION_DESC_SIZE];
    bool has_pages;
};

SEC("tracepoint/i915/i915_gem_object_migrate")
int i915_gem_object_migrate(struct i915_gem_object_migrate_ctx *ctx)
{
    u64 start_time_migrate = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();

    struct migrate_rec zero = {0, 0, 0, {0}, {0}, 0};
    struct migrate_rec *val;

    struct migrate_key key = {pid, start_time_migrate};

    val = bpf_map_lookup_elem(&object_migrate_map, &key);
    if (!val)
    {
        bpf_map_update_elem(&object_migrate_map, &key, &zero, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&object_migrate_map, &key);
        if (!val)
            return 0;
    }

    val->dev  = ctx->dev;
    val->obj  = ctx->obj;
    val->size = ctx->size;
    bpf_probe_read_str(val->src_region, MEM_REGION_DESC_SIZE, ctx->src_region);
    bpf_probe_read_str(val->dst_region, MEM_REGION_DESC_SIZE, ctx->dst_region);
    val->has_pages = ctx->has_pages;

    return 0;
}

struct gpu_pagefault_key
{
    u64 pid;
    u64 time;
};

struct gpu_pagefault_rec
{
    int dev;
    u64 vm;
    u64 obj;
    char region[MEM_REGION_DESC_SIZE];
    u64 obj_size;
    u64 addr;
    u64 vma_size;
    u32 asid;
    u32 pg_sz_mask;
    u16 pdata;
    u8  access_type;
    u8  fault_type;
    u8 	fault_level;
    u8  engine_class;
    u8  engine_instance;
    bool is_bound;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct gpu_pagefault_key);
    __type(value, struct gpu_pagefault_rec);
    __uint(max_entries, 16384);
} gpu_fault_map SEC(".maps");

struct i915_mm_fault_ctx
{
    u64 pad;
    int dev;
    u64 vm;
    u64 obj;
    char region[MEM_REGION_DESC_SIZE];
    u64 obj_size;
    u64 addr;
    u64 vma_size;
    u32 asid;
    u32 pg_sz_mask;
    u16 pdata;
    u8  access_type;
    u8  fault_type;
    u8  fault_level;
    u8  engine_class;
    u8  engine_instance;
    bool is_bound;
};

SEC("tracepoint/i915/i915_mm_fault")
int gpu_fault(struct i915_mm_fault_ctx *ctx)
{
    u64 start_time_gpu_pagefault = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();

    struct gpu_pagefault_rec zero = {0, 0, 0, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    struct gpu_pagefault_rec *val;

    struct gpu_pagefault_key key = {pid, start_time_gpu_pagefault};

    val = bpf_map_lookup_elem(&gpu_fault_map, &key);
    if (!val)
    {
        bpf_map_update_elem(&gpu_fault_map, &key, &zero, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&gpu_fault_map, &key);
        if (!val)
            return 0;
    }

    val->dev       = ctx->dev;
    val->vm        = ctx->vm;
    val->obj       = ctx->obj;
    bpf_probe_read_str(val->region, MEM_REGION_DESC_SIZE, ctx->region);
    val->obj_size  = ctx->obj_size;
    val->addr      = ctx->addr;
    val->vma_size  = ctx->vma_size;
    val->asid      = ctx->asid;
    val->pg_sz_mask      = ctx->pg_sz_mask;
    val->pdata           = ctx->pdata;
    val->access_type     = ctx->access_type;
    val->fault_type      = ctx->fault_type;
    val->fault_level     = ctx->fault_level;
    val->engine_class    = ctx->engine_class;
    val->engine_instance = ctx->engine_instance;
    val->is_bound        = ctx->is_bound;

    return 0;
}

struct cpu_pagefault_key
{
    u64 pid;
    u64 time;
};

struct cpu_pagefault_rec
{
    u64 obj;
    u64 addr;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct cpu_pagefault_key);
    __type(value, struct cpu_pagefault_rec);
    __uint(max_entries, 16384);
} cpu_fault_map SEC(".maps");

struct i915_gem_object_fault_ctx
{
    u64 pad;
    u64 obj;
    u64 addr;
    u64 index;
    u8  gtt;
    u8  write;
};

SEC("tracepoint/i915/i915_gem_object_fault")
int cpu_fault(struct i915_gem_object_fault_ctx *ctx)
{
    u64 obj = ctx->obj;
    u64 addr = ctx->addr;

    u64 start_time_cpu_pagefault = bpf_ktime_get_ns();
    u64 pid = bpf_get_current_pid_tgid();

    struct cpu_pagefault_rec zero = {0, 0};
    struct cpu_pagefault_rec *val;

    struct cpu_pagefault_key key = {pid, start_time_cpu_pagefault};

    val = bpf_map_lookup_elem(&cpu_fault_map, &key);
    if (!val)
    {
        bpf_map_update_elem(&cpu_fault_map, &key, &zero, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&cpu_fault_map, &key);
        if (!val)
            return 0;
    }

    val->obj = obj;
    val->addr = addr;

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
