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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "i915_mem_user.h"

static struct bpf_object *obj;
static struct bpf_program *prog;
static struct bpf_link *links[5];
static int links_num;
mem_mode_t global_mode;

// obj migration latency structures
struct migrate_time_key
{
    __u64 pid;
    __u64 time;
};

struct migrate_time_rec
{
    __u64 end_time;
    /// u64 size;
    char proc_name[16];
};

// obj migration counting structures
struct counter_rec
{
    __u64 count;
    __u64 size;
};

struct combined_key
{
    __u32 key1;
    __u32 key2;
};

struct migrate_key
{
    __u64 pid;
    __u64 time;
};

struct migrate_rec
{
    __s32 dev;
    __u64 obj;
    __u64 size;
    char src_region[MEM_REGION_DESC_SIZE];
    char dst_region[MEM_REGION_DESC_SIZE];
    bool has_pages;
};

// gpu page fault counting structures

struct gpu_pagefault_key
{
    __u64 pid;
    __u64 time;
};

struct gpu_pagefault_rec
{
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

// cpu page fault counting structures
struct cpu_pagefault_key
{
    __u64 pid;
    __u64 time;
};

struct cpu_pagefault_rec
{
    __u64 mem_obj;
    __u64 addr;
};

static void print_object_migrate_time(void)
{
    struct migrate_time_key key = {0, 0}, next_key;
    __u64 pid, time;
    __u64 end_time;
    char proc_name[16];
    struct migrate_time_rec value;
    int map_fd;

    map_fd = bpf_object__find_map_fd_by_name(obj, "object_migrate_time_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            pid = next_key.pid;
            time = next_key.time;
            end_time = value.end_time;
            strncpy(proc_name, value.proc_name, sizeof(proc_name));
            printf("debug print: time %-8llu pid %u to end time %-8llu migrated from process %s\n",
                time, get_pid_from_pid_tgid(pid), end_time, proc_name);
        }
        key = next_key;
    }
}

int read_object_migrate_time(size_t size, struct obj_migrate_time_trace_record *buf, int *count, int *oversize)
{
    struct migrate_time_key key = {0, 0}, next_key;
    struct migrate_time_rec value;
    struct obj_migrate_time_trace_record record;
    int map_fd;

    *oversize = 0;
    if (count == 0 || buf == 0)
        return 1;

    int limit = (int)size;
    int cnt = 0;

    map_fd = bpf_object__find_map_fd_by_name(obj, "object_migrate_time_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            record.pid = next_key.pid;
            record.time = next_key.time;
            record.end_time = value.end_time;
            strncpy(record.proc_name, value.proc_name, sizeof(record.proc_name));
            if (cnt < limit)
            {
                // Using mem copy as there is a char array in the structure
                memcpy(buf, &record, sizeof(struct obj_migrate_time_trace_record));
                buf++;
            }
            else
                *oversize = 1;
            cnt++;

            if (global_mode == debug)
            {
                printf("i915_mem_user: time %-8llu pid %u to end time %-8llu migrated from process %s\n",
                    record.time, get_pid_from_pid_tgid(record.pid), record.end_time, record.proc_name);
            }
        }
        key = next_key;
    }
    ///TODO: clean up the maps
    *count = cnt;
    return 0;
}

static void print_object_migrate_counter(void)
{
    struct migrate_key key = {0, 0}, next_key;
    __u32 src, dst;
    __u64 pid, time;
    struct migrate_rec value;
    int map_fd;

    map_fd = bpf_object__find_map_fd_by_name(obj, "object_migrate_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            pid = next_key.pid;
            time = next_key.time;
            printf("debug print: time %-8llu pid %u dev %d migrate obj %p [size %llu bytes] %s %s from %s to %s\n",
                time, get_pid_from_pid_tgid(pid),
                value.dev,
                (void*)value.obj,
                value.size,
                value.has_pages ? "with" : "without", "backing storage",
                value.src_region,
                value.dst_region);
        }
        key = next_key;
    }
}


int read_object_migrate_counter(size_t size, struct obj_migrate_cnt_trace_record *buf, int *count, int *oversize)
{
    struct migrate_key key = {0, 0}, next_key;
    struct migrate_rec value;
    struct obj_migrate_cnt_trace_record record;
    int map_fd;

    *oversize = 0;
    if (count == 0 || buf == 0)
        return 1;

    int limit = (int)size;
    int cnt = 0;

    map_fd = bpf_object__find_map_fd_by_name(obj, "object_migrate_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            record.pid = next_key.pid;
            record.time = next_key.time;
            record.dev = value.dev;
            record.obj = value.obj;
            record.size = value.size;
            strcpy(record.src_region, value.src_region);
            strcpy(record.dst_region, value.dst_region);
            record.has_pages = value.has_pages;
            if (cnt < limit)
            {
                *(buf) = record;
                buf++;
            }
            else
                *oversize = 1;
            cnt++;

            if (global_mode == debug)
            {
                printf("i915_mem_user: time %-8llu pid %u dev %d migrate obj %p [size %llu bytes] %s %s from %s to %s\n",
                    record.time, get_pid_from_pid_tgid(record.pid),
                    record.dev,
                    (void*)record.obj,
                    record.size,
                    record.has_pages ? "with" : "without", "backing storage",
                    value.src_region,
                    value.dst_region);
            }
        }
        key = next_key;
    }
    ///TODO: clean up the maps
    *count = cnt;
    return 0;
}

static void print_gpu_fault(void)
{
    struct gpu_pagefault_key key = {0, 0}, next_key;
    __u64 pid, time;
    struct gpu_pagefault_rec value;
    int map_fd;

    map_fd = bpf_object__find_map_fd_by_name(obj, "gpu_fault_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            pid = next_key.pid;
            time = next_key.time;

            printf("debug print: time %-8llu pid %u dev %d GPU %s fault [access type %d] on %s mem obj %p [size %lld] addr %llx %s size 0x%llx\n",
                time, get_pid_from_pid_tgid(pid),
                value.dev,
                (value.access_type == ACCESS_TYPE_READ) ? "read " : "write", // TODO: Define other regions
                value.access_type,
                value.region,
                (void*)value.obj,
                value.obj_size,
                value.addr,
                value.is_bound ? " bound" : "",
                value.vma_size);
        }
        key = next_key;
    }
}

int read_gpu_fault(size_t size, struct gpu_pagefault_trace_record *buf, int *count, int *oversize)
{
    struct gpu_pagefault_key key = {0, 0}, next_key;
    struct gpu_pagefault_rec value;
    struct gpu_pagefault_trace_record record;
    int map_fd;

    *oversize = 0;
    if (count == 0 || buf == 0)
        return 1;

    int limit = (int)size;
    int cnt = 0;

    map_fd = bpf_object__find_map_fd_by_name(obj, "gpu_fault_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            record.pid  = next_key.pid;
            record.time = next_key.time;
            record.dev  = value.dev;
            record.vm   = value.vm;
            record.obj  = value.obj;
            strcpy(record.region, value.region);
            record.obj_size        = value.obj_size;
            record.addr            = value.addr;
            record.vma_size        = value.vma_size;
            record.asid            = value.asid;
            record.pg_sz_mask      = value.pg_sz_mask;
            record.pdata           = value.pdata;
            record.access_type     = value.access_type;
            record.fault_type      = value.fault_type;
            record.fault_level     = value.fault_level;
            record.engine_class    = value.engine_class;
            record.engine_instance = value.engine_instance;
            record.is_bound        = value.is_bound;

            if (cnt < limit)
            {
                *(buf) = record;
                buf++;
            }
            else
                *oversize = 1;
            cnt++;

            if (global_mode == debug)
            {
                printf("i915_mem_user: time %-8llu pid %u dev %d GPU %s fault on %s mem obj %p [size %lld] addr %llx %s size 0x%llx\n",
                    record.time, get_pid_from_pid_tgid(record.pid),
                    record.dev,
                    (record.access_type == ACCESS_TYPE_READ) ? "read " : "write", // TODO: Define other regions
                    record.region,
                    (void*)record.obj,
                    record.obj_size,
                    record.addr,
                    record.is_bound ? " bound" : "",
                    record.vma_size);
            }
        }
        key = next_key;
    }
    ///TODO: clean up the maps
    *count = cnt;
    return 0;
}

static void print_cpu_fault(void)
{
    struct cpu_pagefault_key key = {0, 0}, next_key;
    __u64 pid, time;
    __u64 dev, mem_obj, addr;

    struct cpu_pagefault_rec value;
    int map_fd;

    map_fd = bpf_object__find_map_fd_by_name(obj, "cpu_fault_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            pid = next_key.pid;
            time = next_key.time;

            mem_obj = value.mem_obj;
            addr = value.addr;
            printf("debug print: time %-8llu pid %u CPU memory fault, obj %llx, addr %llx\n",
                time, get_pid_from_pid_tgid(pid),
                mem_obj, addr);
        }
        key = next_key;
    }
}

int read_cpu_fault(size_t size, struct cpu_pagefault_trace_record *buf, int *count, int *oversize)
{
    struct cpu_pagefault_key key = {0, 0}, next_key;
    struct cpu_pagefault_rec value;
    struct cpu_pagefault_trace_record record;
    int map_fd;

    *oversize = 0;
    if (count == 0 || buf == 0)
        return 1;

    int limit = (int)size;
    int cnt = 0;

    map_fd = bpf_object__find_map_fd_by_name(obj, "cpu_fault_map");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
        {
            record.pid = next_key.pid;
            record.time = next_key.time;
            record.mem_obj = value.mem_obj;
            record.addr = value.addr;
            if (cnt < limit)
            {
                *(buf) = record;
                buf++;
            }
            else
                *oversize = 1;
            cnt++;

            if (global_mode == debug)
            {
                printf("i915_mem_user: time %-8llu pid %u CPU memory fault, obj %llx, addr %llx\n",
                    record.time, get_pid_from_pid_tgid(record.pid), record.mem_obj, record.addr);
            }
        }
        key = next_key;
    }
    ///TODO: clean up the maps
    *count = cnt;
    return 0;
}

void print_bpf_mem(void)
{
    print_object_migrate_time();
    print_object_migrate_counter();
    print_gpu_fault();
    print_cpu_fault();
}

int init_bpf_mem(const char *path, mem_mode_t mode)
{
    char filename[PATH_MAX];
    int map_fd, j = 0;
    global_mode = mode;

#if 0
    // rlimit must be set via a script
    // later implement this setting check here
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
        return 1;
    }
#endif

    if (strlen(path) == 0)
    {
        return 1;
        fprintf(stderr, "ERROR: BPF object file path is empty\n");
    }
    strcpy(filename, path);
    printf("BPF object file path: %s\n", filename);

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    /* load BPF program */
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        destroy_bpf_mem();
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "object_migrate_time_map");
    if (map_fd < 0)
    {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        destroy_bpf_mem();
        return 1;
    }

    bpf_object__for_each_program(prog, obj)
    {
        links[j] = bpf_program__attach(prog);
        if (libbpf_get_error(links[j])) {
            fprintf(stderr, "ERROR: bpf_program__attach failed\n");
            links[j] = NULL;
            destroy_bpf_mem();
            return 1;
        }
        j++; links_num=j;
    }
    return 0;
}

int destroy_bpf_mem()
{
    int j = links_num;;
    for (j--; j >= 0; j--)
    {
        bpf_link__destroy(links[j]);
    }

    bpf_object__close(obj);
    return 0;
}
