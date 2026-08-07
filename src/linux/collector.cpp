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

#include <string>
#include <linux/types.h>
#include <time.h> /* for clock_gettime */

#include <cerrno>
#include <dlfcn.h>

#include "collector.hpp"
#include "shared_library.hpp"
#include "print_list.hpp"
#include "trace.hpp"
#include "storage.hpp"
#include "i915_mem_user.h"

namespace usmcollector {

#ifdef USM_TRACE_OUTPUT
#define USM_TRACE(msg) std::cerr << USM_CLASS"::" << __func__ << "(" << __LINE__ << "): " << msg << std::endl
#else
#define USM_TRACE(msg) do {} while (0)
#endif

#define USM_ERROR(msg) std::cerr << "usm: " << msg << std::endl

#define PREFIX_CPU_FLT "usm.cpu.flt"
#define PREFIX_GPU_FLT "usm.gpu.flt"
#define PREFIX_OBJ_MGR_CNT "usm.obj.mgr.cnt"
#define PREFIX_OBJ_MGR_TIME "usm.obj.mgr.time"

#define NS_PER_SECOND 1000000000L

static std::string getLibFileName()
{
    return std::string("lib") + std::string("i915_mem_user") + std::string(".so");
}

static std::string getObjFileName()
{
    return std::string("i915_mem_kern") + std::string(".o");
}

static std::string getLibPath(std::string exe_path)
{
    std::string lib_sub_dir("/../lib64/");
    return exe_path + lib_sub_dir;
}

static bool isFileExists(const char* file_name)
{
    if (file_name == nullptr)
        return false;

    FILE* file = nullptr;
    file = fopen(file_name, "rb");
    if (file != nullptr)
    {
        fclose(file);
        return true;
    }
    return false;
}

#undef USM_CLASS
#define USM_CLASS "USM_Collector"
class Collector : public ICollector
{
public:
    static Collector* instance()
    {
        static Collector object;
        return &object;
    }

    Collector() : m_lib(nullptr) {}

    ~Collector()
    {
        delete m_lib;
    }

    void setTemporaryDirectory(std::string directory)
    {
        m_tempDirectory = directory;
        USM_TRACE("m_tempDirectory = " << m_tempDirectory.c_str());
    }

    void setExperimentDirectory(std::string directory)
    {
        m_experimentDirectory = directory;
        USM_TRACE("m_experimentDirectory = " << m_experimentDirectory.c_str());
    }

    std::string getExperimentDirectory() const
    {
        return m_experimentDirectory.c_str();
    }

    void setTraceFilesDirectory(std::string directory)
    {
        m_traceFilesDirectory = directory;
        USM_TRACE("m_traceFilesDirectory = " << m_traceFilesDirectory.c_str());
    }

    std::string getTraceFilesDirectory() const
    {
        return m_traceFilesDirectory.c_str();
    }

    status_t initialize()
    {
        return stFalse;
    }

    status_t initialize(prof_options::ProfOptions& op);
    status_t destroy();
    status_t start(pid_t pid);
    status_t stop();
    status_t pause();
    status_t resume();

private:

    prof_options::Operations m_operations;
    int m_suboptions;
    int m_eventselect;
    status_t createCpuFaultTrace();
    status_t createGpuFaultTrace();
    status_t createObjMigrateCntTrace();
    status_t createObjMigrateTimeTrace();
    status_t printBpfMem();

    __u64 correctTimer( // returns corrected time to CLOCK_MONOTONIC_RAW
                        __u64 time_mono); // takes CLOCK_MONOTONIC from clock_gettime()
    void getMonoTimerDelta( // calculates time difference
                            struct timespec time_mono,
                            struct timespec time_mono_raw,
                            struct timespec *delta,
                            bool *raw_higher);
    bool m_raw_higher = false;
    bool m_timer_corrected = false;
    uint64_t m_timer_diff = 0;

    std::string m_tempDirectory;
    std::string m_experimentDirectory;
    std::string m_traceFilesDirectory;
    std::string m_hostHame;

    SharedLibrary* m_lib = nullptr;

    std::vector<print_trace_record> m_printList;
}; // class Collector

status_t Collector::initialize(prof_options::ProfOptions& options)
{
    m_hostHame = options.getHostName();
    std::string library_file_name = getLibFileName();
    std::string object_file_name = getObjFileName();
    std::string library_path = getLibPath(options.getExePath());

    std::string library_file_path = library_path + library_file_name;
    if (!isFileExists(library_file_path.c_str()))
    {
        USM_ERROR("Failed to find library: " << library_file_path);
        return stSystemError;
    }

    std::string object_file_path = library_path + object_file_name;
    if (!isFileExists(object_file_path.c_str()))
    {
        USM_ERROR("Failed to find BPF kernel module: " << object_file_path);
        return stSystemError;
    }

    // Setting up data directory and files
    setTraceFilesDirectory(options.getRawDataPath());

    // Setting up modes
    mem_mode_t mode = trace;
    m_operations = options.getOp();

    m_suboptions = options.getSuboptions();
    m_eventselect = options.getEventSelect();

    if (m_operations == prof_options::Operations::opDebug)
        mode = debug;

    USM_TRACE("User library path: " << library_file_path);
    m_lib = SharedLibrary::create(library_file_path);
    if (m_lib == nullptr)
    {
        USM_ERROR("Failed to load library: " << library_file_path);
        return stSystemError;
    }

    decltype(init_bpf_mem)* init_bpf_mem_fn = m_lib->getSym<decltype(init_bpf_mem)*>("init_bpf_mem");
    if (init_bpf_mem_fn == nullptr)
    {
        USM_ERROR("Failed to find init_bpf_mem function in library");
        delete m_lib;
        m_lib = nullptr;
        return stSystemError;
    }

    if (init_bpf_mem_fn(object_file_path.c_str(), mode))
    {
        USM_ERROR("Failed to initialize collector");
        delete m_lib;
        m_lib = nullptr;
        return stFalse;
    }

    return stOk;
}

status_t Collector::destroy()
{
    if (m_lib == nullptr)
    {
        USM_TRACE("No library to unload");
        return stSystemError;
    }

    decltype(destroy_bpf_mem)* destroy_bpf_mem_fn = m_lib->getSym<decltype(destroy_bpf_mem)*>("destroy_bpf_mem");
    if (destroy_bpf_mem_fn == nullptr)
    {
        USM_ERROR("Failed to find Destroy function in library");
        delete m_lib;
        m_lib = nullptr;
        return stSystemError;
    }
    if (destroy_bpf_mem_fn())
    {
        USM_ERROR("Failed destroy functions in library");
        delete m_lib;
        m_lib = nullptr;
        return stSystemError;
    }

    delete m_lib;
    m_lib = nullptr;

    m_printList.clear();
    return stOk;
}

status_t Collector::start(pid_t pid)
{
    USM_TRACE("Start, pid = " << pid);
    return stOk;
}

// The function is used for debugging purpose
// (print data directly from BPF functions)
status_t Collector::printBpfMem()
{

    decltype(print_bpf_mem)* print_bpf_mem_fn = m_lib->getSym<decltype(print_bpf_mem)*>("print_bpf_mem");
    if (print_bpf_mem_fn == nullptr)
    {
        USM_ERROR("Failed to find print_bpf_mem function in library");
        return stSystemError;
    }

    print_bpf_mem_fn();

    return stOk;
}

status_t Collector::createObjMigrateTimeTrace()
{
    if (!(m_eventselect & prof_options::EventSelect::OBJ_MGR_INT || m_eventselect & prof_options::EventSelect::ALL))
    {
        return stFalse;
    }
    int counter = 0, oversize = 0;
    ITrace<obj_migrate_time_trace_record> trace;

    if (m_lib == nullptr)
    {
        USM_TRACE("No library");
        return stSystemError;
    }

    decltype(read_object_migrate_time)* read_object_migrate_time_fn = m_lib->getSym<decltype(read_object_migrate_time)*>("read_object_migrate_time");
    if (read_object_migrate_time_fn == nullptr)
    {
        USM_ERROR("Failed to find read_object_migrate_time function in library");
        return stSystemError;
    }

    int status = read_object_migrate_time_fn(trace.getTraceLimit(), trace.getBuffer(), trace.getCounter(), trace.getOversize());

    counter = *trace.getCounter();
    oversize = *trace.getOversize();

    if (status)
    {
        USM_ERROR("read_object_migrate_time returned bad status");
        return stFalse;
    }
    if (oversize)
    {
        USM_ERROR("read_object_migrate_time returned oversize status");
        return stOutOfMemory;
    }

    trace.resizeTrace(counter); // Bring size of the trace to the number of collected data records
    trace.sortTraceTime(); // Reoorder of records in the trace for 'time' value

    if (m_operations == prof_options::Operations::opPrint) // Print trace
    {
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            print_trace_record r;
            r.time = correctTimer(trace.getTrace()[i].time);
            r.pid = get_pid_from_pid_tgid(trace.getTrace()[i].pid);
            snprintf(r.buf, sizeof(r.buf), "At time %-8llu pid %u tid %u memory object transfer end time %-8llu",
                correctTimer(trace.getTrace()[i].time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid),
                get_tid_from_pid_tgid(trace.getTrace()[i].pid),
                correctTimer(trace.getTrace()[i].end_time));
            m_printList.push_back(r);
        }
    }
    else if (m_operations == prof_options::Operations::opTrace) // Create a trace cvf file
    {
        std::string prefix = PREFIX_OBJ_MGR_TIME;
        prefix += "-hostname-" + m_hostHame;
        IStorage* storage = IStorage::create(m_traceFilesDirectory, prefix);
        if (!storage)
            return stFalse;
        storage->dumpIntervalHeader();
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            storage->dumpIntervalRecord("DATA MIGRATION",
                correctTimer(trace.getTrace()[i].time),
                correctTimer(trace.getTrace()[i].end_time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid));
        }
        delete storage;
    }
    return stOk;
}

status_t Collector::createObjMigrateCntTrace()
{
    if (!(m_eventselect & prof_options::EventSelect::OBJ_MGR_EVT || m_eventselect & prof_options::EventSelect::ALL))
    {
        return stFalse;
    }

    int counter = 0, oversize = 0;
    ITrace<obj_migrate_cnt_trace_record> trace;

    if (m_lib == nullptr)
    {
        USM_TRACE("No library");
        return stSystemError;
    }

    decltype(read_object_migrate_counter)* read_object_migrate_counter_fn = m_lib->getSym<decltype(read_object_migrate_counter)*>("read_object_migrate_counter");
    if (read_object_migrate_counter_fn == nullptr)
    {
        USM_ERROR("Failed to find read_object_migrate_counter function in library");
        return stSystemError;
    }

    int status = read_object_migrate_counter_fn(trace.getTraceLimit(), trace.getBuffer(), trace.getCounter(), trace.getOversize());

    counter = *trace.getCounter();
    oversize = *trace.getOversize();

    if (status)
    {
        USM_ERROR("read_object_migrate_counter returned bad status");
        return stFalse;
    }
    if (oversize)
    {
        USM_ERROR("read_object_migrate_counter returned oversize status");
        return stOutOfMemory;
    }

    trace.resizeTrace(counter);
    trace.sortTraceTime(); // Reorder of records in the trace for 'time' value

    if (m_operations == prof_options::Operations::opPrint) // Print trace
    {
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            print_trace_record r;
            r.time = correctTimer(trace.getTrace()[i].time);
            r.pid = get_pid_from_pid_tgid(trace.getTrace()[i].pid);
            snprintf(r.buf, sizeof(r.buf),"At time %-8llu pid %u dev %d migrate obj %p [size %llu bytes] %s %s from %s to %s",
                correctTimer(trace.getTrace()[i].time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid),
                trace.getTrace()[i].dev,
                (void*)trace.getTrace()[i].obj,
                trace.getTrace()[i].size,
                trace.getTrace()[i].has_pages ? "with" : "without", "backing storage",
                trace.getTrace()[i].src_region,
                trace.getTrace()[i].dst_region);
            m_printList.push_back(r);
        }
    }
    else if (m_operations == prof_options::Operations::opTrace) // Create a trace cvf file
    {
        std::string prefix = PREFIX_OBJ_MGR_CNT;
        prefix += "-hostname-" + m_hostHame;
        IStorage* storage = IStorage::create(m_traceFilesDirectory, prefix);
        if (!storage)
            return stFalse;
        storage->dumpIntervalHeader();
        int event_num = 0;
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            std::string name = std::string("OBJECT ")
                + trace.getTrace()[i].src_region + "->"
                + trace.getTrace()[i].dst_region + " size: "
                + std::to_string(trace.getTrace()[i].size);
            storage->dumpIntervalRecord(name,
                correctTimer(trace.getTrace()[i].time),
                correctTimer(trace.getTrace()[i].time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid));
        }
        delete storage;
    }
    return stOk;
}

status_t Collector::createCpuFaultTrace()
{
    if (!(m_eventselect & prof_options::EventSelect::CPU_PFL_EVT || m_eventselect & prof_options::EventSelect::ALL))
    {
        return stFalse;
    }

    int counter = 0, oversize = 0;
    ITrace<cpu_pagefault_trace_record> trace;

    if (m_lib == nullptr)
    {
        USM_TRACE("No library");
        return stSystemError;
    }

    decltype(read_cpu_fault)* read_cpu_fault_fn = m_lib->getSym<decltype(read_cpu_fault)*>("read_cpu_fault");
    if (read_cpu_fault_fn == nullptr)
    {
        USM_ERROR("Failed to find read_cpu_fault function in library");
        return stSystemError;
    }

    /*  The function reads all records related to the event: cpu page fault.
        You need to provide a buffer: structure of trace records, and its limit size as a separate parameter.
        The limit is corresponding to a number of expected maximum records. All above will be dropped.
        Function returns 'counte' of records, so you can itereate over the buffer.
        Parameter 'oversize' is indicating that there were more records collected than the buffer size.
        Successful status is 0, otherwise, there was something wrong with data collection - switch on debug tracing.
    */
    int status = read_cpu_fault_fn(trace.getTraceLimit(), trace.getBuffer(), trace.getCounter(), trace.getOversize());

    counter = *trace.getCounter();
    oversize = *trace.getOversize();

    if (status)
    {
        USM_ERROR("read_cpu_fault returned bad status");
        return stFalse;
    }
    if (oversize)
    {
        USM_ERROR("read_cpu_fault returned oversize status");
        return stOutOfMemory;
    }

    trace.resizeTrace(counter);
    trace.sortTraceTime(); // Reoorder of records in the trace for 'time' value

    if (m_operations == prof_options::Operations::opPrint) // Print trace
    {
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            print_trace_record r;
            r.time = correctTimer(trace.getTrace()[i].time);
            r.pid = get_pid_from_pid_tgid(trace.getTrace()[i].pid);
            snprintf(r.buf, sizeof(r.buf),"At time %-8llu pid %u CPU memory fault, obj %llx, addr %llx",
                correctTimer(trace.getTrace()[i].time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid),
                trace.getTrace()[i].mem_obj,
                trace.getTrace()[i].addr);
            m_printList.push_back(r);
        }
    }
    else if (m_operations == prof_options::Operations::opTrace) // Create a trace cvf file
    {
        std::string prefix = PREFIX_CPU_FLT;
        prefix += "-hostname-" + m_hostHame;
        IStorage* storage = IStorage::create(m_traceFilesDirectory, prefix);
        if (!storage)
            return stFalse;
        storage->dumpIntervalHeader();
        int event_num = 0;
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            storage->dumpIntervalRecord("CpuPageFault",
                correctTimer(trace.getTrace()[i].time),
                correctTimer(trace.getTrace()[i].time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid));
        }
        delete storage;
    }
    return stOk;
}

status_t Collector::createGpuFaultTrace()
{
    if (!(m_eventselect & prof_options::EventSelect::GPU_PFL_EVT || m_eventselect & prof_options::EventSelect::ALL))
    {
        return stFalse;
    }

    int counter = 0, oversize = 0;
    ITrace<gpu_pagefault_trace_record> trace;

    if (m_lib == nullptr)
    {
        USM_TRACE("No library");
        return stSystemError;
    }

    decltype(read_gpu_fault)* read_gpu_fault_fn = m_lib->getSym<decltype(read_gpu_fault)*>("read_gpu_fault");
    if (read_gpu_fault_fn == nullptr)
    {
        USM_ERROR("Failed to find read_gpu_fault function in library");
        return stSystemError;
    }
    int status = read_gpu_fault_fn(trace.getTraceLimit(), trace.getBuffer(), trace.getCounter(), trace.getOversize());

    counter = *trace.getCounter();
    oversize = *trace.getOversize();

    if (status)
    {
        USM_ERROR("read_gpu_fault returned bad status");
        return stFalse;
    }
    if (oversize)
    {
        USM_ERROR("read_gpu_fault returned oversize status");
        return stOutOfMemory;
    }

    trace.resizeTrace(counter);
    trace.sortTraceTime(); // Reorder of records in the trace for 'time' value

    if (m_operations == prof_options::Operations::opPrint) // Print trace
    {
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            print_trace_record r;
            r.time = correctTimer(trace.getTrace()[i].time);
            r.pid = get_pid_from_pid_tgid(trace.getTrace()[i].pid);
            snprintf(r.buf, sizeof(r.buf),"At time %-8llu pid %u dev %d GPU %s fault on %s mem obj %p [size %lld] addr %llx %s size 0x%llx",
                correctTimer(trace.getTrace()[i].time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid),
                trace.getTrace()[i].dev,
                (trace.getTrace()[i].access_type == ACCESS_TYPE_READ) ? "read " : "write",
                trace.getTrace()[i].region,
                (void*)trace.getTrace()[i].obj,
                trace.getTrace()[i].obj_size,
                trace.getTrace()[i].addr,
                trace.getTrace()[i].is_bound ? " bound" : "",
                trace.getTrace()[i].vma_size);
            m_printList.push_back(r);
        }
    }
    else if (m_operations == prof_options::Operations::opTrace) // Create a trace cvf file
    {
        std::string prefix = PREFIX_GPU_FLT;
        prefix += "-hostname-" + m_hostHame;
        IStorage* storage = IStorage::create(m_traceFilesDirectory, prefix);
        if (!storage)
            return stFalse;
        storage->dumpIntervalHeader();
        int event_num = 0;
        for (unsigned int i = 0; i != trace.getTraceSize(); i++)
        {
            storage->dumpIntervalRecord("GpuPageFault",
                correctTimer(trace.getTrace()[i].time),
                correctTimer(trace.getTrace()[i].time),
                get_pid_from_pid_tgid(trace.getTrace()[i].pid));
        }
        delete storage;
    }
    return stOk;
}

__u64 Collector::correctTimer(__u64 time_mono)
{
    if (m_timer_corrected == false)
        return time_mono;
    if (m_raw_higher)
        return (time_mono + m_timer_diff);
    else
        return (time_mono - m_timer_diff);
}

void Collector::getMonoTimerDelta(struct timespec time_mono, struct timespec time_mono_raw, struct timespec *delta, bool *raw_higher)
{
    delta->tv_sec = time_mono_raw.tv_sec - time_mono.tv_sec;
    delta->tv_nsec = time_mono_raw.tv_nsec - time_mono.tv_nsec;

    if (delta->tv_sec > 0)
    {
        *raw_higher = true;
        if (delta->tv_nsec < 0)
        {
            delta->tv_nsec += NS_PER_SECOND;
            delta->tv_sec--;
        }
    }
    else if (delta->tv_sec < 0)
    {
        *raw_higher = false;
        if (delta->tv_nsec > 0)
        {
            delta->tv_nsec -= NS_PER_SECOND;
            delta->tv_sec++;
        }
    }
    else if (delta->tv_sec == 0)
    {
        if (delta->tv_nsec > 0)
            *raw_higher = true;
        if (delta->tv_nsec < 0)
            *raw_higher = false;
    }
}

status_t Collector::stop()
{
    USM_TRACE("sending STOP command");

    status_t status;

    // Get time delta between CLOCK_MONOTONIC and CLOCK_MONOTONIC_RAW
    struct timespec time_mono, time_mono_raw, delta;
    clock_gettime(CLOCK_MONOTONIC, &time_mono);
    clock_gettime(CLOCK_MONOTONIC_RAW, &time_mono_raw);

    getMonoTimerDelta(time_mono, time_mono_raw, &delta, &m_raw_higher);

    m_timer_diff = NS_PER_SECOND * abs(delta.tv_sec) + abs(delta.tv_nsec);
    m_timer_corrected = true;

    /*
    // Use these calculations to compare mono and mono_row time
    printf("Time Mono   %d.%.9ld\n", (int)time_mono.tv_sec, time_mono.tv_nsec);
    printf("Time MonoR  %d.%.9ld\n", (int)time_mono_raw.tv_sec, time_mono_raw.tv_nsec);
    printf("Time Delta  %d.%.9ld\n", (int)delta.tv_sec, delta.tv_nsec);
    */
    // End of calculation time delta


    status = createCpuFaultTrace();
    status = createGpuFaultTrace();
    status = createObjMigrateCntTrace();
    status = createObjMigrateTimeTrace();

    // Sorting printed records by time
    if (m_suboptions & prof_options::Suboptions::SUB_OPT_TIME_SORT)
    {
        std::sort(m_printList.begin(), m_printList.end(), [](const print_trace_record &a, const print_trace_record &b)
        {
            return a.time < b.time;
        });
    }
    // Printing out all records
    for (auto &record : m_printList)
    {
        std::cout << std::string(record.buf) << std::endl;
    }

// Use this function for debugging:
// printing directly form user mem module
//    printBpfMem();

    return status;
}

status_t Collector::pause()
{
    USM_TRACE("sending PAUSE command");
    return stOk;
}

status_t Collector::resume()
{
    USM_TRACE("sending RESUME command");
    return stOk;
}

ICollector* ICollector::instance()
{
    return Collector::instance();
}

} // namespace usmcollector
