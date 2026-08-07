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

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#include <csignal>
#include <signal.h>

#include <string>
#include <iostream>
#include <unistd.h>
#include <limits.h>
#include <libgen.h>
#include <stdio.h>
#include <cstdlib>

#include "collector.hpp"

using namespace usmcollector::prof_options;

inline std::string getEnv(const char* name)
{
    const char* value = getenv(name);
    if (value == nullptr)
        return std::string();
    return std::string(value);
}

static void usage(void)
{
    std::cout << "Usage: usmtool [options] [[suboptions] [parameters]]" << std::endl
        << "options:" << std::endl
        << "  -verson print collector version" << std::endl
        << "  -start  start collection of data" << std::endl
        << "  -print  start collection and then print data" << std::endl
// TODO: add check        << "  -check  check bpf availability" << std::endl
        << "  -help   print help" << std::endl
        << "suboptions [parameters]:" << std::endl
        << "(applicable with -print option)" << std::endl
        << "  -timesort [all|none] " << std::endl
        << "  -pid [{process id}] " << std::endl
        << "  -event [all|{event name}] " << std::endl
        << "event names:" << std::endl
        << "  CpuPageFaultEvent" << std::endl
        << "  GpuPageFaultEvent" << std::endl
        << "  ObjMigrationEvent" << std::endl
        << "  ObjMigrationInterval" << std::endl
        << "examples:" << std::endl
        << "  usmtool -print" << std::endl
        << "  usmtool -print -timesort all" << std::endl
        << "  usmtool -print -pid 12345678" << std::endl
        << "  usmtool -print -event ObjMigrationEvent" << std::endl
        << "  usmtool -print -timesort all -pid 12345678 -event all" << std::endl;
}

volatile std::sig_atomic_t isDataCollectionRunning = 0;

static void sigint_handler(int signal)
{
    isDataCollectionRunning = 0;
}

static unsigned long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
    std::string value;
    std::string log_file;
    std::string raw_data_path;
    std::string exe_path;
    std::string host_name;
    uint32_t pid = 0;

    bool collectData = false;

    if (argc < 2)
    {
        usage();
        return EXIT_FAILURE;
    }
    std::string arg1 = argv[1];

    // Define signal handling
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1)
        return EXIT_FAILURE;

    // Check collector operations option
    Operations op = Operations::opTrace;
    int subopt = Suboptions::NONE;
    int eventsel = EventSelect::ALL;

    // TODO: Implement more graceful handling of command options

    if (arg1 == "-version")
    {
        collectData = false;
#ifdef USM_COLLECTOR_VERSION
        std::cout << "version: " << TOSTRING(USM_COLLECTOR_VERSION) << std::endl;
#endif
        return EXIT_SUCCESS;
    }
    else if (arg1 == "-start")
    {
        op = Operations::opTrace;
        collectData = true;
    }
    else if (arg1 == "-print")
    {
        if (argc == 3)
        {
            // Should not be suboptions without parameters
            usage();
            return EXIT_FAILURE;
        }
        op = Operations::opPrint;
        collectData = true;
        if (argc > 3)
        {
            for (int i = 2; i < argc; i+=2)
            {
                std::string arg2 = argv[i];
                std::string arg3 = argv[i+1];
                char *parg3 = argv[i+1];
                if (arg2 == "-timesort")
                {
                    if (arg3 == "all")
                    {
                        subopt |= Suboptions::SUB_OPT_TIME_SORT;
                    }
                }
                else if (arg2 == "-pid")
                {
                    char *endptr;
                    errno = 0;
                    pid = strtol(parg3, &endptr, 10);

                    if (endptr == parg3)
                    {
                        std::cerr << "Invalid number: " << parg3 << std::endl;
                        usage();
                        return EXIT_FAILURE;
                    } 
                    else if (*endptr)
                    {
                        std::cerr << "Trailing characters after number: " << parg3 << std::endl;
                        usage();
                        return EXIT_FAILURE;
                    }
                    else if (errno == ERANGE)
                    {
                        std::cerr << "Number out of range: " << parg3 << std::endl;
                        usage();
                        return EXIT_FAILURE;
                    }
                    subopt |= Suboptions::SUB_OPT_PID_SELECT;
                    std::cout << "Selected pid = " <<  pid << std::endl;
                }
                else if (arg2 == "-event")
                {
                    if (arg3 == "all")
                    {
                        eventsel |= EventSelect::ALL;
                    }
                    else if (arg3 == "CpuPageFaultEvent")
                    {
                        eventsel |= EventSelect::CPU_PFL_EVT;
                    }
                    else if (arg3 == "GpuPageFaultEvent")
                    {
                        eventsel |= EventSelect::GPU_PFL_EVT;
                    }
                    else if (arg3 == "ObjMigrationEvent")
                    {
                        eventsel |= EventSelect::OBJ_MGR_EVT;
                    }
                    else if (arg3 == "ObjMigrationInterval")
                    {
                        eventsel |= EventSelect::OBJ_MGR_INT;
                    }
                    else
                    {
                        usage();
                        return EXIT_FAILURE;
                    }
                }
                else
                {
                    usage();
                    return EXIT_FAILURE;
                }
            }
        }
    }
    else if (arg1 == "-debug")
    {
        op = Operations::opDebug;
        collectData = true;
    }
    else if (arg1 == "-check")
    {
        collectData = false;
    }
    else if (arg1 == "/?" || arg1 == "-h" || arg1 == "-help" || arg1 == "--help")
    {
        usage();
        return EXIT_SUCCESS;
    }
    else
    {
        usage();
        return EXIT_FAILURE;
    }

    // Define data directory
    raw_data_path = "./";
    value = getEnv("AMPLXE_DATA_DIR");
    if (!value.empty())
    {
        raw_data_path = value;
    }

    // Define Host name
    char host_name_buf[HOST_NAME_MAX];
    int host_name_result = gethostname(host_name_buf, HOST_NAME_MAX);
    if (host_name_result)
    {
        perror("gethostname error");
        return EXIT_FAILURE;
    }
    host_name = host_name_buf;

    value = getEnv("AMPLXE_HOSTNAME");
    if (!value.empty())
    {
        host_name = value;
    }

    // Define PID to profile from env variable
    value = getEnv("AMPLXE_COLLECT_PID");
    if (!value.empty())
    {
        pid = std::stoi(value);
    }

    // Define executable path
    exe_path = "./";
    char exe_path_buf[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", exe_path_buf, PATH_MAX - 1);
    if (count != -1)
    {
        exe_path_buf[PATH_MAX - 1] = '\0';
        exe_path = dirname(exe_path_buf);
    }

    std::cout << "usm: Host name: " << host_name << std::endl;
    std::cout << "usm: Data path: " << raw_data_path << std::endl;
    std::cout << "usm: Exe path: " << exe_path << std::endl;
    std::cout << "usm: PID to profile: " << pid << std::endl;
    ProfOptions options(pid, op, subopt, eventsel, log_file, raw_data_path, exe_path, host_name);

    // Create collector and start
    if (collectData)
    {
        usmcollector::ICollector* pCollector = usmcollector::ICollector::instance();
        if (pCollector->initialize(options) != usmcollector::stOk)
            return EXIT_FAILURE;
        if (pCollector->start(0) != usmcollector::stOk)
            return EXIT_FAILURE;

        isDataCollectionRunning = 1;
        std::cout << "usm: Collection has been started..." << std::endl;

        while (isDataCollectionRunning)
        {
            sleep(1);
        }
        std::cout << "usm: Stopping collection..." << std::endl;

        if (pCollector->stop() != usmcollector::stOk)
            return EXIT_FAILURE;
        if (pCollector->destroy() != usmcollector::stOk)
            return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
