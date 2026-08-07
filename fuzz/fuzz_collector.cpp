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
#include <cstring>
#include <collector.hpp>

using namespace usmcollector;
using namespace usmcollector::prof_options;

template <typename T>
inline T Deserialize(const unsigned char* byte_array, size_t size)
{
    T object;
    std::memcpy(&object, &byte_array, sizeof(T));
    return object;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    std::string host_name;
    std::string log_file;
    std::string exe_path;
    std::string raw_data_path;
    uint32_t pid = 0;
    Operations op = Operations::opTrace;
    // TODO: Add suboptions and event selection to Options
    //int subopt = Suboptions::NONE;
    //int eventsel = EventSelect::ALL;
    //if(Size >= (sizeof(pid) + sizeof(op) + sizeof(subopt) + sizeof(eventsel)))

    if(Size >= (sizeof(pid) + sizeof(op) ))
    {
        pid = Deserialize<uint32_t>(Data, Size);
        op = Deserialize<Operations>(Data, Size);
        // TODO: Add suboptions and event selection to Options
        //subopt = Deserialize<int>(Data, Size);
        //eventsel = Deserialize<int>(Data, Size);
    }

    exe_path = (".");
    // TODO: Add suboptions and event selection to Options
    //ProfOptions options(pid, op, subopt, eventsel, log_file, raw_data_path, exe_path, host_name);
    ProfOptions options(op, log_file, raw_data_path, exe_path, host_name);
    usmcollector::ICollector* pCollector = usmcollector::ICollector::instance();
    pCollector->initialize(options);
    pCollector->start(pid);
    pCollector->stop();
    pCollector->destroy();

    return 0;
}