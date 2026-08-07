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

#ifndef USM_STORAGE_HPP
#define USM_STORAGE_HPP

#include <fstream>
#include <iostream>
#include <vector>
#include <type_traits>
#include "i915_mem_user.h"

class IStorage
{
public:
    static std::string getResultFileName(const std::string path, const std::string prefix);
    static IStorage* create(const std::string& path, const std::string& prefix);

    void dumpIntervalHeader();
    void dumpIntervalRecord(const std::string& name, __u64 start_tsc, __u64 end_tsc, __u32 pid);

    virtual ~IStorage();

private:
    std::ofstream m_file;

    IStorage(const std::string& filename) :
        m_file(filename, std::ios::out | std::ios::trunc)
    {}
};

std::string IStorage::getResultFileName(const std::string path, const std::string prefix)
{
    std::string filename = prefix;

    filename += std::string(".csv");
    if (!path.empty())
    {
        filename = path + std::string("/") + filename;
    }
    return filename;
}

IStorage::~IStorage()
{
    m_file.close();
}

IStorage* IStorage::create(const std::string& path, const std::string& prefix)
{
    std::string filename = getResultFileName(path, prefix);

    IStorage* storage = new IStorage(filename);

    if (!storage->m_file.is_open())
    {
        delete storage;
        return nullptr;
    }
    return storage;
}

void IStorage::dumpIntervalHeader()
{
    if (!m_file.is_open())
        return;

    std::string header("name,start_tsc.CLOCK_MONOTONIC_RAW,end_tsc,pid,tid");

    m_file << header << std::endl;
}

void IStorage::dumpIntervalRecord(const std::string& name, __u64 start_tsc, __u64 end_tsc, __u32 pid)
{
    if (!m_file.is_open())
        return;

    // No tid as tasks are not properly mapped to Pid in Timeline
    m_file << name << "," << start_tsc << "," << end_tsc << "," << pid << "," << std::endl;
}

#endif // USM_STORAGE_HPP
