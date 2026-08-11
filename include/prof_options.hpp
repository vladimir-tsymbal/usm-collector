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

#ifndef USM_PROF_OPTIONS_HPP
#define USM_PROF_OPTIONS_HPP

#include <cstdint>
#include <string>

namespace usmcollector
{

namespace prof_options
{

enum class Operations
{
    opPrint,
    opTrace,
    opDebug
};

struct Suboptions
{
    enum Value
    {
        NONE               = 0,
        SUB_OPT_TIME_SORT  = (1<<0),
        SUB_OPT_PID_SELECT = (1<<1),
        SUB_OPT_EVT_SELECT = (1<<2)
    };
};
enum class TimeSort
{
    noTimeSort = 0,
    allTimeSort
};
struct EventSelect
{
    enum Value
    {
        ALL	    = (1<<0),
        CPU_PFL_EVT = (1<<1),
        CPU_PFL_INT = (1<<2),
        GPU_PFL_EVT = (1<<3),
        GPU_PFL_INT = (1<<4),
        OBJ_MGR_EVT = (1<<5),
        OBJ_MGR_INT = (1<<6),
    };
};

class ProfOptions
{
public:
    ProfOptions(
        const uint32_t pid,
        const Operations& op,
        const int suboptions,
        const int eventselect,
        const std::string& log_file,
        const std::string& raw_data_path,
        const std::string& exe_path,
        const std::string& host_name) :
        m_pid(pid),
        m_op(op),
        m_subOptions(suboptions),
        m_eventSelect(eventselect),
        m_log_file(log_file),
        m_raw_data_path(raw_data_path),
        m_exe_path(exe_path),
        m_host_name(host_name)
    {}

    const uint32_t getPid() const
    {
        return m_pid;
    }
    Operations getOp() const
    {
        return m_op;
    }
    const int getSuboptions() const
    {
        return m_subOptions;
    }
    const int getEventSelect() const
    {
        return m_eventSelect;
    }
    const std::string& getLogFileName() const
    {
        // TODO: implement logging
        return m_log_file;
    }
    const std::string& getRawDataPath() const
    {
        return m_raw_data_path;
    }
    const std::string& getExePath() const
    {
        return m_exe_path;
    }
    const std::string& getHostName() const
    {
        return m_host_name;
    }

private:
    std::string m_log_file;
    std::string m_raw_data_path;
    std::string m_exe_path;
    std::string m_host_name;
    uint32_t m_pid;
    Operations m_op;
    int m_subOptions;
    int m_eventSelect;
};

} // namespace prof_options

} // namespace usmcollector

#endif // USM_PROF_OPTIONS_HPP
