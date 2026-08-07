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

#ifndef USM_TRACE_HPP
#define USM_TRACE_HPP

#include <vector>
#include <algorithm>

#define NRECORDS_MAX 16384

template <typename T> class ITrace
{
public:
    ITrace();
    T* getBuffer();
    const std::vector<T>& getTrace() const { return m_trace; }
    const size_t getTraceLimit() { return m_trace_limit; };
    int* getCounter() { return &m_counter; };
    int* getOversize() { return &m_oversize; };
    size_t getTraceSize() { return m_trace.size(); }
    void resizeTrace(int size) { if(size<=m_trace_limit) m_trace.resize(size); }
    void sortTraceTime() { std::sort(m_trace.begin(), m_trace.end(), compareTime); }
    virtual ~ITrace();

private:
    int m_counter;
    int m_oversize;
    size_t m_trace_limit;
    std::vector<T> m_trace;
    static bool compareTime(const T& a, const T& b) { return a.time < b.time; }
};

template <typename T> ITrace<T>::ITrace() :
    m_counter(0),
    m_oversize(0),
    m_trace_limit(NRECORDS_MAX)
{
    m_trace.resize(m_trace_limit);
}

template <typename T> T* ITrace<T>::getBuffer()
{
    return m_trace.data();
}

template <typename T> ITrace<T>::~ITrace()
{
}

#endif // USM_TRACE_HPP
