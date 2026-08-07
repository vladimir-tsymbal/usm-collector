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

#ifndef USM_SHARED_LIBRARY_HPP
#define USM_SHARED_LIBRARY_HPP

#if defined(_WIN32)
#include <Windows.h>
#else
#include <cerrno>
#include <dlfcn.h>
#endif

#include <string>
#include <vector>

class SharedLibrary
{
public:
    static SharedLibrary* create(const std::string& name)
    {
#if defined(_WIN32)
        HMODULE handle = nullptr;
        handle = LoadLibraryA(name.c_str());
#else
        void* handle = nullptr;
        handle = dlopen(name.c_str(), RTLD_NOW);
#endif
        if (handle != nullptr)
        {
            return new SharedLibrary(handle);
        }
        fprintf(stderr, "%s\n", dlerror());
        return nullptr;
    }

    SharedLibrary() {}

    ~SharedLibrary()
    {
#if defined(_WIN32)
        BOOL completed = FreeLibrary(m_handle);
#else
        int completed = dlclose(m_handle);
#endif
    }

    template<typename T> T getSym(const char* name)
    {
        void* sym = nullptr;
#if defined(_WIN32)
        sym = GetProcAddress(m_handle, name);
#else
        sym = dlsym(m_handle, name);
#endif
        return reinterpret_cast<T>(sym);
    }

#if defined(_WIN32)
    HMODULE getHandle()
#else
    void* getHandle()
#endif
    {
        return m_handle;
    }

private:
#if defined(_WIN32)
    SharedLibrary(HMODULE handle) : m_handle(handle) {}
#else
    SharedLibrary(void* handle) : m_handle(handle) {}
#endif

#if defined(_WIN32)
    HMODULE m_handle = nullptr;
#else
    void* m_handle = nullptr;
#endif
};

#endif // USM_SHARED_LIBRARY_HPP
