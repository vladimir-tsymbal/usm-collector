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

#ifndef USM_COLLECTOR_HPP
#define USM_COLLECTOR_HPP

#include "prof_options.hpp"

namespace usmcollector {

typedef int32_t status_t;

enum /* status */
{
    stOk,              /**< successful error code */
    stFalse,           /**< successful error code but operation was ignored */
    stInvalidOp,       /**< the operation can't be performed now */
    stInvalidArgs,     /**< one or more arguments are invalid */
    stNoSpace,         /**< no space left on the device */
    stNoPermission,    /**< no enough permission */
    stOutOfMemory,     /**< no enough memory */
    stOutOfResources,  /**< no enough resources */
    stSystemError,     /**< a problem with resources or something like that */
    stDriverError,     /**< driver returns an error */
    stConfigError,     /**< given configuration isn't correct */
    stNotImplemented,  /**< some functionality isn't implemented */
    stBusy             /**< collection is already running */
};

class ICollector
{
public:
    /**
     * Get the instance of collector.
     * @return The instance of ICollector class. */
    static ICollector* instance();

    /**
     * Set a directory for temporary files. By default collector uses default
     * Windows temporary directory on the system. You should call the method
     * before start collection.
     * @param[in] directory      a directory for temporary files. */
    virtual void setTemporaryDirectory(std::string directory) = 0;

    /**
     * Set a directory for storing trace files. You can call the method
     * several times. New trace files will be created in new result directory
     * after you call start(pid_t pid) method.
     * By default, trace files is stored in system temporary directory.
     * @param[in] directory    full path to a directory. It should not be
     * zero. */
    virtual void setTraceFilesDirectory(std::string directory) = 0;

    /**
     * Set an experiment directory. In most cases it is a part of directory
     * for trace files. For example, Amplifier has the following directory
     * layout <experiment directory>/data.<N>/<trace files>. */
    virtual void setExperimentDirectory(std::string directory) = 0;

    /**
     * Get the experiment directory. It returns the same value as was
     * passed into setExperimentDirectory method. */
    virtual std::string getExperimentDirectory() const = 0;

    virtual status_t initialize(prof_options::ProfOptions& op) = 0;
    virtual status_t destroy() = 0;

    /**
     * Attach. The method is called when profiled process is already exist.
     * But there is no guarantee that it will not be finished before the
     * code start to work.
     * The operation isn't blocking. It configures driver and starts sampling.
     * @param[in] pid    identifier of profiled process.
     * @return The method returns status of the operation. */
    virtual status_t start(pid_t pid) = 0;

    /**
     * Stop collection. The method will fully shutdown collection. You should
     * call it at the end otherwise VTSS++ driver will not be stopped at all.
     * Be aware of after VTSS++ driver is stopped configuration will be
     * reseted. It means that result directory and other parameters will have
     * default values. Note the operation doesn't terminate profiled process.
     * @return The method returns status of the operation. */
    virtual status_t stop() = 0;

    /**
     * Pause collection. The method will limit amount of collected data. But
     * collection will not be stopped because we should collect basic
     * information about threads and processes.
     * @return The method returns status of the operation. */
    virtual status_t pause() = 0;

    /**
     * Resume collection. The method will resume collection if it is in pause
     * state.
     * @return The method returns status of the operation. */
    virtual status_t resume() = 0;

protected:
    virtual ~ICollector() {}
};

} // namespace usmcollector

#endif // USM_COLLECTOR_HPP
