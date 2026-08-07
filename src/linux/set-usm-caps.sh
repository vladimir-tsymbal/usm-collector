#!/bin/sh
#
# Copyright (C) 2023 Intel Corporation
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License, as published
# by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

SCRIPT_DIR=$(cd -P "$(dirname "$0")" && pwd)
USM_EXE="usmtool"
GROUP_NAME="vtune"

print_msg()
{
    MSG="$*"
    echo "$MSG"
}

print_nnl()
{
    MSG="$*"
    echo -n "$MSG"
}

print_err()
{
    MSG="$*"
    if [ -w /dev/stderr ] ; then
        echo "$MSG" >> /dev/stderr
    else
        echo "$MSG"
    fi
}

print_usage_and_exit()
{
    err=${1:-0}
    print_msg "This script sets Linux capabilities 'CAP_PERFMON, CAP_BPF' to allow USM collection"
    print_msg ""
    print_msg "Usage: $0 [ options ]"
    print_msg ""
    print_msg " where \"options\" are:"
    print_msg ""
    print_msg "    -h | --help"
    print_msg "      prints out usage"
    print_msg ""
    print_msg "    -g | --group <group>"
    print_msg "      restricts access to the privileged executable to users in the specified"
    print_msg "      group; if this option is not provided, the group '$GROUP_NAME' will be used"
    print_msg ""
    exit $err
}

set_capabilities()
{
    BIN_DIR="$(dirname "${SCRIPT_DIR}")/$1"
    PRIVILIGED_BINARY="${BIN_DIR}/${USM_EXE}"

    if ! [ -x "$(command -v setcap)" ] ; then
        print_err "ERROR: unable to find command \"setcap\"."
        print_err ""
        print_err "Please install:"
        print_err ""
        print_err "    \"libcap\" package for Red Hat Enterprise Linux/CentOS/Fedora distributions"
        print_err "    \"libcap2-bin\" package for Ubuntu/Debian distributions"
        print_err "    \"libcap-progs\" package for SLES/openSUSE distributions"
        print_err ""
        exit 255
    fi

    if [ ! -f "${PRIVILIGED_BINARY}" ] ; then
        echo "ERROR: the binary file \"${PRIVILIGED_BINARY}\" does not exist."
        exit 101
    fi

    chgrp ${GROUP_NAME} "${PRIVILIGED_BINARY}"
    if [ $? -ne 0 ] ; then
        print_err "ERROR: failed to set group for \"${PRIVILIGED_BINARY}\"."
        exit 102
    fi

    chmod o-rwx,g+x "${PRIVILIGED_BINARY}"
    if [ $? -ne 0 ] ; then
        print_err "ERROR: failed to chmod \"${PRIVILIGED_BINARY}\"."
        exit 103
    fi

    setcap "cap_perfmon,cap_bpf=iep" "${PRIVILIGED_BINARY}" >/dev/null 2>&1
    if [ $? -ne 0 ] ; then
        setcap "38,39=ep" "${PRIVILIGED_BINARY}" >/dev/null 2>&1
        if [ $? -ne 0 ] ; then
            print_err "ERROR: failed to assign the required capabilities to \"${PRIVILIGED_BINARY}\"."
            print_err ""
            print_err "CAP_PERFMON or CAP_BPF are probably not supported in this version of Linux kernel or Libcap utilities."
            print_err "Make sure your Linux kernel version is 5.8 or higher, and Libcap utilities version is 2.37 or higher."
            print_err ""
            exit 104
        else
            print_msg "cap_perfmon(38), cap_bpf(39) set successfully"
        fi
    else
        print_msg "cap_perfmon, cap_bpf set successfully"
    fi
}

check_memlock_limit()
{
    MEMLOCK_LIMIT=$(ulimit -l)

    if [ ${MEMLOCK_LIMIT} != "unlimited" ] ; then
        print_err "WARNING: the maximum number of bytes of memory that may be locked is set to \"${MEMLOCK_LIMIT}\"."
        print_err ""
        print_err "Set the limit to \"unlimited\" in the /etc/security/limits.conf file by adding or changing these lines:"
        print_err ""
        print_err " * hard memlock unlimited"
        print_err " * soft memlock unlimited"
        print_err ""
        print_err "To do this, you must have administrator privilege."
        print_err ""
    fi
}

ARGS="$@"
if [ $# -eq 1 ] ; then
    case "$1" in
        -h | --help)
        print_usage_and_exit 0
        ;;
    esac
fi

while [ $# -gt 0 ] ; do
    case "$1" in
        -g | --group)
            GROUP_NAME="$2"
            shift
            shift
            ;;

        *)
            print_err ""
            print_err "ERROR: unrecognized option $1."
            print_usage_and_exit 101
            ;;
    esac
done

if [ $(id -u) -ne 0 ] ; then
    print_msg "NOTE: super-user or \"root\" privileges are required."
    print_nnl "Please enter \"root\" "
    exec su -c "/bin/sh $0 $ARGS"
    print_msg ""
    exit 0
fi

check_memlock_limit

set_capabilities "bin64"

print_msg "Done"

exit 0
