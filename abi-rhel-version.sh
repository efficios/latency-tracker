#!/bin/sh
#
# Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; only
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

# First argument is the path to the kernel headers.
KPATH=$1

if [ ! -f "${KPATH}/include/generated/uapi/linux/version.h" ]; then
	echo 0
	exit 0
fi

# Assuming KPATH is the target kernel headers directory
RHEL_RELEASE=$(sed -rn 's/^#define RHEL_RELEASE "(.*)"/\1/p' "${KPATH}/include/generated/uapi/linux/version.h")

RHEL_RELEASE_MAJOR=$(echo "${RHEL_RELEASE}" | sed -r 's/^([0-9]+)\.([0-9]+)\.([0-9]+)/\1/')
RHEL_RELEASE_MINOR=$(echo "${RHEL_RELEASE}" | sed -r 's/^([0-9]+)\.([0-9]+)\.([0-9]+)/\2/')
RHEL_RELEASE_PATCH=$(echo "${RHEL_RELEASE}" | sed -r 's/^([0-9]+)\.([0-9]+)\.([0-9]+)/\3/')

# Combine all update numbers into one
RHEL_API_VERSION=$((RHEL_RELEASE_MAJOR * 10000 + RHEL_RELEASE_MINOR * 100 + RHEL_RELEASE_PATCH))

echo ${RHEL_API_VERSION}
