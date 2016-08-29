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

if [ ! -f "${KPATH}/include/generated/package.h" ]; then
	echo 0
	exit 0
fi

# Debian snippet courtesy of Ben Hutchings

# Assuming KPATH is the target kernel headers directory
DEB_PACKAGE_VERSION=$(sed -rn 's/^#define LINUX_PACKAGE_ID " Debian (.*)"/\1/p' "${KPATH}/include/generated/package.h")
# Ignore backports part
DEB_PACKAGE_VERSION=$(echo "${DEB_PACKAGE_VERSION}" | sed -r 's/~(bpo|deb).*//')
# Get -ckt update number, if present
KERNEL_CKT_UPDATE=$(echo "${DEB_PACKAGE_VERSION}" | sed -rn 's/^[0-9]+\.[0-9]+\.[0-9]+-ckt([0-9]+).*/\1/p')

# Only care about the rest if it is a -ckt kernel, making sure we do not
# clash with older Debian kernels (e.g. Debian 3.2.65-1+deb7u2).
if [ -z "${KERNEL_CKT_UPDATE}" ]; then
	echo 0
	exit 0
fi

# Get package revision
DEB_PACKAGE_REVISION=$(echo "${DEB_PACKAGE_VERSION}" | sed -r 's/.*-([^-]+)$/\1/')
# Get non-sec update number
DEB_PACKAGE_REVISION_BASE=$(echo "${DEB_PACKAGE_REVISION}" | sed -r 's/^([0-9]+).*/\1/')
# Get security update number, if present
DEB_PACKAGE_REVISION_SECURITY=$(echo "${DEB_PACKAGE_REVISION}" | sed -rn 's/.*\+(squeeze|deb[0-9])+u([0-9]+)$/\1/p')
test -n "${DEB_PACKAGE_REVISION_SECURITY}" || DEB_PACKAGE_REVISION_SECURITY=0
# Combine all update numbers into one
DEB_API_VERSION=$((KERNEL_CKT_UPDATE * 10000 + DEB_PACKAGE_REVISION_BASE * 100 + DEB_PACKAGE_REVISION_SECURITY))

echo ${DEB_API_VERSION}
