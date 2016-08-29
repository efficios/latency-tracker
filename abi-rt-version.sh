#!/bin/sh
#
# Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
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
KPATH="$1"

VERSIONFILE=""

if [ -f "${KPATH}/localversion-rt" ]; then
	VERSIONFILE="${KPATH}/localversion-rt"

elif [ -f "${KPATH}/source/localversion-rt" ]; then
	VERSIONFILE="${KPATH}/source/localversion-rt"
else
	echo 0
	exit 0
fi

RT_PATCH_VERSION=$(sed -rn 's/^-rt([0-9]+)$/\1/p' "${VERSIONFILE}")

if [ "x${RT_PATCH_VERSION}" = "x" ]; then
	echo 0
	exit 0
fi

echo "${RT_PATCH_VERSION}"
