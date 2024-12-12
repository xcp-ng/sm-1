#!/usr/bin/env python3
#
# Copyright (C) 2024  Vates SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# TODO: Use StrEnum in python 3.11.
class VdiType(object):
    RAW = "aio"
    VHD = "vhd"
    ISO = "iso"
    FILE = "file"
    CBTLOG = "cbtlog"
