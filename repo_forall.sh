#!/bin/bash

################################################################################
# Copyright 2024 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
################################################################################

# This script is meant to be run by 'repo forall'.
# Refer to 'repo help forall' to know about the forall usage.
# It echoes shell commands to create the build environment.
# The shell commands (export myVAR=...) are to be put into a temp file which must be sourced.
# To print out comments without mucking up the tmp file, redirect output to stderr.
# Example:
#	echo >&2 "My comment"

# Process EXPORT_PATH annotations.
if [ ! -z ${REPO__MANIFEST_EXPORT_PATH} ]; then
	export_string="$REPO__MANIFEST_EXPORT_PATH=$PWD${REPO__MANIFEST_EXPORT_PATH_EXTEND:+/}$REPO__MANIFEST_EXPORT_PATH_EXTEND"
	echo "export $export_string" # Used by the upper script does the export
	#echo >&2 "export $export_string" # Debugging & used to ensure that the logging comes out of the terminal
fi

if [ ! -z ${REPO__MANIFEST_EXPORT_PATH1} ]; then
        export_string="$REPO__MANIFEST_EXPORT_PATH1=$PWD${REPO__MANIFEST_EXPORT_PATH1_EXTEND:+/}$REPO__MANIFEST_EXPORT_PATH1_EXTEND"
        echo "export $export_string" # Used by the upper script does the export
        #echo >&2 "export $export_string" # Debugging & used to ensure that the logging comes out of the terminal
fi

if [ ! -z ${REPO__MANIFEST_EXPORT_PATH2} ]; then
        export_string="$REPO__MANIFEST_EXPORT_PATH2=$PWD${REPO__MANIFEST_EXPORT_PATH2_EXTEND:+/}$REPO__MANIFEST_EXPORT_PATH2_EXTEND"
        echo "export $export_string" # Used by the upper script does the export
        #echo >&2 "export $export_string" # Debugging & used to ensure that the logging comes out of the terminal
fi
