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

##
# MANIFEST_PATH variables from manifests
##

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

repo_forall=$SCRIPT_DIR/repo_forall.sh
tmp_env_file=$(mktemp)
repo forall -c "$repo_forall >> $tmp_env_file"
# Pre-process MANIFEST_PATH_BBLAYERS_TEMPLATE to support dev and feed support in the image assembler
manifest_lines=$(grep '^export MANIFEST_PATH_BBLAYERS_TEMPLATE=' "$tmp_env_file")
count=$(echo "$manifest_lines" | wc -l)
if [ "$count" -gt 1 ]; then
    chosen_line=$(echo "$manifest_lines" | grep 'meta-rdk-images')
    if [ -z "$chosen_line" ]; then
        echo "Bug: Duplicated variable(s) - "
    else
        # Remove all existing lines and append only the chosen one
        sed -i '/^export MANIFEST_PATH_BBLAYERS_TEMPLATE=/d' "$tmp_env_file"
        echo "$chosen_line" >> "$tmp_env_file"
    fi
fi
duplicated_variables=`cat $tmp_env_file | grep -v 'PATH=' | sed 's|=.*$||g' | sort | uniq -c | grep -v '1 export' | sed 's|^.*export ||g'`
if [ ! -z "$duplicated_variables" ]; then
  echo
  echo "Bug: Duplicated variable(s)"
  echo $duplicated_variables
  exit 2
fi
source $tmp_env_file
# Generate manifest paths relative to the repo root so the same build directory
# works both on the host and inside the yocto docker mount.
repo_root=$(cd "$SCRIPT_DIR/.." && pwd)
while IFS='=' read -r key value; do
    [ -n "$key" ] || continue
    key=${key#export }
    if [ "$key" = "MW_LAYER_BUILD_TYPE" ]; then
        printf '%s = "%s"\n' "$key" "$value"
        continue
    fi

    relative_path=$(realpath --relative-to="$repo_root" "$value" 2>/dev/null || true)
    if [ -n "$relative_path" ] && [ "$relative_path" != "." ]; then
        printf '%s = "${RDKROOT}/%s"\n' "$key" "$relative_path"
    else
        printf '%s = "%s"\n' "$key" "$value"
    fi
done < "$tmp_env_file" > ./manifest_vars.conf
rm $tmp_env_file
