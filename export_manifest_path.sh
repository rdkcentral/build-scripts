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
duplicated_variables=`cat $tmp_env_file | grep -v 'PATH=' | sed 's|=.*$||g' | sort | uniq -c | grep -v '1 export' | sed 's|^.*export ||g'`
if [ ! -z "$duplicated_variables" ]; then
  echo
  echo "Bug: Duplicated variable(s)"
  echo $duplicated_variables
  exit 2
fi
source $tmp_env_file
# Take the env file, remove the export, add spacing on the =, and add quotes
# e.g. export MANIFEST_PATH_SCRIPTS=/home/ppl22/RDK-E/<Machine>/scripts to MANIFEST_PATH_SCRIPTS = "/home/ppl22/RDK-E/<Machine>/scripts"
# This can then be used in the conf files for yocto
cat $tmp_env_file | sed 's/export //g' | sed 's/=/ = /g' | sed 's/\(=[[:blank:]]*\)\(.*\)/\1"\2"/' > ./manifest_vars.conf
rm $tmp_env_file
