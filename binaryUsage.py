#!/usr/bin/env python3

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

import concurrent.futures
import os.path
import re
import string
import subprocess
from datetime import datetime
from RDKEAuditUtils import get_max_workers

# In test mode only process a few files, to speed things up
_test_mode = False
_files_processed_in_test_mode = 10

_logger = None


def _process_output(raw_output):
    """process terminal output in a consistent way for use in this script"""
    working_string_data = raw_output.decode()
    for char in string.whitespace:
        working_string_data = working_string_data.replace(char, " ")

    while "  " in working_string_data:
        working_string_data = working_string_data.replace("  ", " ")

    return [x for x in working_string_data.split(" ") if len(x) > 1]


def _re_friendly_name(name):
    reformatted_name = name
    for char in (".", "+"):
        reformatted_name = reformatted_name.replace(char, "\\" + char)
    return reformatted_name


def _get_systemd_references(binary_name, root_dir):
    references = list()
    try:
        references = _process_output(
            subprocess.check_output(("egrep", "-rl", f"ExecStart.*=.*{_re_friendly_name(binary_name)}", root_dir)))
    except subprocess.CalledProcessError as ex:
        if ex.returncode != 1:  # no matches is an expected result
            _logger.error(f"error with systemd grep for {binary_name}")

    return references


def _get_sh_references(binary_name, root_dir):
    """
     Get a list of shell script files that contain the name of the specified binary.
     The list may be empty
     """
    reformatted_name = _re_friendly_name(binary_name)
    bin_string = f"(^|\b|/|\s|\(){reformatted_name}(\||\<|>|\s|$|\))"
    try:
        raw_references = _process_output(subprocess.check_output(("egrep", "-rl", bin_string, root_dir)))
    except subprocess.CalledProcessError as ex:
        if ex.returncode == 1:  # no matches is an expected result
            _logger.debug(f"no matches from {binary_name}'egrep -rl '{bin_string}' {root_dir}'")
        else:
            _logger.error(
                f"error with {binary_name}'egrep -rl '{bin_string}' {root_dir}' out:{ex.output}, code:{ex.returncode}")
        raw_references = list()

    filtered_references = list()
    try:
        general_bin_re = re.compile(bin_string)
        script_file_paths = list()
        shebang_check = re.compile("^#!.*/bin/.*sh\s*$")  # re.compile("^#!.*bin/.*sh\s*$") # bash, ash etc
        for file_path in raw_references:
            if file_path.endswith(".sh"):
                script_file_paths.append(file_path)
            else:
                with open(file_path) as f:
                    try:
                        line = f.readline()
                        if shebang_check.match(line):
                            script_file_paths.append(file_path)
                    except UnicodeDecodeError:
                        pass

        for file_path in script_file_paths:
            valid_reference_found = False  # updated below
            with open(file_path) as f:
                for line in f:
                    # check shebang
                    line_no_indent = line.strip()
                    if len(line_no_indent) > 0 and (general_bin_re.search(line_no_indent) is not None):

                        valid_reference_found |= line_no_indent.startswith("#!") or (line_no_indent[0] != "#")
                        if valid_reference_found:
                            _logger.debug(f"found reference to {binary_name}: '{line_no_indent}' ({file_path})")
                            break
                        else:
                            _logger.debug(f"ignoring reference to {binary_name}: '{line_no_indent} ({file_path})'")
            if valid_reference_found:
                filtered_references.append(file_path)
    except re.error:
        _logger.error(f"re error for {bin_string}")
    return filtered_references


def _get_all_references(binary_file_names, root_dir, executor):
    """
    get a dictionary that lists .sh files that contain likely executions of the corresponding binary.
    The list may be emtpy
    """

    start_t = datetime.now()
    uses = dict()

    def _get_references(binary_name):
        all_references = (_get_sh_references(binary_name, root_dir) +
                          _get_systemd_references(binary_name, root_dir))

        filtered_references = list()
        for reference in all_references:
            if reference.endswith(f"bin/{binary_name}"):
                _logger.debug(f"removed {reference}, self reference to {binary_name}")
            else:
                filtered_references.append(reference)

        return binary_name, filtered_references,

    futures = list()
    for binary_file_name in binary_file_names:
        futures.append(executor.submit(_get_references, binary_file_name))

        if _test_mode and len(futures) >= _files_processed_in_test_mode:
            break

    for future in futures:
        data = future.result()
        uses[data[0]] = data[1]

    delta_t = datetime.now() - start_t
    _logger.info(f"Completed in {round(delta_t.total_seconds())} seconds")

    return uses


_bin_locations = ("bin", "sbin", "usr/bin", "usr/sbin")


def output_binary_usage_report(root_fs_path, report_file_path, logger, executor):
    """
   Analyses files specified root_fs_path's bin folders and identifies most calls to them in
   Shell scripts & systemd unit files.  This script does not fully implement shell scripting or systemd parsing rules so
   some false positives and false negatives should be expected.
    """

    # set module scope _logger
    global _logger
    _logger = logger

    binary_directories = [os.path.join(root_fs_path, x) for x in _bin_locations]

    list_of_binary_names = list()
    file_sizes = dict()
    for directory in binary_directories:
        if os.path.isdir(directory):
            new_names = [name for name in os.listdir(directory) if
                         name not in list_of_binary_names and os.path.isfile(os.path.join(directory, name))]

            for name in new_names:
                file_sizes[name] = round(os.path.getsize(os.path.join(directory, name)) / 1000)

            list_of_binary_names += new_names

    uses = _get_all_references(list_of_binary_names, root_fs_path, executor)

    with open(report_file_path, "w") as f:
        print("Binary Name, Size kB, Use Count, Uses", file=f)

        for binary_file_name in sorted(uses.keys()):
            row = f"{binary_file_name}, {file_sizes[binary_file_name]}, {len(uses[binary_file_name])},"
            for use in uses[binary_file_name]:
                row += f" {use}"
            print(row, file=f)
    return report_file_path


if __name__ == "__main__":
    import logging

    _logger = logging.getLogger("binaryUsage")
    logging.basicConfig(level=logging.DEBUG)
    import argparse

    parser = argparse.ArgumentParser(
        description=f"Analyses the specified root fs. Analyses files from the rootfs bin folders {_bin_locations}."
                    f"Lists confirmed uses of these files from shell scripts & systemd unit files in the output report")
    parser.add_argument("root_dir", help="The location of the rootfs to be analysed")
    parser.add_argument("report_path", help="output path for report")
    parser.add_argument('--debug', help="Enable debug logging", action='store_true')
    parser.add_argument('--test_mode', help="Only process a few files to speed up testing", action='store_true')

    args = parser.parse_args()
    _test_mode = args.test_mode
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    output_binary_usage_report(args.root_dir, args.report_path, _logger)
