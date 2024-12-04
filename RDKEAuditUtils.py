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
from datetime import datetime
import os
import os.path
from pathlib import Path
from shutil import rmtree, unpack_archive
import subprocess
import sys
from tempfile import mkdtemp
import glob
import re
import csv


def add_poky_scripts_to_sys_path():
    build_scripts_path=os.path.dirname(os.path.realpath(__file__))
    lib_path = os.path.dirname(build_scripts_path) + '/rdke/common/poky/scripts/lib'
    sys.path = sys.path + [lib_path]

def get_layer_version_info(tinfoil):
    info="\nRELEASE_LAYER_VERSIONS\n"
    file = Path(tinfoil.config_data.getVar("RELEASE_LAYER_VERSIONS", True))
    if file.is_file():
        info+= file.read_text()
    else:
        info+="unknown"

    info+="\nIPK_FEED_URIS\n"
    for uri in tinfoil.config_data.getVar("IPK_FEED_URIS").split(): 
        info+=f"{uri}\n"
    return info

add_poky_scripts_to_sys_path()
import scriptutils

logger = scriptutils.logger_create('rdk_rootfs_audit_utils')

def packages_from_manifest(manifest_file_path):

    # Handle situations where the manifest file has a different timestamp
    search_term = os.path.join(os.path.dirname(manifest_file_path), "*.manifest")
    print(search_term)
    manifest_files =  glob.glob(search_term)
    if manifest_file_path in manifest_files:
        correct_manifest_path = manifest_file_path
    elif len(manifest_files)>0:
        # likely the script has not been run directly after building
        correct_manifest_path = os.path.realpath(manifest_files[0]) # follow links
        logger.warn(f'{manifest_file_path} not found using {correct_manifest_path} instead.')
    else:
        logger.error(f'No manifest file.')
        correct_manifest_path=None

    packages =list()
    if correct_manifest_path is not None:
        with open(correct_manifest_path) as f:
            for line in f:
                package = line.split()[0]
                if len(package)>0:
                    packages.append(package)

    logger.info(f'{len(packages)} packages in {correct_manifest_path}.')
    return packages

def get_max_workers():
        """consistent with python 3.8 default logic"""
        cores = os.cpu_count()
        return 5 if cores is None else min(32, cores + 4)

class _IpkFileLookup:
    """
    An object that indexs ipk file names by rootfs file names.
    The intention is that the ipk file name is then used with OPKGPackageInfo
    """

    @staticmethod
    def __get_file_dict(package_path: str):
        """create a lookup dict from single ipk file"""
        package_dict = dict()
        tmp_dir = mkdtemp()
        try:
            ipk_file_name = os.path.split(package_path)[1]

            subprocess.run(("ar", "x", package_path), cwd=tmp_dir)
            data_path = os.path.join(tmp_dir, "data.tar.xz")
            if os.path.exists(data_path):
                files_path = os.path.join(tmp_dir, "data")
                os.mkdir(files_path)

                unpack_archive(data_path, files_path)

                for file in Path(files_path).glob('**/*'):
                    if file.is_file():
                        rootfs_path = str(file).replace(files_path, "")
                        package_dict[rootfs_path] = ipk_file_name

        except Exception as ex:
            logger.error(str(ex))

        finally:
            rmtree(tmp_dir)

        return package_dict

    def __init__(self, ipk_folder: str, executor):
        self.file_lookup = dict()
        package_files = list(Path(ipk_folder).glob('**/*.ipk'))
        logger.info(f'''processing {len(package_files)} ipk files''')

        # create a separate dictionary for each ipk file
        futures = list()
        for package in package_files:
            futures.append(executor.submit(__class__.__get_file_dict, package))

        # update self.file_lookup from file dictionaries as these become available
        for future in futures:
            try:
                data = future.result()
                self.file_lookup.update(data)
            except Exception as ex:
                logger.error(str(ex))

        logger.info(f'''found {len(self.rootfs_file_paths)} files in ipks''')

    def __getitem__(self, rootfs_file_path):
        """
        lookup the file name of the ipk that contains the supplied rootfs file path
        """
        if type(rootfs_file_path) is not str:
            raise TypeError(str(type(rootfs_file_path)) + "is not a str.")

        return self.file_lookup.get(rootfs_file_path, None)

    @property
    def ipk_file_names(self):
        return list(set(self.file_lookup.values()))

    @property
    def rootfs_file_paths(self):
        return self.file_lookup.keys()

def get_depends_dict(packages, packages_used_in_build):
    depends_dict = dict()
    for recipe in packages[0].tinfoil.all_recipes():
        depends = packages_used_in_build.intersection(set(recipe.depends))
        if len(depends)>0:
            for package in packages_used_in_build.intersection(set(recipe.packages)):
                depends_dict[package] = depends
    return depends_dict


def get_required_by_dict(depend_dicts, packages_used_in_build):
    """
    invert & combine multiple 'depends on' dicts into one 'required by' dict which
    only includes the packages included in the supplied build manifest
    """

    required_by_dict=dict()
    for depend_dict in depend_dicts:
        for package_name in packages_used_in_build.intersection(set(depend_dict.keys())):
            for dependancy in packages_used_in_build.intersection(set(depend_dict[package_name])):
                required_by_dict.setdefault(dependancy, list()).append(package_name)
    return required_by_dict

class _OPKGPackageInfo:
    """
    A faster alternative to 'opkg info' commands.
    This information is used in rdk_rootfs_audit reports.
    """

    def __init__(self, list_file_or_list_dir_path=None):
        self.filename_lookup = dict()
        if os.path.isdir(list_file_or_list_dir_path):
            for sub_path in Path(list_file_or_list_dir_path).glob('*'):
                self.__add_package_info(_OPKGPackageInfo(sub_path).filename_lookup.values())
        elif os.path.isfile(list_file_or_list_dir_path) is not None:
            self.__add_package_info(__class__.__get_package_info_from_file(list_file_or_list_dir_path))
        self.package_name_to_ipk_name = dict() # ipk file name keyed by package name
        for ipk_file_name in self.filename_lookup.keys():
            package_info  = self.filename_lookup[ipk_file_name]
            if "Package" in package_info:
               self.package_name_to_ipk_name[package_info["Package"]]=ipk_file_name

    def get_depends_dict(self):
        depends_dict = dict()
        for package_info in self.filename_lookup.values():
            if "Depends" in package_info.keys() and "Package" in package_info.keys():
                name = package_info["Package"]

                def package_or_group(possible):
                       return len(possible)>0 and "(" not in possible and ")" not in possible

                if package_or_group(name):
                    for dependancy in package_info["Depends"].split():
                        if package_or_group(dependancy):
                            depends_dict.setdefault(name, list()).append(dependancy)
        return depends_dict

    def __getitem__(self, ipk_file_name):
        """return a dictionary containing OPKG info about the package corresponding to the supplied ipk file name"""
        if type(ipk_file_name) is not str:
            raise TypeError(str(type(ipk_file_name)) + "is not a str.")
        return self.filename_lookup.get(ipk_file_name, None)


    def required_ipk_files(self, manifest_file_path):
        required_ipks = list()
        installed_packages = packages_from_manifest(manifest_file_path)
        for package in installed_packages:
            if package in self.package_name_to_ipk_name:
                ipk_name = self.package_name_to_ipk_name[package]
                required_ipks.append(ipk_name)

        return required_ipks

    def package_name(self, ipk_file_name):
        """get the package name corresponding to the supplied ipk file name"""
        lookup = self.filename_lookup.get(ipk_file_name, None)
        if lookup is None:
           name = None
        else:
           name = lookup.get("Package", None)
        return name

    def __add_package_info(self, list_of_package_info):
        for package in list_of_package_info:
            self.filename_lookup[package["Filename"]] = package

    @staticmethod
    def __get_package_info_from_file(file_path):
        all_package_info = list()
        current_package_info = dict()
        with open(file_path) as f:
            current_key = None
            for line in f:
                if ":" in line:
                    split_line = line.split(":", 1)
                    if len(split_line) == 2:
                        current_key = split_line[0].strip()
                        current_package_info[current_key] = split_line[1].strip()
                    else:
                        raise ValueError(f"unexpected format, multiple ':' in {line}")
                elif len("".join(line.split())) == 0:
                    # package seperator
                    if len(current_package_info.keys()) > 0:
                        if "Package" in current_package_info.keys():
                            all_package_info.append(current_package_info)
                        else:
                            raise ValueError(f"no package name in {current_package_info}")
                    current_key = None
                    current_package_info = dict()
                elif current_key is not None:
                    current_package_info[current_key] += (" " + line.strip())
                else:
                    logger.warn(f"unexpected line: {line}")

        return all_package_info


class _Ipkdownloader:
    """
    Provides a mechanism to download all .ipk files available to the build.
    The normal RDK-E build deletes these files as it uses opkg's --volatile-cache option.
    The downloaded .ipk files are needed to link these rootfs files back to their source .ipk
    """
    def __init__(self, image_work_dir):
        logger.debug(f"image_work_dir: {image_work_dir}")
        conf_file = os.path.join(image_work_dir, "opkg.conf")

        def file_check(file_path):
            if os.path.isfile(file_path):
                logger.debug(f"File exists: {file_path}")
            else:
                logger.error(f"File does not exist: {file_path}")

        file_check(conf_file)
        opkg_bin = os.path.join(image_work_dir, "recipe-sysroot-native/usr/bin/opkg")
        file_check(opkg_bin)

        self.fake_fs = mkdtemp()
        self.tmp = mkdtemp()

        self.opkg_base_cmd = [opkg_bin, "-f", conf_file, "-t", self.tmp, "-o", self.fake_fs]
        self.__opkg("update")

        lists_path = os.path.join(self.fake_fs, "var/lib/opkg/lists")
        self.package_info = _OPKGPackageInfo(lists_path)

    def __del__(self):
        try:
            rmtree(self.fake_fs)
            rmtree(self.tmp)
        except FileNotFoundError as ex:
            logger.error(ex)

    def __opkg(self, arg, cwd=None, stdout=subprocess.PIPE):
        if len(arg) > 10:
            logger.info(f"opkg {arg[0:10]}...")
        else:
            logger.info(f"opkg {arg}")
        if type(arg) is str:
            specific_command = self.opkg_base_cmd + [arg]
        else:
            specific_command = self.opkg_base_cmd + arg

        return subprocess.run(specific_command, stdout=stdout, cwd=cwd)

    def package_name(self, ipk_file_name):
        """get the package name corresponding to the supplied ipk file name"""
        return self.package_info.package_name(ipk_file_name)

    def download(self, ipk_dir, manifest_file_path):
        """Download ipks files for RDK-E Layers"""
        files = os.listdir(ipk_dir)
        missing_package_names = list()
        required_ipk_files = self.package_info.required_ipk_files(manifest_file_path)
        for file_name in required_ipk_files:
            if file_name not in files:
                missing_package_names.append(self.package_name(file_name))

        if len(missing_package_names) > 0:
            logger.info(f"{len(missing_package_names)}/{len(required_ipk_files)} to download")

            start = datetime.now()
            self.__opkg(["download"] + missing_package_names, cwd=ipk_dir, stdout=None)
            logger.info(f"download completed in {datetime.now() - start}")


class MinimalPackageInfo:
    """
    An abstraction of rdk_rootfs_audit's Package class which
    make the coupling between Package & RDKEPackageInfo explicit
    """
    __unknown_str: str = "Unknown no Ipk"

    def __init__(self):
        self.file_name = __class__.__unknown_str
        self.name = __class__.__unknown_str
        self.recipe_name = __class__.__unknown_str

        self.license = __class__.__unknown_str
        self.category = __class__.__unknown_str
        self.recipe_file = __class__.__unknown_str
        self.layer = __class__.__unknown_str
        self.appends = []

    def srcuri(self):
        return (__class__.__unknown_str,)


class RDKEPackageInfo(MinimalPackageInfo):
    """
    An object compatible with rdk_rootfs_audit's Package class.
    """

    def update(self, package_info, all_categories):
        self.file_name = package_info['Filename']
        self.name = package_info['Package']
        self.license = package_info["License"]
        self.recipe_file = package_info["Source"]
        self.recipe_name = self.recipe_file.rstrip(".bb").rstrip(".bbappend")

        split_name = self.file_name.rstrip(".ipk").rsplit("_", 1)
        if len(split_name) == 2:
            self.layer = split_name[1]
        else:
            logger.info(f"no layer name from {self.file_name}")

        self.category = all_categories.get_package_category(self.name)


class RDKELayerInterface:
    """
    Provides information about rootfs files which are populated by different RDK-E layers.
    By design bitbake recipies for these files are not available to the final build.
    Intended for use by rdk_rootfs_audit.
    """

    def __init__(self, package_dir, all_categories, ipk_dir, manifest_file_path, profiler, executor):
        self.ipk_Downloader = _Ipkdownloader(package_dir)
        self.all_categories = all_categories
        self.package_info_cache = dict()  # RDKEPackageInfo indexed by ipkfile name
        self.unknown_package = RDKEPackageInfo()  # common package for files with no corresponding ipk

        if not os.path.exists(ipk_dir):
            os.mkdir(ipk_dir)

        # (re)download ipk files from other RDK-E layers.
        # This is necessary to allow rootfs files from these packages to be traced.
        # During the build Ipk files are deleted by opkg's --volatile-cache option
        # making --volatile-cache configurable in bitbake was considered but this option was selected because its 
        # more maintainable & lower impact (new code added here rather than modifying open-embedded code).
        self.ipk_Downloader.download(ipk_dir, manifest_file_path)
 
        # index the ipk files
        self.ipk_file_lookup = _IpkFileLookup(ipk_dir, executor)
        logger.info(
            f'Found {len(self.ipk_file_lookup.ipk_file_names)} ipk packages for '
            f'{len(self.ipk_file_lookup.rootfs_file_paths)} files.')

    def get_ipk_depends_dict(self):
        return self.ipk_Downloader.package_info.get_depends_dict()

    def get_package(self, rootfs_file_path):
        """
        Normally returns an RDKEPackageInfo object containing information about the specified rootfs file.
        Where no information about rootfs_file_path is available, return an empty RDKEPackageInfo object.
        """
        return_info = self.unknown_package

        ipk_file_name = self.ipk_file_lookup[rootfs_file_path]
        if ipk_file_name is not None:
            if ipk_file_name in self.package_info_cache.keys():
                return_info = self.package_info_cache[ipk_file_name]
            else:
                ipk_info = self.ipk_Downloader.package_info[ipk_file_name]
                if ipk_info is not None:
                    self.package_info_cache[ipk_file_name] = RDKEPackageInfo()
                    self.package_info_cache[ipk_file_name].update(ipk_info, self.all_categories)
                    return_info = self.package_info_cache[ipk_file_name]

        return return_info

    def write_summary_file(self, file_path, required_by_dict):
        """write a report which lists rootfs files with corresponding .ipk files"""
        with open(file_path, 'w') as f:
            f.write("Rootfs Filename, Ipk, Package, Required by\n")
            for file in self.ipk_file_lookup.rootfs_file_paths:
                ipk_name = self.ipk_file_lookup[str(file)]
                package_name = self.ipk_Downloader.package_info.package_name(ipk_name)
                if package_name in required_by_dict.keys():
                    required_by = ""
                    for required_by_component in required_by_dict[package_name]:
                        required_by += required_by_component
                        required_by +=" "
                    logger.debug(f'{package_name}:required by {required_by}')
                else:
                    logger.debug(f'{package_name} (for {ipk_name}) is not in required by dict')
                    required_by = ""
                f.write(f'{file}, {ipk_name}, {package_name}, "{required_by}"\n')
        return file_path
    
def filter_csv_report(input_report_path, filtered_report_path, filter):
    """
    Creates a filtered version of the input report using the supplied filter.
    returns the number of entries in the new report (excluding the header row)
    """
    lines_in_filtered_report=0
    with open(input_report_path) as input_file:
        with open(filtered_report_path, 'w') as output_file:
            for count, line in enumerate(input_file):
                if count==0 or filter.match(line):
                    output_file.write(line)
                    lines_in_filtered_report+=1
    return max(0, lines_in_filtered_report-1)


class RuntimeProfiler:
    def __init__(self):
        self.logs = [("start", datetime.now())]
        self.label_postfix=""

    @staticmethod
    def get_period_label(log, last_log):

        if ((last_log[0].startswith("pre ") and log[0].startswith("post ")) and
            (last_log[0].replace("pre ", "") == log[0].replace("post ", ""))):
            return last_log[0].replace("pre ", "")
        else: 
            return f"{last_log[0]} to {log[0]}"
    @staticmethod
    def get_rounded_total_seconds(log, last_log):
        period_dt = log[1] - last_log[1]
        return round(period_dt.total_seconds()*100)/100

    def log(self, label):
        new_entry = (f"{label} {self.label_postfix}", datetime.now())
        self.logs.append(new_entry)

        previous_entry = self.logs[-2]
        dt = self.get_rounded_total_seconds(new_entry, previous_entry)
        if dt>1:
            msg=f"RuntimeProfiler:{self.get_period_label(new_entry, previous_entry)} took {dt} seconds"
            if dt>10:
                logger.warning(msg)
            else:
                logger.info(msg)

    def total_time_row(self):
        return ("Total logged execution Time", (self.logs[-1][1] - self.logs[0][1]).total_seconds(),)

    def log_total_time(self):
        row = self.total_time_row()
        logger.warning(f"{row[0]}:{row[1]}")

    def output_report(self, file_path):
        with open(file_path, 'w') as  f:
            csv_writer = csv.writer(f, escapechar='\\', quoting=csv.QUOTE_NONE)
            csv_writer.writerow(("Period","Duration (s)",))
            
            last_log = None
            for log in self.logs:
                if last_log is not None:
                    period_dt = log[1] - last_log[1]
                    csv_writer.writerow((self.get_period_label(log, last_log),
                                         period_dt.total_seconds(),))

                last_log=log

            csv_writer.writerow(self.total_time_row())

        return file_path