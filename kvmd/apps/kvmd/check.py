#!/usr/bin/env python
# -*- coding: utf-8 -*-

# here put the import lib

import configparser
import hashlib
import json
import os
import re
import subprocess
import traceback
import shutil
from urllib.parse import urljoin

import aiohttp
import psutil

from ...logging import get_logger

logger = get_logger(0)


def md5sum(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def check_version(v1: str, v2: str):
    """
    返回值：1 v1大于v2; 0 v1等于v2; -1 v1小于v2
    :param v1:
    :param v2:
    :return:
    """
    v1_l = v1.split(".")
    v2_l = v2.split(".")
    c = 0
    while True:
        if c == len(v1_l) and c == len(v2_l):
            return 0
        if len(v1_l) == c:
            v1_l.append("0")
        if len(v2_l) == c:
            v2_l.append("0")
        if int(v1_l[c]) > int(v2_l[c]):
            return 1
        elif int(v1_l[c]) < int(v2_l[c]):

            return -1
        c += 1


def get_cur_addr():
    """
    获取本机IPv4地址
    :return:
    """
    """获取ipv4地址"""
    dic = psutil.net_if_addrs()
    ipv4_list = []
    for adapter in dic:
        snic_list = dic[adapter]
        for snic in snic_list:
            if snic.family.name == 'AF_INET':
                ipv4 = snic.address
                if ipv4 == '127.0.0.1':
                    continue
                ipv4_list.append(ipv4)

    if len(ipv4_list) >= 1:
        return ipv4_list[0]
    else:
        return None


class UpgradeInfo(object):
    def __init__(self):
        self._upgrade_info_path = "/var/log/updinfo"

    def write(
            self,
            version: str,
            username: str,
            tag: int = 0,
            primary_id: int = None,
            ip: str = None,
            is_cancel: int = 0,
    ):
        """
        :param version:
        :param username:
        :param tag:
            0: KVMD侧手动升级
            1：通过RCC平台一键升级功能
        :param primary_id:
        :param ip:
        :param is_cancel: 是否手动取消升级
            0：没有取消升级
            1：取消升级
        :return:
        """
        if ip is None:
            ip = get_cur_addr()
        infos = dict(
            version=version,
            username=username,
            tag=tag,
            ip=ip,
            primary_id=primary_id,
            is_cancel=is_cancel
        )
        with open(self._upgrade_info_path, 'w') as fp:
            json.dump(infos, fp)
        return True

    def read(self):
        with open(self._upgrade_info_path, "r") as fp:
            infos = json.load(fp)
        return infos if infos else dict(
            version="", username="", tag="", ip="", primary_id=None)

    def clear(self):
        with open(self._upgrade_info_path, "w") as fp:
            json.dump(dict(
                version="", username="", tag="", ip="", primary_id=None), fp)

    def remove(self):
        if os.path.exists(self._upgrade_info_path):
            os.remove(self._upgrade_info_path)


class PlatformSettings(object):
    def __init__(self):
        self._config = configparser.ConfigParser()
        self._config.read("/app/settings")

    @property
    def get_ip(self):
        return self._config.get("platform", "addr")

    @property
    def get_port(self):
        return self._config.get("platform", "port")

    @property
    def get_protocol(self):
        return self._config.get("platform", "protocol")

    @property
    def get_username(self):
        return self._config.get("platform", "username")

    @property
    def get_password(self):
        return self._config.get("platform", "password")


class CheckAutoOperation(object):
    """
    检查是否存在代操任务
    """

    def __init__(self):
        self._settings = PlatformSettings()
        self.__check_uri = "api/auto_operate/process/has_running"
        self._cur_addr = self.__get_cur_addr()

    def _get_check_url(self):
        base_url = "{protocol}://{addr}:{port}/".format(
            protocol=self._settings.get_protocol,
            addr=self._settings.get_ip, port=self._settings.get_port)
        return urljoin(base_url, self.__check_uri)

    @staticmethod
    def __get_cur_addr():
        """
        获取本机IPv4地址
        :return:
        """
        """获取ipv4地址"""
        dic = psutil.net_if_addrs()
        ipv4_list = []
        for adapter in dic:
            snic_list = dic[adapter]
            for snic in snic_list:
                if snic.family.name == 'AF_INET':
                    ipv4 = snic.address
                    if ipv4 == '127.0.0.1':
                        continue
                    ipv4_list.append(ipv4)

        if len(ipv4_list) >= 1:
            return ipv4_list[0]
        else:
            return None

    async def check(self):
        """
        True 是可以升级， False 是不可以进行升级
        :return:
        """
        try:
            if not self._cur_addr:
                return True
            url = self._get_check_url()
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=dict(
                        kvm_ip=self._cur_addr)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                    if isinstance(data, dict) and not data["data"][
                        "has_running"]:
                        return True
        except Exception as e:
            logger.error(e)
            logger.error(traceback.print_exc())
        return False


class CheckPack(object):
    def __init__(self):
        self._chunk_size = 8192 * 1024
        self._check_pack_url = "/api/equipment/kvm/package/latest"
        self._pack_path = "/home/tmp/pack"
        self._pack_name = "/home/tmp/RccKVMD.zip"
        self._unzip_command = "DatrixPack unpack -file=/home/tmp/RccKVMD.zip -o=/home/tmp/pack"
        self._settings = PlatformSettings()
        self._cur_ver = self.get_cur_ver()

    @staticmethod
    def get_cur_ver():
        if not os.path.exists("/app/version"):
            return "1.0.0"
        with open("/app/version", "r") as fp:
            cur_version = fp.readline()
        if not cur_version:
            return "1.0.0"
        cur_ver = re.findall(r".*?KVMD(.+?)Build", cur_version)[0]
        if not cur_ver or not isinstance(cur_ver, str):
            return "1.0.0"
        return cur_ver.strip()

    def _get_check_url(self):
        base_url = "{protocol}://{addr}:{port}/".format(
            protocol=self._settings.get_protocol,
            addr=self._settings.get_ip, port=self._settings.get_port)
        return urljoin(base_url, self._check_pack_url)

    async def download_pack(self, download_url, _md5sum):
        """
        下载软件包
        :param download_url:
        :param _md5sum:
        :return:
        """

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(download_url) as resp:
                    with open(self._pack_name, "wb") as fp:
                        async for chunk in resp.content.iter_chunked(
                                self._chunk_size):
                            fp.write(chunk)
            if not os.path.exists(self._pack_name):
                return False
            pack_md5 = md5sum(self._pack_name)
            if pack_md5 != _md5sum:
                os.remove(self._pack_name)
                return False
            return True
        except Exception as e:
            logger.error(e)
            logger.error(traceback.print_exc())
        return False

    def unpack(self):
        """
        解压ZIP软件包
        :return:
        """
        if os.path.exists(self._pack_path):
            shutil.rmtree(self._pack_path, ignore_errors=True)

        recode = subprocess.call(
            [self._unzip_command], shell=True, timeout=10 * 60)
        if recode != 0:
            return False

        # recode = subprocess.call(
        #     ["rm -rf /home/tmp/RccKVMD.zip"], shell=True, timeout=60)
        if os.path.exists(self._pack_name):
            os.remove(self._pack_name)

        return True

    async def check(self):
        """
        检查用用升级包
        :return:
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self._get_check_url()) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        pack_url = data.get("url", "")
                        pack_md5sum = data.get("kvmd_md5sum", "")
                        version = data.get("version", "")
                        pack_ver = re.findall(r"[\d.]+", version)[0]
                        cur_version = self.get_cur_ver()
                        res = check_version(pack_ver, cur_version)
                        if res == -1:
                            logger.info("无需升级固件版本已是最新版本")
                            return
                        download_status = await self.download_pack(
                            pack_url, pack_md5sum)
                        if not download_status:
                            logger.error(f"软件包版本：{version}，软件包下载失败")
                        unpack_status = self.unpack()
                        if not unpack_status:
                            logger.error(f"软件包版本：{version}，软件包提取失败")
        except Exception as e:
            logger.error(e)
            logger.error(traceback.print_exc())
