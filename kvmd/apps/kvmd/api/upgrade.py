#!/usr/bin/env python
# -*- coding: utf-8 -*-

import configparser
import os.path
import re
import asyncio
import subprocess
import time
import traceback
import threading

# here put the import lib
from datetime import datetime
from typing import AsyncGenerator
from aiohttp.web import Request
from aiohttp.web import Response
from ..report_log import put_upgrade_record_download, \
    put_upgrade_record_upgrade, record_log
from ..table import LogTable
from ..auth import AuthManager
from ..check import CheckAutoOperation, check_version, CheckPack, UpgradeInfo, \
    get_cur_addr
from ...utils.system import get_system_version
from ....htserver import HttpError, exposed_http, make_json_response
from ....logging import get_logger
from .... import aiotools
from ....validators.auth import valid_auth_token

_COOKIE_AUTH_TOKEN = "auth_token"
_DEFAULT_USERNAME = "admin"
UPDATE_NOW_CODE, SHELL_RES_CODE = 1, 0


class UploadError(Exception):
    def __init__(self, msg: str, status: int) -> None:
        super().__init__(msg)
        self.status = status


class UpgradeApi(object):
    username, message = None, None
    pack_version, pack_depends, pack_info, pack_date = None, None, None, None

    def __init__(self, log_table: LogTable, auth_manager: AuthManager):
        self._tmp_path = "/home/tmp/"
        self._app_ver_path = "/app/version"
        self._rcc_settings = "/app/settings"
        self._upgrade_script = "/usr/sbin/upgrade.sh"
        self._untar_command = "tar -zxvf {0} -C /home/tmp/"
        self._pack_info = "/home/tmp/pack/pkginfo"
        self._pack_version = "/home/tmp/pack/version"
        self._unzip_command = "DatrixPack unpack -file=/home/tmp/RccKVMD.zip -o=/home/tmp/pack"
        self._pack_max_size = 2 * 1024 * 1024 * 1024
        self._chunk_size = 8192 * 1024
        self._log_table = log_table
        self.__state_poll = 1
        self._auto_upgrade_seconds = 5 * 60
        self.__auth_manager = auth_manager
        self._upd_info = UpgradeInfo()
        self.__notifier = aiotools.AioNotifier()

    @exposed_http("POST", "/upgrade/pack/upload")
    async def upload(self, request: Request) -> Response:
        """
        软件包上传接口
        请求接口报文头必须加{"Content-Type":"multipart/form-data"}
        :return:
        """
        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(
                request.headers.get("Authorization", ""))
            user = self.__auth_manager.check(valid_auth_token(token))
        else:
            user = _DEFAULT_USERNAME

        try:
            self._clear_pack()
            reader = await request.multipart()
            pack = await reader.next()
            filename = pack.filename
            file_size = 0
            if not os.path.exists(self._tmp_path):
                os.makedirs(self._tmp_path)
            pack_filename = os.path.join(self._tmp_path, filename)
            with open(pack_filename, "wb") as fp:
                while True:
                    chunk = await pack.read_chunk(self._chunk_size)
                    if not chunk:
                        break
                    file_size += len(chunk)
                    fp.write(chunk)
                    if file_size > self._pack_max_size:
                        self._clear_pack()
                        self._log_table.insert_log(
                            username=user, level=15,
                            description="上传失败，软件包太大, 无法上传")
                        raise HttpError(
                            msg="上传失败，软件包太大, 无法上传", status=400)

            res = self._unpack(packname=pack_filename)
            if not res:
                self._log_table.insert_log(
                    username=user, level=15, description="上传失败，包解压失败")
                raise EOFError("上传失败，软件包解压失败")

            self.username = user
            results = self._check_pack()
            self.pack_version = results.get("version")
            self.pack_depends = results.get("depends")
            self.pack_info = results.get("info")
            self.pack_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            kvm_ip = get_cur_addr()
            version = self._get_version(filepath=self._pack_version)

            # 写入信息
            self._upd_info.write(
                version=version,
                username=user,
                tag=0,
                ip=kvm_ip,
                primary_id=None,
            )

            return make_json_response(result=results)
        except Exception as e:
            get_logger().error(e)
            get_logger().error(traceback.print_exc())
            self._clear_pack()
            self._log_table.insert_log(
                username=user, level=15, description="上传失败")
            raise HttpError(msg="上传失败", status=400)

    @exposed_http("POST", "/upgrade/confirm")
    async def upgrade(self, request: Request) -> Response:
        """
        确认升级
        :return:
        """
        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(
                request.headers.get("Authorization", ""))
            user = self.__auth_manager.check(valid_auth_token(token))
        else:
            user = _DEFAULT_USERNAME

        self._log_table.insert_log(
            username=user, level=10,
            description=f"用户：{user}，确认了对最新包进行升级")
        version = self._get_version(filepath=self._pack_version)
        # 读取再写入，避免信息丢失
        try:
            infos = self._upd_info.read()

            self._upd_info.write(
                version=version,
                username=user,
                tag=infos["tag"],
                primary_id=infos["primary_id"],
                ip=infos["ip"],
            )
        except FileNotFoundError:
            get_logger(0).error(traceback.format_exc())

        if not os.path.exists(self._rcc_settings):
            self._log_table.insert_log(
                username=user, level=10,
                description=f"请先确认RCC管理系统配置信息是否正确，无法进行升级")
            self.username = None
            self.message = None
            self.pack_version = None
            self.pack_depends = None
            self.pack_info = None
            return make_json_response(
                status=400,
                result=dict(msg="请先确认RCC管理系统配置信息是否正确...")
            )

        check_status = await CheckAutoOperation().check()
        if not check_status:
            self._log_table.insert_log(
                username=user, level=10,
                description=f"验证代操失败或正在执行代操任务，无法进行升级")
            self.username = None
            self.message = None
            self.pack_version = None
            self.pack_depends = None
            self.pack_info = None
            return make_json_response(
                status=400,
                result=dict(
                    msg="验证代操失败或正在执行代操任务，无法进行升级，请稍后重试...")
            )

        self.username = user
        confirm_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.message = f"用户：[{user}], 对固件版本：{version}升级进行了确认，时间：" \
                       f"[{confirm_date}]，\n\n正在升级，预计需要10分钟..."
        time.sleep(5)

        subprocess.Popen("bash {0}".format(self._upgrade_script), shell=True)
        return make_json_response(
            result=dict(msg="正在升级，预计需要10分钟...")
        )

    @exposed_http("GET", "/upgrade/cancel")
    async def cancel(self, request: Request) -> Response:
        """
        取消升级
        :return:
        """
        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(
                request.headers.get("Authorization", ""))
            user = self.__auth_manager.check(valid_auth_token(token))
        else:
            user = _DEFAULT_USERNAME

        self.username = user
        self._log_table.insert_log_for_request(
            request=request, level=10,
            description=f"取消了[{self.pack_version}]包的升级")
        self.pack_version = None
        self.pack_depends = None
        self.pack_info = None
        self.pack_date = None
        await record_log(status=4)
        infos = self._upd_info.read()
        self._upd_info.write(
            version=infos["version"],
            username=infos["username"],
            tag=infos["tag"],
            ip=infos["ip"],
            primary_id=infos["primary_id"],
            is_cancel=1,
        )

        return make_json_response()

    @exposed_http("GET", "/upgrade/pack/info")
    async def upgradable(self, _: Request) -> Response:
        """
        可升级版本信息
        :return:
        """
        if not os.path.exists(self._pack_info):
            return make_json_response()

        config = configparser.ConfigParser()
        config.read(self._pack_info)
        version = self._get_version(filepath=self._pack_version)
        depends = config.get("depends", "depends")
        info = config.get("infos", "infos")
        level = config.getint("levels", "levels")
        cur_version = "RccKVMD1.0.0 Build20230601"

        if os.path.exists(self._app_ver_path):
            with open(self._app_ver_path, "r") as fp:
                cur_version = fp.readline()
            if not cur_version:
                return make_json_response()
            cur_ver = re.findall(r".*?KVMD(.+?)Build", cur_version)[0]
            if isinstance(cur_ver, str):
                cur_ver = cur_ver.strip()
            depend_ver_list = depends.split(",")
            if (cur_ver is None) or (cur_ver not in depend_ver_list):
                return make_json_response()

        return make_json_response(
            result=dict(
                version=version,
                depends=depends,
                info=info,
                level=level,
                cur_ver=cur_version
            )
        )

    @exposed_http("GET", "/upgrade/system/version")
    async def system_version(self, _: Request) -> Response:
        """
        查看当前系统的版本信息
        :param _:
        :return:
        """
        version = await get_system_version()

        return make_json_response(
            result=version
        )

    @exposed_http("POST", "/upgrade/system/upgrade")
    async def new_pack_info(self, request: Request) -> Response:
        """对应RCC平台的一键升级功能"""
        data = await request.json()
        get_logger(0).info("upgrade api body: {data}".format(data=data))
        check_obj = CheckPack()
        version = data.get("version", "")
        update_now = data.get("update_now")
        primary_id = data.get("upgrade_record_id")
        if not version:
            return make_json_response(
                result=dict(msg="固件升级失败")
            )
        pack_ver = re.findall(r"[\d.]+", version)[0]
        cur_version = check_obj.get_cur_ver()
        res = check_version(pack_ver, cur_version)
        if res == -1:
            return make_json_response(
                result=dict(msg="固件版本已是最新版本")
            )
        pack_url = data.get("pack_url", "")
        pack_md5sum = data.get("md5sum", "")

        kvm_ip = get_cur_addr()

        download_status = await check_obj.download_pack(pack_url, pack_md5sum)
        if not download_status:
            await put_upgrade_record_download(
                primary_id=primary_id, download_result=0)
            return make_json_response(
                result=dict(msg="固件升级失败")
            )
        await put_upgrade_record_download(
            primary_id=primary_id, download_result=1)

        unpack_status = check_obj.unpack()
        if not unpack_status:
            await put_upgrade_record_download(
                primary_id=primary_id, download_result=0)
            return make_json_response(
                result=dict(msg="固件升级失败")
            )

        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(
                request.headers.get("Authorization", ""))
            user = self.__auth_manager.check(valid_auth_token(token))
        else:
            user = _DEFAULT_USERNAME

        check_status = await CheckAutoOperation().check()
        if not check_status:
            await put_upgrade_record_upgrade(
                primary_id=primary_id, upgrade_result=0)
            self._log_table.insert_log(
                username=user, level=10,
                description=f"通过RCC平台的一键升级，验证代操失败或正在执行代操任务，无法进行升级")
            self.username = None
            self.message = None
            self.pack_version = None
            self.pack_depends = None
            self.pack_info = None
            return make_json_response(
                status=400,
                result=dict(
                    msg="验证代操失败或正在执行代操任务，无法进行升级，请稍后重试...")
            )

        self._log_table.insert_log_for_request(
            request=request, level=10,
            description="通过RCC平台的一键升级功能下载最新版本的升级包")

        # 写入信息
        self._upd_info.write(
            version=version,
            username=user,
            tag=1,
            ip=kvm_ip,
            primary_id=primary_id,
        )

        if update_now == UPDATE_NOW_CODE:
            self._log_table.insert_log_for_request(
                request=request, level=10,
                description="通过RCC平台的一键升级功能对版本进行了升级")
            await put_upgrade_record_upgrade(
                primary_id=primary_id, upgrade_result=3)
            self.username = user
            results = self._check_pack()
            self.pack_version = results.get("version")
            self.pack_depends = results.get("depends")
            self.pack_info = results.get("info")
            self.pack_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            schedule_task = threading.Timer(
                self._auto_upgrade_seconds, self.schedule_upgrade)
            schedule_task.start()
        else:
            await put_upgrade_record_upgrade(
                primary_id=primary_id, upgrade_result=5)

        return make_json_response()

    @exposed_http("GET", "/upgrade/readyTo")
    async def ready_to_upgrade(self, request: Request) -> Response:
        """
        触发升级准备
        :param request:
        :return:
        """
        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(
                request.headers.get("Authorization", ""))
            user = self.__auth_manager.check(valid_auth_token(token))
        else:
            user = _DEFAULT_USERNAME

        self.username = user
        results = self._check_pack()
        self.pack_version = results.get("version")
        self.pack_depends = results.get("depends")
        self.pack_info = results.get("info")
        self.pack_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return make_json_response()

    async def get_state(self) -> dict:
        if self.username is not None and self.message is not None:
            # 正在升级中.....
            return {
                "user": self.username,
                "msg": self.message,
                "version": self.pack_version,
                "depends": self.pack_depends,
                "info": self.pack_info,
                "minute": None,
                "status": 1,
                "cancel_status": False
            }
        elif self.username is not None and self.pack_version is not None and \
                self.pack_depends is not None and self.pack_info is not None \
                and self.pack_date is not None:
            cur_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # 准备升级
            minute = self.diff_min_nums(
                start_time=self.pack_date, end_time=cur_date)
            return {
                "user": self.username,
                "msg": self.message,
                "version": self.pack_version,
                "depends": self.pack_depends,
                "info": self.pack_info,
                "minute": minute,
                "status": 2,
                "cancel_status": False
            }
        elif self.username is not None and self.pack_version is None and \
                self.pack_depends is None and self.pack_info is None \
                and self.pack_date is None:
            # 取消升级
            return {
                "user": self.username,
                "msg": self.message,
                "version": self.pack_version,
                "depends": self.pack_depends,
                "info": self.pack_info,
                "minute": None,
                "status": 3,
                "cancel_status": True
            }

    async def poll_state(self) -> AsyncGenerator[dict, None]:
        waiter_task: (asyncio.Task | None) = None
        prev_state: dict = {}
        while True:
            state = await self.get_state()
            if state != prev_state:
                yield state
                prev_state = state

            if waiter_task is None:
                waiter_task = asyncio.create_task(self.__notifier.wait())

            if waiter_task in (
                    await aiotools.wait_first(
                        asyncio.sleep(self.__state_poll), waiter_task))[0]:
                waiter_task = None

    def _clear_pack(self):
        """
        清理软件包解压目录
        :return:
        """
        command = "rm -rf {0}".format(self._tmp_path)
        subprocess.call([command], shell=True, timeout=60)

    def _unpack(self, packname) -> bool:
        """
        对软件包进行解压处理
        :param packname:
        :return:
        """
        # 先进行tar解压，然后到再对RccKVMD.zip进行zip解压
        recode = subprocess.call(
            [self._untar_command.format(packname)], shell=True, timeout=10 * 60)
        if recode != SHELL_RES_CODE:
            return False

        # 解压tar包成功后，清理tar包释放磁盘空间
        recode = subprocess.call(
            ["rm -rf {0}".format(packname)], shell=True, timeout=60)
        if recode != SHELL_RES_CODE:
            return False

        recode = subprocess.call(
            [self._unzip_command], shell=True, timeout=10 * 60)
        if recode != SHELL_RES_CODE:
            return False

        recode = subprocess.call(
            ["rm -rf /home/tmp/RccKVMD.zip"], shell=True, timeout=60)
        if recode != SHELL_RES_CODE:
            return False

        return True

    def _check_pack(self) -> dict:
        """
        对软件包进行校验
        :return:
        """
        if not os.path.exists(self._pack_info):
            raise FileNotFoundError(
                "上传失败，上传的软件包信息文件不存在，无法解析")
        config = configparser.ConfigParser()
        config.read(self._pack_info)
        version = config.get("version", "version")
        depends = config.get("depends", "depends")
        info = config.get("infos", "infos")
        level = config.getint("levels", "levels")
        if os.path.exists(self._app_ver_path):
            with open(self._app_ver_path, "r") as fp:
                cur_version = fp.readline()
            if not cur_version:
                raise UploadError(
                    msg="上传失败，升级依赖版本，{}，版本依赖不符合，无法升级".format(
                        depends),
                    status=400
                )
            cur_ver = re.findall(r".*?KVMD(.+?)Build", cur_version)[0]
            if isinstance(cur_ver, str):
                cur_ver = cur_ver.strip()
            depend_ver_list = depends.split(",")
            if cur_ver not in depend_ver_list:
                raise UploadError(
                    msg="上传失败，升级依赖版本，{}，版本依赖不符合，无法升级".format(
                        depends),
                    status=400
                )

        return dict(
            version=version,
            depends=depends,
            info=info,
            level=level
        )

    @staticmethod
    def _get_version(filepath):
        if not os.path.exists(filepath):
            return "RccKVMD1.0.0 Build20230601"

        with open(filepath, "r") as fp:
            cur_version = fp.readline().strip()

        return cur_version

    def _get_pack_info(self):
        if not os.path.exists(self._pack_info):
            return ""

        config = configparser.ConfigParser()
        config.read(self._pack_info)
        return config.get("version", "version")

    @staticmethod
    def diff_min_nums(start_time, end_time):
        """
        计算两个时间点之间的分钟数
        :param start_time:
        :param end_time:
        :return:
        """
        # 计算分钟数
        start_time1 = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time1 = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        total_seconds = (end_time1 - start_time1).total_seconds()
        # 来获取准确的时间差，并将时间差转换为秒
        return int(5 - int((total_seconds / 60))) if int(
            5 - int((total_seconds / 60))) >= 0 else 0

    def schedule_upgrade(self):
        """
        触发定时五分钟后没有取消升级，执行升级任务
        :return:
        """
        infos = self._upd_info.read()
        if infos["is_cancel"]:
            get_logger(0).warning("升级取消，本次无需执行升级")
            self._upd_info.remove()
            return

        subprocess.Popen(
            "bash {0}".format(self._upgrade_script), shell=True)
