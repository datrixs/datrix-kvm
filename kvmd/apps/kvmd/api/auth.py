# ========================================================================== #
#                                                                            #
#    KVMD - The main PiKVM daemon.                                           #
#                                                                            #
#    Copyright (C) 2018-2022  Maxim Devaev <mdevaev@gmail.com>               #
#                                                                            #
#    This program is free software: you can redistribute it and/or modify    #
#    it under the terms of the GNU General Public License as published by    #
#    the Free Software Foundation, either version 3 of the License, or       #
#    (at your option) any later version.                                     #
#                                                                            #
#    This program is distributed in the hope that it will be useful,         #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#    GNU General Public License for more details.                            #
#                                                                            #
#    You should have received a copy of the GNU General Public License       #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                            #
# ========================================================================== #


import base64
import json
import os
import platform
import re
from typing import Tuple
from aiohttp.web import Request
from aiohttp.web import Response

from ..auth import AuthManager
from ..table import UserTable, LogTable, SystemSettingTable, LoginFailMsgTable
from ....logging import get_logger
from ....htserver import ForbiddenError, HttpError
from ....htserver import HttpExposed
from ....htserver import UnauthorizedError
from ....htserver import exposed_http
from ....htserver import make_json_response
from ....htserver import set_request_auth_info, RequestMsgControl
from ....validators.auth import valid_auth_token
from ....validators.auth import valid_passwd
from ....validators.auth import valid_user

# =====
_COOKIE_AUTH_TOKEN = "auth_token"
_LOCAL_HOSTS = ["localhost", "127.0.0.1"]


class IP2MAC:
    """
    Python3根据IP地址获取MAC地址（不能获取本机IP，可以获取与本机同局域网设备IP的MAC）
    """

    def __init__(self):
        self.logger = get_logger()
        self.patt_mac = re.compile('([a-f0-9]{2}[-:]){5}[a-f0-9]{2}', re.I)

    def get_mac(self, ip):
        sys_name = platform.system()
        if sys_name == 'Windows':
            macaddr = self.__for_win(ip)
        elif sys_name == 'Linux':
            macaddr = self.__for_linux(ip)
        else:
            macaddr = None
        return macaddr or '00-00-00-00-00-00'

    def __for_win(self, ip):
        try:
            os.popen('ping -n 1 -w 500 {} > nul'.format(ip))
            macaddr = self.__get_remote_mac(ip)
        except Exception as e:
            self.logger.warning(f"get mac for win fail: {e.__str__()}")
            macaddr = None
        return macaddr

    def __for_linux(self, ip):
        try:
            os.popen('ping -nq -c 1 -W 500 {} > /dev/null'.format(ip))
            macaddr = self.__get_remote_mac(ip)
        except Exception as e:
            self.logger.warning(f"get mac for linux fail: {e.__str__()}")
            macaddr = None
        return macaddr

    def __get_remote_mac(self, ip):
        result = os.popen('arp -an {}'.format(ip))
        result = self.patt_mac.search(result.read())
        if result:
            macaddr = result.group()
        else:
            macaddr = None
        return macaddr


async def check_request_auth(
    auth_manager: AuthManager, exposed: HttpExposed, request: Request) -> Tuple[str, str]:
    if request.host in _LOCAL_HOSTS:
        return None
    if exposed.auth_required and auth_manager.is_auth_enabled():
        user = request.headers.get("X-KVMD-User", "")
        if user:
            user = valid_user(user)
            passwd = request.headers.get("X-KVMD-Passwd", "")
            set_request_auth_info(request, f"{user} (xhdr)")
            if not (await auth_manager.authorize(user, valid_passwd(passwd))):
                raise ForbiddenError()
            return user, ""

        token = request.headers.get("Authorization", "")
        if token:
            user = auth_manager.check(valid_auth_token(token))  # type: ignore
            if not user:
                set_request_auth_info(request, "- (token)")
                raise ForbiddenError()
            set_request_auth_info(request, f"{user} (token)")
            return user, token

        query_token = request.query.get("auth_token", "")
        if query_token:
            user = auth_manager.check(valid_auth_token(query_token))  # type: ignore
            if not user:
                set_request_auth_info(request, "- (query_token)")
                raise ForbiddenError()
            set_request_auth_info(request, f"{user} (query_token)")
            return user, query_token

        # basic_auth = request.headers.get("Authorization", "")
        # if basic_auth and basic_auth[:6].lower() == "basic ":
        #     try:
        #         (user, passwd) = base64.b64decode(basic_auth[6:]).decode(
        #             "utf-8").split(":")
        #     except Exception:
        #         raise UnauthorizedError()
        #     user = valid_user(user)
        #     set_request_auth_info(request, f"{user} (basic)")
        #     if not (await auth_manager.authorize(user, valid_passwd(passwd))):
        #         raise ForbiddenError()
        #     return user

        raise UnauthorizedError()


class AuthApi:
    def __init__(
        self, auth_manager: AuthManager,
        log_table: LogTable, system_setting_table: SystemSettingTable, login_fail_msg_table: LoginFailMsgTable,
        user_table: UserTable
    ) -> None:
        self.__auth_manager = auth_manager
        self.__user_table = user_table
        self.__log_table = log_table
        self.__system_setting_table = system_setting_table
        self.__login_fail_msg_table = login_fail_msg_table
        self.__ip2mac = IP2MAC()
        self.unauthorized_path = [
            "/auth/login", "/auth/logout"
        ]

    # =====

    async def get_login_fail_msg(self, username: str = "", user_addr: str = "") -> tuple[dict, int, bool]:
        if user_addr:
            lock_msg = self.__login_fail_msg_table.get_client_login_fail_msg(user_addr=user_addr)
            description = f"用户:[{username}] [登入系统失败：客户端被锁定]"
        else:
            lock_msg = self.__login_fail_msg_table.get_account_login_fail_msg(username=username)
            description = f"用户:[{username}] [登入系统失败：账号被锁定]"
        exists = True if lock_msg else False
        table_id = lock_msg.get("id", 0)
        lock_status = lock_msg.get("lock_status", False)

        if lock_status:
            self.__log_table.insert_log(
                username=username,
                level=5,
                description=description
            )
            format_str = "客户端" if user_addr else "账号"
            raise HttpError(f"该{format_str}已锁定", 400)
        return lock_msg, table_id, exists

    async def check_account(self, username: str):
        """
        验证是否锁定用户账号
        """
        return await self.get_login_fail_msg(username=username)

    async def check_client(self, user_addr: str):
        """
        验证是否锁定客户端
        """
        return await self.get_login_fail_msg(user_addr=user_addr)

    async def filter_user_request(
        self, filter_flag: bool, filter_include: bool, data: str, filters: list,
        user: str, is_ip: bool
    ):
        format_str = "IP" if is_ip else "MAC"
        filter_res = False
        if filter_flag:
            if filter_include and (data not in filters):
                filter_res = True
            elif not filter_include and (data in filters):
                filter_res = True

        if filter_res:
            self.__log_table.insert_log(
                username=user,
                level=5,
                description=f"用户:[{user}] {format_str}地址:[{data}] [登入系统失败：该电脑{format_str}限制登录]"
            )
            raise HttpError(f"该电脑{format_str}限制登录", 400)

    async def check_ip_or_mac(
        self, safety_setting: dict, user: str, request_ip: str, request_mac: str
    ):
        """
        验证是否过滤ip或者mac
        """
        client_filter = safety_setting.get("filter", {})
        filter_ip = client_filter.get("filter_ip", False)
        ip_include = client_filter.get("ip_include", False)
        ips = client_filter.get("ips", [])
        await self.filter_user_request(
            filter_flag=filter_ip, filter_include=ip_include,
            data=request_ip, filters=ips, user=user, is_ip=True
        )

        filter_mac = client_filter.get("filter_mac", False)
        mac_include = client_filter.get("mac_include", False)
        macs = client_filter.get("macs", [])
        macs_lower = [x.lower() for x in macs]
        await self.filter_user_request(
            filter_flag=filter_mac, filter_include=mac_include,
            data=request_mac, filters=macs_lower, user=user, is_ip=False
        )

    async def __check_users_mode(
        self, user: str, remote: str, users_mode: int
    ):
        """
        验证多用户模式
        多用户模式：
            1->共享：支持多人远程
            2->排他：只支持同时一人操作，后者登录，前者将被迫下线
            3->独占：只支持同时一人操作，一人操作时，其他用户无法远程
            4->待机模式：无法远程，只能监控，0711update：可以登录，只是不能操作远程界面
        """
        if users_mode == 3:
            user_login = False
            for login_token, login_user in self.__auth_manager.get_tokens().items():
                if user in login_user:
                    user_login = True
                    break
            if user_login:
                self.__log_table.insert_log(
                    username=user,
                    level=5,
                    description=f"用户:[{user}] IP地址:[{remote}] [登入系统失败：当前为独占模式]"
                )
                raise HttpError(f"当前为独占模式，无法同时登录", 400)
        elif users_mode == 2:
            need_logout_token = []
            for login_token, login_user in self.__auth_manager.get_tokens().items():
                if login_user == user:
                    continue
                need_logout_token.append(login_token)
                self.__log_table.insert_log(
                    username=login_user,
                    level=5,
                    description=f"用户:[{login_user}] [排他模式，被迫登出]"
                )
            for token in need_logout_token:
                if token in self.__auth_manager.get_tokens():
                    self.__auth_manager.logout(token)

    async def __update_login_fail_msg(
        self,
        lock_msg: dict, recycle: int, exists: bool,
        table_id: int, username: str, remote: str, mac: str,
        safety_setting: dict, lock_type: int = 1
    ):
        """
        更新登录失败信息
        lock_type: 1 -> 账号；2 -> 客户端PC
        """
        login_fail_count = int(lock_msg.get("login_fail_count", 0))
        login_fail_count = login_fail_count + 1
        if login_fail_count >= recycle:
            lock_status = 1
        else:
            lock_status = 0
        if exists:
            self.__login_fail_msg_table.update_login_fail_msg(
                msg_id=table_id,
                login_fail_count=login_fail_count,
                lock_status=lock_status,
                is_delete=0
            )
        else:
            if lock_type == 1:
                self.__login_fail_msg_table.insert_login_fail_msg(
                    username=username,
                    user_addr="",
                    login_fail_count=login_fail_count,
                    lock_status=lock_status,
                    is_delete=0
                )
            elif lock_type == 2:
                self.__login_fail_msg_table.insert_login_fail_msg(
                    username="",
                    user_addr=mac,
                    login_fail_count=login_fail_count,
                    lock_status=lock_status,
                    is_delete=0
                )
        if lock_type == 2 and lock_status:
            filter_remote = safety_setting.get("filter", {})
            mac_include = filter_remote.get("mac_include", False)
            macs = filter_remote.get("macs", [])
            filter_remote["filter_mac"] = True
            if not mac_include and (mac not in macs):
                macs.append(mac)
            elif mac_include and (mac in macs):
                macs.remove(mac)
            filter_remote["macs"] = macs
            safety_setting["filter"] = filter_remote
            self.__system_setting_table.update_system_setting(
                system_name="safety",
                content=json.dumps(safety_setting, ensure_ascii=False)
            )
        self.__log_table.insert_log(
            username=username,
            level=5,
            description=f"用户:[{username}] IP地址:[{remote}] MAC:[{mac}] [登入系统失败：账号或密码错误]"
        )

    @exposed_http("POST", "/auth/login", auth_required=False)
    async def __login_handler(self, request: Request) -> Response:
        """
            共享：支持多人远程
            排他：只支持同时一人操作，后者登录，前者将被迫下线
            独占：只支持同时一人操作，一人操作时，其他用户无法远程
            待机模式：无法远程，只能监控
        """

        if self.__auth_manager.is_auth_enabled():
            remote = request.headers.get("X-Real-IP", "")
            request_mac = self.__ip2mac.get_mac(ip=remote)
            request_mac = request_mac.lower()
            credentials = await request.post()
            user = credentials.get("user", "")
            safety_setting = self.__system_setting_table.get_setting_content(system_name="safety")

            # 工作模式
            operating_mode = safety_setting.get("operating_mode", [])
            operating_mode = [int(x) for x in operating_mode]

            login_fail = safety_setting.get("login_fail", {})
            login_fail_open = login_fail.get("open", False)
            lock_client = login_fail.get("lock_client", False)
            lock_account = login_fail.get("lock_account", False)

            # 验证权限-账号是否被锁定，能走过这里说明没有被锁定拦截
            lock_account_msg, account_table_id, account_exists = await self.check_account(
                username=user
            ) if lock_account else ({}, 0, False)

            # 验证权限-客户端是否被锁定，能走过这里说明没有被锁定拦截
            lock_client_msg, client_table_id, client_exists = await self.check_client(
                user_addr=request_mac
            ) if lock_client else ({}, 0, False)

            # 验证权限-IP或者MAC，能走过这里说明没有被拦截
            await self.check_ip_or_mac(
                safety_setting=safety_setting,
                user=user,
                request_ip=remote,
                request_mac=request_mac
            )

            users_mode = safety_setting.get("users_mode", dict()).get("users_mode", 1)
            users_mode = int(users_mode)

            if 2 in operating_mode and users_mode in [3, 4]:
                await self.__check_users_mode(
                    user=user, remote=remote, users_mode=users_mode
                )

            token = await self.__auth_manager.login(
                user=valid_user(user),
                passwd=valid_passwd(credentials.get("passwd", "")),
            )
            if token:
                self.__log_table.insert_log(
                    username=user,
                    level=5,
                    description=f"用户:[{user}] IP地址:[{remote}] [登入系统]"
                )

                # 当多用户模式允许登录的时候，处理其他用户的登录
                if 2 in operating_mode:
                    await self.__check_users_mode(
                        user=user, remote=remote, users_mode=users_mode
                    )

                # 更新登录信息
                self.__user_table.update_login_status(username=user, is_login=True)
                if user == "admin":
                    return make_json_response(set_cookies={_COOKIE_AUTH_TOKEN: token})

                # 刷新账号锁定信息
                if not account_exists:
                    self.__login_fail_msg_table.insert_login_fail_msg(
                        username=user, user_addr="", login_fail_count=0, lock_status=0, is_delete=1
                    )
                elif account_table_id:
                    self.__login_fail_msg_table.update_login_fail_msg(
                        msg_id=account_table_id, login_fail_count=0, lock_status=0, is_delete=1
                    )

                # 刷新客户端锁定信息
                if not client_exists:
                    self.__login_fail_msg_table.insert_login_fail_msg(
                        username="", user_addr=request_mac, login_fail_count=0, lock_status=0, is_delete=1
                    )
                elif client_table_id:
                    self.__login_fail_msg_table.update_login_fail_msg(
                        msg_id=client_table_id, login_fail_count=0, lock_status=0, is_delete=1
                    )

                return make_json_response(
                    result=self.__user_table.get_user(
                        key="username",
                        value=user,
                    ),
                    set_cookies={_COOKIE_AUTH_TOKEN: token}
                )

            # 如果是超级管理员，不进行限制
            if not login_fail_open or user == "admin":
                raise HttpError("登入系统失败：账号或密码错误", 400)
            recycle = int(login_fail.get("recycle", 0))

            # 锁定账号的情况
            if lock_account:
                await self.__update_login_fail_msg(
                    lock_msg=lock_account_msg, recycle=recycle, exists=account_exists,
                    table_id=account_table_id, username=user, remote=remote, mac=request_mac,
                    safety_setting={}, lock_type=1
                )

            # 锁定客户端PC的情况
            if lock_client:
                await self.__update_login_fail_msg(
                    lock_msg=lock_client_msg, recycle=recycle, exists=client_exists,
                    table_id=client_table_id, username=user, remote=remote, mac=request_mac,
                    safety_setting=safety_setting, lock_type=2
                )
            raise HttpError("登入系统失败：账号或密码错误", 400)
        return make_json_response()

    @exposed_http("POST", "/auth/logout")
    async def __logout_handler(self, request: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(
                request.headers.get("Authorization", ""))
            user = self.__auth_manager.check(token)
            if not user:
                return make_json_response()
            remote = request.headers.get("X-Real-IP", "")
            logout_flag = True
            for ws in RequestMsgControl.WS_CLIENT:
                ws_token = ws.kwargs.get("token", "")
                ws_user = self.__auth_manager.check(ws_token)
                if (token != ws_token) and (ws_user == user):
                    logout_flag = False
                    break
            if logout_flag:
                self.__user_table.update_login_status(username=user, is_login=False)
            self.__log_table.insert_log(
                username=user,
                level=5,
                description=f"用户:[{user}] IP地址:[{remote}] [退出登录]"
            )
            self.__auth_manager.logout(token)
        return make_json_response()

    @exposed_http("GET", "/auth/check")
    async def __check_handler(self, _: Request) -> Response:
        return make_json_response()

    @exposed_http("GET", "/auth/userinfo")
    async def __userinfo_handler(self, request: Request) -> Response:
        if self.__auth_manager.is_auth_enabled():
            token = valid_auth_token(
                request.headers.get("Authorization", ""))
            user = self.__auth_manager.check(token)
            return make_json_response(
                self.__user_table.get_user(
                    key="username",
                    value=user
                )
            )
        return make_json_response()
