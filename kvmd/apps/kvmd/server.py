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


import asyncio
import dataclasses
import operator
import time
import datetime
from typing import Any
from typing import AsyncGenerator
from typing import Callable
from typing import Coroutine
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from aiohttp.web import Request
from aiohttp.web import Response
from aiohttp.web import WebSocketResponse

from .api.atx import AtxApi
from .api.auth import AuthApi, check_request_auth
from .api.export import ExportApi
from .api.hardware import KVMHardWareInfoAPI, SystemSettingName
from .api.hid import HidApi
from .api.info import InfoApi
from .api.log import LogApi
from .api.logs import LogsApi
from .api.msd import MsdApi
from .api.permission import PermissionsApi
from .api.rcc import RCCApi
from .api.redfish import RedfishApi
from .api.role import RolesApi
from .api.rpc import RPCServerApi
from .api.streamer import StreamerApi
from .api.ugpio import UserGpioApi
from .api.upgrade import UpgradeApi
from .api.user import UsersApi
from .auth import AuthManager
from .info import InfoManager
from .logreader import LogReader
from .snapshoter import Snapshoter
from .streamer import Streamer
from .table import LogTable, UserTable, SystemSettingTable, LoginFailMsgTable
from .tesseract import TesseractOcr
from .ugpio import UserGpio
from .. import init
from ... import aioproc
from ... import aiotools
from ..utils.system import get_settings, reset_settings
from ...errors import OperationError
from ...htserver import HttpError, RequestMsgControl, start_operate
from ...htserver import HttpExposed
from ...htserver import HttpServer
from ...htserver import WsSession
from ...htserver import exposed_http
from ...htserver import exposed_ws
from ...htserver import make_json_response
from ...logging import get_logger
from ...plugins import BasePlugin
from ...plugins.atx import BaseAtx
from ...plugins.hid import BaseHid
from ...plugins.msd import BaseMsd
from ...validators.auth import valid_auth_token
from ...validators.basic import valid_bool
from ...validators.kvm import valid_stream_fps
from ...validators.kvm import valid_stream_h264_bitrate
from ...validators.kvm import valid_stream_h264_gop
from ...validators.kvm import valid_stream_quality
from ...validators.kvm import valid_stream_resolution


def calculate_time(time_string: str, timeout_value: int):
    """计算时间差值，时间格式必须是 YYYY-mm-dd HH:MM:SS"""
    time_before = datetime.datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S")
    time_temp = time_before + datetime.timedelta(minutes=timeout_value)
    time_after = time_temp.strftime("%Y-%m-%d %H:%M:%S")
    return time_after


def get_system_settings(system_setting_table: SystemSettingTable):
    safety_setting = system_setting_table.get_setting_content(system_name="safety")
    users_mode = safety_setting.get("users_mode", dict()).get("users_mode", 1)
    operating_mode = safety_setting.get("operating_mode", list())
    if 2 not in operating_mode:
        RequestMsgControl.USERS_MODE = 1
    else:
        users_mode = int(users_mode)
        RequestMsgControl.USERS_MODE = users_mode


def get_button_permission():
    button_permission = True
    if RequestMsgControl.USERS_MODE == 4:
        button_permission = False
    result = {}
    button_list = ["text", "macro", "camera", "stream", "control", "power"]
    for name in button_list:
        result[name] = button_permission
    return result


# =====
class StreamerQualityNotSupported(OperationError):
    def __init__(self) -> None:
        super().__init__("This streamer does not support quality settings")


class StreamerResolutionNotSupported(OperationError):
    def __init__(self) -> None:
        super().__init__("This streamer does not support resolution settings")


class StreamerH264NotSupported(OperationError):
    def __init__(self) -> None:
        super().__init__("This streamer does not support H264")


# =====
@dataclasses.dataclass(frozen=True)
class _Component:  # pylint: disable=too-many-instance-attributes
    name: str
    event_type: str
    obj: object
    sysprep: Optional[Callable[[], None]] = None
    systask: Optional[Callable[[], Coroutine[Any, Any, None]]] = None
    get_state: Optional[Callable[[], Coroutine[Any, Any, Dict]]] = None
    poll_state: Optional[Callable[[], AsyncGenerator[Dict, None]]] = None
    cleanup: Optional[Callable[[], Coroutine[Any, Any, Dict]]] = None

    def __post_init__(self) -> None:
        if isinstance(self.obj, BasePlugin):
            object.__setattr__(self, "name",
                               f"{self.name} ({self.obj.get_plugin_name()})")

        for field in ["sysprep", "systask", "get_state", "poll_state",
                      "cleanup"]:
            object.__setattr__(self, field, getattr(self.obj, field, None))
        if self.get_state or self.poll_state:
            assert self.event_type, self


class KvmdServer(HttpServer):  # pylint: disable=too-many-arguments,too-many-instance-attributes
    def __init__(  # pylint: disable=too-many-arguments,too-many-locals
            self,
            auth_manager: AuthManager,
            info_manager: InfoManager,
            log_reader: (LogReader | None),
            user_gpio: UserGpio,
            ocr: TesseractOcr,

            hid: BaseHid,
            atx: BaseAtx,
            msd: BaseMsd,
            streamer: Streamer,
            snapshoter: Snapshoter,

            keymap_path: str,
            ignore_keys: List[str],
            mouse_x_range: Tuple[int, int],
            mouse_y_range: Tuple[int, int],
            stream_cmd: List[str],
            stream_forever: bool,
    ) -> None:

        super().__init__()
        rcc_setting: dict = get_settings()
        reset_settings(data=rcc_setting)
        self.__auth_manager = auth_manager
        self.__hid = hid
        self.__streamer = streamer
        self.__snapshoter = snapshoter  # Not a component: No state or cleanup
        self.__user_gpio = user_gpio  # Has extra state "gpio_scheme_state"

        self.__stream_forever = stream_forever

        # get config
        _, _, config = init(
            add_help=False,
            cli_logging=False,
            argv=[],
            load_auth=True,
        )

        self.__user_table = UserTable(config.kvmd.sqlite.path)
        self.__system_setting_table = SystemSettingTable(
            config.kvmd.sqlite.path)
        self.__login_fail_msg_table = LoginFailMsgTable(config.kvmd.sqlite.path)
        self.__log_table = LogTable(config.kvmd.sqlite.path)
        self.__upgrade_api = UpgradeApi(self.__log_table, self.__auth_manager)
        self.__hid_api = HidApi(hid, keymap_path, ignore_keys, mouse_x_range,
                                mouse_y_range)  # Ugly hack to get keymaps state
        self.__streamer_api = StreamerApi(streamer, ocr,
                                          self.__log_table)  # Same hack to get ocr langs state
        self.__rpc_api = RPCServerApi(
            hid, ignore_keys, mouse_x_range, mouse_y_range)

        self.__user_api = UsersApi(config, self.__log_table)
        self.__role_api = RolesApi(config, self.__log_table)
        self.__permission_api = PermissionsApi(config)
        self.__logs_api = LogsApi(config)
        self.__hardware_info_api = KVMHardWareInfoAPI(
            self.__system_setting_table, self.__log_table, self.__login_fail_msg_table, auth_manager
        )
        self.__auth_api = AuthApi(
            auth_manager, self.__log_table, self.__system_setting_table,
            self.__login_fail_msg_table,
            self.__user_table
        )

        self.__rcc_api = RCCApi()

        self.__apis: List[object] = [
            self,
            self.__auth_api,
            InfoApi(info_manager),
            LogApi(log_reader),
            UserGpioApi(user_gpio),
            self.__hid_api,
            AtxApi(atx),
            MsdApi(msd),
            self.__streamer_api,
            ExportApi(info_manager, atx, user_gpio),
            RedfishApi(info_manager, atx),
            self.__rpc_api,
            self.__user_api,
            self.__role_api,
            self.__permission_api,
            self.__logs_api,
            self.__hardware_info_api,
            self.__upgrade_api,
            self.__rcc_api
        ]

        self.__streamer_notifier = aiotools.AioNotifier()
        self.__reset_streamer = False
        self.__new_streamer_params: Dict = {}
        self.__components = [
            *[
                _Component("Auth manager", "", auth_manager),
            ],
            *[
                _Component(f"Info manager ({sub})", f"info_{sub}_state",
                           info_manager.get_submanager(sub))
                for sub in sorted(info_manager.get_subs())
            ],
            *[
                _Component("User-GPIO", "gpio_state", user_gpio),
                _Component("HID", "hid_state", hid),
                _Component("ATX", "atx_state", atx),
                _Component("MSD", "msd_state", msd),
                _Component("Streamer", "streamer_state", streamer),
            ],
            *[
                _Component("Upgrade", "upgrade_state", self.__upgrade_api)
            ]
        ]
        get_system_settings(system_setting_table=self.__system_setting_table)

    # ===== STREAMER CONTROLLER

    @exposed_http("POST", "/streamer/set_params")
    async def __streamer_set_params_handler(self, request: Request) -> Response:
        current_params = self.__streamer.get_params()
        for (name, validator, exc_cls) in [
            ("quality", valid_stream_quality, StreamerQualityNotSupported),
            ("desired_fps", valid_stream_fps, None),
            ("resolution", valid_stream_resolution,
             StreamerResolutionNotSupported),
            ("h264_bitrate", valid_stream_h264_bitrate,
             StreamerH264NotSupported),
            ("h264_gop", valid_stream_h264_gop, StreamerH264NotSupported),
        ]:
            value = request.query.get(name)
            if value:
                if name not in current_params:
                    assert exc_cls is not None, name
                    raise exc_cls()
                value = validator(value)  # type: ignore
                if current_params[name] != value:
                    self.__new_streamer_params[name] = value
        self.__streamer_notifier.notify()
        return make_json_response()

    @exposed_http("POST", "/streamer/reset")
    async def __streamer_reset_handler(self, _: Request) -> Response:
        self.__reset_streamer = True
        self.__streamer_notifier.notify()
        return make_json_response()

    # ===== WEBSOCKET

    @exposed_http("GET", "/ws")
    async def __ws_handler(self, request: Request) -> WebSocketResponse:
        stream = valid_bool(request.query.get("stream", True))
        equipment_id = request.query.get("equipment_id", None)
        operator_id = request.query.get("operate_id", None)
        is_control = request.query.get("is_control", False)
        token = valid_auth_token(request.query.get("auth_token", None))
        user = self.__auth_manager.check(valid_auth_token(token))
        remote = request.headers.get("X-Real-IP", "")

        # 创建rcc远程操作记录
        operate_id = None
        if equipment_id and operator_id:
            operate_id = await start_operate(
                filepath="/usr/share/kvmd/web/share/js/setting.js", 
                key="rcc_base_url",
                equipment_id=equipment_id,
                operator_id=operator_id,
            )

        if is_control:
            self.__log_table.insert_log(
                username=user,
                level=5,
                description=f"用户:[{user}] IP地址:[{remote}] [开始进行远程控制]"
            )
        async with self._ws_session(
            request, stream=stream, operate_id=operate_id,
            token=token, is_control=is_control, remote=remote,
            last_time=int(time.time())
        ) as ws:
            stage1 = [
                ("gpio_model_state", self.__user_gpio.get_model()),
                ("hid_keymaps_state", self.__hid_api.get_keymaps()),
                ("streamer_ocr_state", self.__streamer_api.get_ocr()),
            ]
            stage2 = [
                (comp.event_type, comp.get_state())
                for comp in self.__components
                if comp.get_state
            ]
            stages = stage1 + stage2
            events = dict(zip(
                map(operator.itemgetter(0), stages),
                await asyncio.gather(*map(operator.itemgetter(1), stages)),
            ))
            for stage in [stage1, stage2]:
                await asyncio.gather(*[
                    ws.send_event(event_type, events.pop(event_type))
                    for (event_type, _) in stage
                ])
            if is_control and (RequestMsgControl.USERS_MODE == 4):
                await ws.send_event(
                    "button_permission",
                    get_button_permission()
                )
            await ws.send_event("loop", {})
            return await self._ws_loop(ws)

    @exposed_ws("ping")
    async def __ws_ping_handler(self, ws: WsSession, _: Dict) -> None:
        await ws.send_event("pong", {"ws": str(ws)})
        token = ws.kwargs.get("token")
        user = self.__auth_manager.check(valid_auth_token(token))
        if token not in self.__auth_manager.get_tokens():
            await ws.send_event("exit_kvm", {})
            await self._ws_loop(ws)
        if ws.kwargs.get("is_control"):
            ws.kwargs["last_time"] = int(time.time())
            if self.__hardware_info_api.send_button_permission:
                await ws.send_event(
                    "button_permission",
                    get_button_permission()
                )
                self.__hardware_info_api.send_button_permission = False
            # 更新登录信息
            self.__user_table.update_login_status(username=user, is_login=True)
            return
        time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        safety_settings = self.__system_setting_table.get_setting_content(
            system_name=SystemSettingName.SAFETY_SETTING
        )
        setting_timeout = int(safety_settings.get("login_fail", {}).get("timeout", 0))

        user_msg = self.__user_table.get_user_by_name(username=user)
        last_login = user_msg.get("last_login", "")
        if not last_login:
            await ws.send_event("exit_kvm", {})
            await self._ws_loop(ws)
        calculate_result = calculate_time(last_login, setting_timeout)
        if calculate_result < time_now or (int(time.time()) - ws.kwargs.get("last_time", 0) > 10):
            await ws.send_event("exit_kvm", {})
            await self._ws_loop(ws)
            ws_ip = ws.kwargs.get("remote", "-")
            self.__log_table.insert_log(
                username=user,
                level=5,
                description=f"用户:[{user}] IP地址:[{ws_ip}] [超时自动登出系统]"
            )
        ws.kwargs["last_time"] = int(time.time())

    @exposed_http("POST", "/streamer/lock")
    async def __streamer_lock_handler(self, request: Request) -> Response:
        data = await request.json()
        event = data.get("lock", False)
        await self._broadcast_ws_event(
            event_type="lock_kvm",
            event=event
        )
        return make_json_response()

    @exposed_http("POST", "/streamer/exit")
    async def __streamer_exit_handler(self, request: Request) -> Response:
        data = await request.json()
        event = data.get("exit", False)
        await self._broadcast_rcc_ws_event(
            event_type="exit_kvm",
            event=event
        )
        return make_json_response()

    # ===== SYSTEM STUFF

    def run(self,
            **kwargs: Any) -> None:  # type: ignore  # pylint: disable=arguments-differ
        for comp in self.__components:
            if comp.sysprep:
                comp.sysprep()
        aioproc.rename_process("main")
        super().run(**kwargs)

    async def _check_request_auth(self, exposed: HttpExposed,
                                  request: Request) -> None:
        remote = request.headers.get("X-Real-IP", "")
        request_path = request.path
        if request_path in self.__auth_api.unauthorized_path:
            return
        user, token = await check_request_auth(self.__auth_manager, exposed, request)
        if not user:
            raise HttpError("用户不存在", 401)
        user_msg = self.__user_table.get_user_by_name(username=user)
        if not user_msg:
            raise HttpError("用户不存在", 401)
        safety_settings = self.__system_setting_table.get_setting_content(
            system_name=SystemSettingName.SAFETY_SETTING)
        setting_timeout = int(safety_settings.get("login_fail", {}).get("timeout", 0))
        last_login = user_msg.get("last_login", "")
        if not setting_timeout or not last_login:
            return
        time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ws_session = {}
        if token:
            for ws_client in self._get_wss():
                if ws_client.kwargs.get("token") != token:
                    continue
                else:
                    ws_session["ws"] = ws_client
                    if ws_client.kwargs.get("is_control"):
                        ws_session["is_control"] = True
                    break
        calculate_result = calculate_time(last_login, setting_timeout)
        if ws_session.get("is_control", False):
            pass
        elif not ws_session.get("is_control", False) and calculate_result < time_now:
            self.__auth_manager.logout(token)
            if ws_session:
                await ws_session["ws"].send_event("exit_kvm", {})
                await self._ws_loop(ws_session["ws"])
            self.__log_table.insert_log(
                username=user,
                level=5,
                description=f"用户:[{user}] IP地址:[{remote}] [超时登出系统]"
            )
            raise HttpError("Token失效，请重新登录", 401)
        # 如果验证结果，没有超时，重新刷新操作记录
        self.__user_table.update_login_status(username=user, is_login=True)

    async def _init_app(self) -> None:
        aiotools.create_deadly_task("Stream controller",
                                    self.__stream_controller())
        for comp in self.__components:
            if comp.systask:
                aiotools.create_deadly_task(comp.name, comp.systask())
            if comp.poll_state:
                aiotools.create_deadly_task(f"{comp.name} [poller]",
                                            self.__poll_state(comp.event_type,
                                                              comp.poll_state()))
        aiotools.create_deadly_task("Stream snapshoter",
                                    self.__stream_snapshoter())
        self._add_exposed(*self.__apis)

    async def _on_shutdown(self) -> None:
        logger = get_logger(0)
        logger.info("Waiting short tasks ...")
        await aiotools.wait_all_short_tasks()
        logger.info("Stopping system tasks ...")
        await aiotools.stop_all_deadly_tasks()
        logger.info("Disconnecting clients ...")
        await self._close_all_wss()
        logger.info("On-Shutdown complete")

    async def _on_cleanup(self) -> None:
        logger = get_logger(0)
        for comp in self.__components:
            if comp.cleanup:
                logger.info("Cleaning up %s ...", comp.name)
                try:
                    await comp.cleanup()  # type: ignore
                except Exception:
                    logger.exception("Cleanup error on %s", comp.name)
        logger.info("On-Cleanup complete")

    async def _on_ws_opened(self) -> None:
        self.__streamer_notifier.notify()

    async def _on_ws_closed(self) -> None:
        self.__hid.clear_events()
        self.__streamer_notifier.notify()

    def __has_stream_clients(self) -> bool:
        return bool(sum(map(
            (lambda ws: ws.kwargs["stream"]),
            self._get_wss(),
        )))

    # ===== SYSTEM TASKS

    async def __stream_controller(self) -> None:
        prev = False
        while True:
            cur = (
                    self.__has_stream_clients() or self.__snapshoter.snapshoting() or self.__stream_forever)
            if not prev and cur:
                await self.__streamer.ensure_start(reset=False)
            elif prev and not cur:
                await self.__streamer.ensure_stop(immediately=False)

            if self.__reset_streamer or self.__new_streamer_params:
                start = self.__streamer.is_working()
                await self.__streamer.ensure_stop(immediately=True)
                if self.__new_streamer_params:
                    self.__streamer.set_params(self.__new_streamer_params)
                    self.__new_streamer_params = {}
                if start:
                    await self.__streamer.ensure_start(
                        reset=self.__reset_streamer)
                self.__reset_streamer = False

            prev = cur
            await self.__streamer_notifier.wait()

    async def __poll_state(self, event_type: str,
                           poller: AsyncGenerator[Dict, None]) -> None:
        async for state in poller:
            await self._broadcast_ws_event(event_type, state)

    async def __stream_snapshoter(self) -> None:
        await self.__snapshoter.run(
            is_live=self.__has_stream_clients,
            notifier=self.__streamer_notifier,
        )
