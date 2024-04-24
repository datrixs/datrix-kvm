# =====
from aiohttp.web import Request
from aiohttp.web import Response

from kvmd.apps.kvmd.control import ControlManager
from kvmd.htserver import exposed_http, make_json_response, make_json_exception


class ControlApi:
    def __init__(self, control_manager: ControlManager) -> None:
        self.control_manager = control_manager

    @exposed_http("GET", "/control/l_or_r", auth_required=False)
    async def l_or_r(self, _: Request) -> Response:

        """
        获取l or r状态
        :return: str L or R
        """
        l_or_r_value = self.control_manager.get_l_or_r_value()
        return make_json_response(result=dict(l_or_r_value=l_or_r_value))

    @exposed_http("POST", "/control/local_permission", auth_required=False)
    async def set_local_permission(self, request: Request) -> Response:

        """
        设置本地操作权限
        :param bool enable
        :return
        """

        params = await request.post()
        enable = params.get("enable", True)

        try:
            self.control_manager.set_local_permission(enable)
        except Exception as e:
            return make_json_exception(e, 500)
        return make_json_response()

    @exposed_http("GET", "/control/local_permission", auth_required=False)
    async def local_permission(self, _: Request) -> Response:
        """
        获取本地操作权限
        :return: bool ture（可控制） or false（不可控制）
        """
        local_permission = self.control_manager.local_permission
        return make_json_response(result=dict(local_permission=local_permission))

    @exposed_http("GET", "/control/remote_permission", auth_required=False)
    async def remote_permission(self, _: Request) -> Response:
        """
        获取远程控制状态
        :return: bool ture（可控制） or false（不可控制）
        """
        remote_permission = self.control_manager.get_remote_permission()
        return make_json_response(result=dict(remote_permission=remote_permission))
