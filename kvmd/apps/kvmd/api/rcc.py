from aiohttp.web import Request
from aiohttp.web import Response

from ...utils.system import get_system_version, get_settings, reset_settings
from ....htserver import HttpError, exposed_http, make_json_response
from ....logging import get_logger


class RCCApi:
    def __init__(self):
        self.logger = get_logger()

    @exposed_http("POST", "/rcc/conf")
    async def write_rcc_conf(self, request: Request) -> Response:
        """
        配置RCC的配置项

        file content:
            export default {
              // websocket连接地址
              // ws_base_url: "localhost:3020",
              ws_base_url: location.host,
              // rcc连接地址
              rcc_base_url: "http://ip:port",
            };
        """
        data = await request.json()
        rcc_addr = data.get("RCC_ADDR", "")
        if not rcc_addr:
            raise HttpError(msg="rcc地址不能为空", status=400)
        self.logger.info(f"update rcc addr: {rcc_addr}")
        url_splits = rcc_addr.split(":")
        if len(url_splits) != 3:
            raise HttpError(msg="rcc地址错误", status=400)
        setting_data = {
            "protocol": url_splits[0],
            "addr": url_splits[1].replace("/", ""),
            "port": url_splits[2],
        }
        reset_settings(data=setting_data)
        return make_json_response()

    @exposed_http("GET", "/system/rcc/settings")
    async def get_settings(self, _: Request) -> Response:
        result = get_settings()

        return make_json_response(
            result=result
        )

    @exposed_http("POST", "/system/rcc/settings")
    async def reset_settings(self, request: Request) -> Response:
        data = await request.json()

        try:
            reset_settings(data=data)
        except Exception as e:
            raise HttpError(msg=e.__str__(), status=400)

        return make_json_response(result=dict(
            addr=data.get("addr", ""),
            port=data.get("port", ""),
            protocol=data.get("protocol", "")
        ))

    @exposed_http("GET", "/system/version")
    async def system_version(self, _: Request):
        """
        查看当前系统的版本信息
        :param _:
        :return:
        """
        version = await get_system_version()

        return make_json_response(
            result=version
        )
