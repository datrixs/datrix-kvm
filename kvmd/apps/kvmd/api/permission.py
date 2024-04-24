from aiohttp.web import Request
from aiohttp.web import Response

from ..table import PermissionTable
from ....htserver import exposed_http, make_json_response
from ....logging import get_logger
from ....yamlconf import Section


class PermissionsApi:
    def __init__(self, config: Section) -> None:
        self.table = PermissionTable(config.kvmd.sqlite.path)

    @exposed_http("GET", "/permissions")
    async def get_list(self, _: Request) -> Response:
        get_logger().info("get permission list")
        return make_json_response(
            result=dict(
                data=self.table.get_permissions()
            )
        )
