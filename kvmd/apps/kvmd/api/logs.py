from aiohttp.web import Request
from aiohttp.web import Response

from ..table import LogTable
from ....htserver import exposed_http, make_json_response
from ....logging import get_logger
from ....yamlconf import Section


class LogsApi:
    def __init__(self, config: Section) -> None:
        self.table = LogTable(config.kvmd.sqlite.path)

    @exposed_http("GET", "/sys_logs")
    async def get_list(self, request: Request) -> Response:
        page = request.rel_url.query.get("page", 1)
        size = request.rel_url.query.get("size", 20)
        get_logger().info("get log list")
        return make_json_response(
            result=dict(
                data=self.table.get_logs(
                    page=int(page),
                    size=int(size),
                ),
                page=page,
                size=size,
                count=self.table.get_count()
            )
        )
