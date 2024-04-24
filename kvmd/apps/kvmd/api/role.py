import json

from aiohttp.web import Request
from aiohttp.web import Response

from ..table import RoleTable, UserTable, LogTable
from ....htserver import HttpError, exposed_http, make_json_response
from ....logging import get_logger
from ....yamlconf import Section


class RolesApi:
    def __init__(self, config: Section, log_table: LogTable) -> None:
        self.table = RoleTable(config.kvmd.sqlite.path)
        self.user_table = UserTable(config.kvmd.sqlite.path)
        self.role = config.kvmd.sqlite.role
        self.__log_table = log_table

    @exposed_http("GET", "/roles")
    async def get_list(self, request: Request) -> Response:
        get_logger().info("get role list")
        self.__log_table.insert_log_for_request(
            request=request,
            level=5,
            description="获取角色列表"
        )
        return make_json_response(
            result=dict(
                data=self.table.get_roles()
            )
        )

    @exposed_http("POST", "/roles")
    async def add(self, request: Request) -> Response:
        data = await request.json()
        name = data.get("name", "")
        permissions = [int(item) for item in data.get("permissions", [])]
        remark = data.get("remark", "")
        await self.check_role(
            name=name,
        )
        get_logger().info(f"insert role:{name} to db")
        self.__log_table.insert_log_for_request(
            request=request,
            level=5,
            description=f"新增角色[{name}]"
        )
        self.table.insert_role(
            name=name,
            permissions=json.dumps(permissions),
            remark=remark,
        )
        return make_json_response()

    @exposed_http("GET", "/roles/{primary_id}")
    async def get(self, request: Request) -> Response:
        primary_id = request.match_info.get("primary_id", None)
        get_logger().info(f"get role:{primary_id}")
        self.__log_table.insert_log_for_request(
            request=request,
            level=5,
            description=f"获取角色[{primary_id}]"
        )
        return make_json_response(
            result=dict(
                data=self.table.get_role(
                    role_id=primary_id
                )
            )
        )

    @exposed_http("PUT", "/roles/{primary_id}")
    async def update(self, request: Request) -> Response:
        primary_id = request.match_info.get("primary_id", None)
        if primary_id in self.role:
            raise HttpError(msg="默认角色禁止修改", status=400)
        role = self.table.get_role(role_id=primary_id)
        if role != dict():
            data = await request.json()
            name = data.get("name", "")
            permissions = [int(item) for item in data.get("permissions", [])]
            remark = data.get("remark", "")
            await self.check_role(
                name=name,
                role_id=primary_id,
            )
            get_logger().info(f"update role:{primary_id} to db")
            self.__log_table.insert_log_for_request(
                request=request,
                level=5,
                description=f"修改角色[{name}]"
            )
            self.table.update_role(
                role_id=primary_id,
                name=name,
                permissions=json.dumps(permissions),
                remark=remark,
            )

        return make_json_response()

    @exposed_http("DELETE", "/roles/{primary_id}")
    async def delete(self, request: Request) -> Response:
        primary_id = request.match_info.get("primary_id", None)

        if primary_id in self.role:
            raise HttpError(msg="默认角色禁止删除", status=400)

        if len(self.user_table.get_users_for_role(role_id=primary_id)) > 0:
            raise HttpError(msg="当前角色下存在用户，不允许删除", status=400)

        role = self.table.get_role(role_id=primary_id)
        if role != dict():
            get_logger().info(f"delete role:{primary_id}")
            self.table.delete_role(role_id=primary_id)
            self.__log_table.insert_log_for_request(
                request=request,
                level=5,
                description=f"删除角色[{primary_id}]"
            )
        return make_json_response()

    async def check_role(
        self,
        name: str,
        role_id: int = None
    ):
        if len(name) <= 0:
            raise HttpError(msg="角色名称不能为空", status=400)
        else:
            exists = self.table.check_exists(
                role_id=role_id,
                name=name
            )
            if exists:
                get_logger().error("name is exists")
                raise HttpError(msg="角色名称已被其他角色使用", status=400)
