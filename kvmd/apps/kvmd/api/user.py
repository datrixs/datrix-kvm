from aiohttp.web import Request
from aiohttp.web import Response

from ..table import UserTable, LoginFailMsgTable, LogTable
from ...htpasswd import _get_htpasswd_for_write
from ....htserver import HttpError, exposed_http, make_json_response
from ....logging import get_logger
from ....validators.auth import valid_user, valid_passwd
from ....yamlconf import Section


class UsersApi:
    def __init__(self, config: Section, log_table: LogTable) -> None:
        self.config = config
        self.table = UserTable(config.kvmd.sqlite.path)
        self.login_fail_msg_table = LoginFailMsgTable(config.kvmd.sqlite.path)
        self.user = config.kvmd.sqlite.user
        self.admin_default_passwd = config.kvmd.sqlite.admin_default_passwd
        self.default_passwd = config.kvmd.sqlite.default_passwd
        self.__log_table = log_table

    @exposed_http("GET", "/users")
    async def get_list(self, request: Request) -> Response:
        role_id = request.rel_url.query.get("role_id")
        if role_id:
            data = self.table.get_users_for_role(role_id=int(role_id))
            get_logger().info(f"get user list for role id:{role_id}")
            self.__log_table.insert_log_for_request(
                request=request,
                level=5,
                description="根据角色获取用户列表"
            )
        else:
            data = self.table.get_users()
            get_logger().info("get user list")
            self.__log_table.insert_log_for_request(
                request=request,
                level=5,
                description="获取用户列表"
            )

        # 添加用户锁定状态
        users = [x["username"] for x in data]
        lock_users = self.login_fail_msg_table.get_many_account_login_fail_msg(usernames=users)
        for user in data:
            username = user["username"]
            user["lock_status"] = True if lock_users.get(username, 0) else False
        return make_json_response(
            result=dict(
                data=data
            )
        )

    @exposed_http("POST", "/users")
    async def add(self, request: Request) -> Response:
        if self.table.get_count() >= 64:
            raise HttpError(msg="最多只支持创建64个用户", status=400)
        data = await request.json()
        username = data.get("username", "")
        role_id = data.get("role_id")
        password = data.get("password", "")
        repeated_password = data.get("repeated_password", "")
        remark = data.get("remark", "")
        await self.check_user(
            username=username,
            password=password,
            repeated_password=repeated_password
        )
        await self.set_htpasswd(username, password)
        passwd = await self.get_htpasswd(username)
        get_logger().info(f"insert user:{username} to db")
        self.__log_table.insert_log_for_request(
            request=request,
            level=5,
            description=f"新增用户[{username}]"
        )
        self.table.insert_user(
            username=username,
            password=passwd,
            role_id=role_id,
            remark=remark,
        )
        return make_json_response()

    @exposed_http("GET", "/users/{primary_id}")
    async def get(self, request: Request) -> Response:
        primary_id = request.match_info.get("primary_id", None)
        get_logger().info(f"get user:{primary_id}")
        self.__log_table.insert_log_for_request(
            request=request,
            level=5,
            description=f"获取用户[{primary_id}]"
        )
        return make_json_response(
            result=dict(
                data=self.table.get_user(
                    key="id",
                    value=primary_id
                )
            )
        )

    @exposed_http("PUT", "/users/{primary_id}")
    async def update(self, request: Request) -> Response:
        primary_id = request.match_info.get("primary_id", None)
        if primary_id in self.user:
            raise HttpError(msg="默认用户禁止修改", status=400)
        user = self.table.get_user(key="id", value=primary_id)
        if user != dict():
            data = await request.json()
            username = data.get("username", "")
            role_id = data.get("role_id")
            password = data.get("password", "")
            repeated_password = data.get("repeated_password", "")
            remark = data.get("remark", "")
            await self.check_user(
                user_id=primary_id,
                username=username,
                password=password,
                repeated_password=repeated_password
            )

            # 修改了用户名
            if user["username"] != username:
                # 删除历史密码记录
                await self.del_htpasswd(user["username"])

            # 修改了密码
            if len(password) > 0:
                await self.set_htpasswd(username, password)
            passwd = await self.get_htpasswd(username)

            get_logger().info(f"update user:{primary_id} to db")
            self.__log_table.insert_log_for_request(
                request=request,
                level=5,
                description=f"修改用户[{username}]"
            )
            self.table.update_user(
                user_id=primary_id,
                role_id=role_id,
                username=username,
                password=passwd,
                remark=remark,
            )

        return make_json_response()

    @exposed_http("DELETE", "/users/{primary_id}")
    async def delete(self, request: Request) -> Response:
        primary_id = request.match_info.get("primary_id", None)
        if primary_id in self.user:
            raise HttpError(msg="默认用户禁止删除", status=400)
        user = self.table.get_user(key="id", value=primary_id)
        if user != dict():
            get_logger().info(f"delete user:{primary_id}")
            self.__log_table.insert_log_for_request(
                request=request,
                level=5,
                description=f"删除用户[{user['username']}]"
            )
            self.table.delete_user(user_id=primary_id)
            await self.del_htpasswd(user["username"])
        return make_json_response()

    @exposed_http("PUT", "/users/reset_password/{primary_id}")
    async def reset(self, request: Request) -> Response:
        primary_id = request.match_info.get("primary_id", None)
        if primary_id in self.user:
            passwd = self.admin_default_passwd
        else:
            passwd = self.default_passwd
        user = self.table.get_user(key="id", value=primary_id)
        if user != dict():
            username = user["username"]
            role_id = user["role_id"]
            remark = user["remark"]
            await self.del_htpasswd(username)

            await self.set_htpasswd(username, passwd)

            get_logger().info(f"reset user:{primary_id} password to db")
            self.__log_table.insert_log_for_request(
                request=request,
                level=5,
                description=f"重制密码"
            )
            self.table.update_user(
                user_id=primary_id,
                role_id=role_id,
                username=username,
                password=await self.get_htpasswd(username),
                remark=remark,
            )

        return make_json_response()

    @exposed_http("POST", "/users/unlock_username")
    async def unlock_username(self, request: Request) -> Response:
        """解锁客户账号"""
        data = await request.json()
        username = data.get("username", "")
        if not username:
            get_logger().warning(f"unlock username fail: not username")
            return make_json_response()
        msg_id, exists = self.login_fail_msg_table.check_one_exists(username=username)
        if not exists:
            get_logger().warning(f"unlock username->{username} fail: user not exists or not locked")
            raise HttpError(msg="用户账号未被锁定或者用户账号不存在", status=400)
        self.login_fail_msg_table.update_login_fail_msg(
            msg_id=msg_id, login_fail_count=0, lock_status=0, is_delete=1
        )
        get_logger().info(f"unlock username: {username} success ...")
        return make_json_response()

    @exposed_http("POST", "/users/lock_username")
    async def lock_username(self, request: Request) -> Response:
        """锁定客户账号"""
        data = await request.json()
        username = data.get("username", "")
        if not username:
            get_logger().warning(f"lock username fail: not username")
            return make_json_response()
        user = self.table.get_user(key="username", value=username)
        if not user:
            get_logger().warning(f"lock username fail: not found user->{username}")
            raise HttpError(msg="用户不存在", status=400)
        msg_id, exists = self.login_fail_msg_table.check_one_exists(username=username)
        if not exists:
            self.login_fail_msg_table.insert_login_fail_msg(
                username=username, user_addr="", login_fail_count=0, lock_status=1, is_delete=0
            )
        else:
            self.login_fail_msg_table.update_login_fail_msg(
                msg_id=msg_id, login_fail_count=999, lock_status=1, is_delete=0
            )
        get_logger().info(f"lock username: {username} success ...")
        return make_json_response()

    async def check_user(
        self,
        username: str,
        password: str,
        repeated_password: str,
        user_id: int = None,
    ):
        username = valid_user(username)
        password = valid_passwd(password)
        repeated_password = valid_passwd(repeated_password)
        if len(password) > 0 and password != repeated_password:
            get_logger().error("user passwords do not match")
            raise HttpError(msg="两次密码不一致", status=400)
        if len(username) > 0:
            exists = self.table.check_exists(
                user_id=user_id,
                username=username
            )
            if exists:
                get_logger().error("username is exists")
                raise HttpError(msg="用户名称已被其他人使用", status=400)

    async def set_htpasswd(self, username: str, password: str):
        with _get_htpasswd_for_write(self.config) as htpasswd:
            htpasswd.set_password(username, password)
            get_logger().info("insert user to htpasswd")

    async def get_htpasswd(self, username: str) -> str:
        with _get_htpasswd_for_write(self.config) as htpasswd:
            return htpasswd.get_hash(username)

    async def del_htpasswd(self, username: str):
        with _get_htpasswd_for_write(self.config) as htpasswd:
            get_logger().info("delete user to htpasswd")
            htpasswd.delete(username)
