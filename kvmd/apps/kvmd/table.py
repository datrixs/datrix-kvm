import datetime
import json
import sqlite3
from typing import List, Dict

from aiohttp.web_request import Request

tz = datetime.timezone(datetime.timedelta(hours=+8))


class BaseTable:
    def __init__(self, db_file):
        self._db_file = db_file

    def _execute_query(self, query: str, args: tuple = None):
        with sqlite3.connect(self._db_file) as conn:
            cursor = conn.cursor()
            if args:
                cursor.execute(query, args)
            else:
                cursor.execute(query)
            conn.commit()

    def _fetch_all(self, query: str, args: tuple = None):
        with sqlite3.connect(self._db_file) as conn:
            cursor = conn.cursor()
            if args:
                cursor.execute(query, args)
            else:
                cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                yield row

    def _fetch_one(self, query: str, args: tuple = None):
        with sqlite3.connect(self._db_file) as conn:
            cursor = conn.cursor()
            if args:
                cursor.execute(query, args)
            else:
                cursor.execute(query)
            row = cursor.fetchone()
            return row, True if row else False


class UserTable(BaseTable):
    def __init__(self, db_file):
        super().__init__(db_file)

    def create_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role_id INTEGER NOT NULL,
                remark TEXT NULL,
                last_login TEXT NOT NULL DEFAULT '',
                is_online INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (role_id) REFERENCES roles(id)
            )
        '''
        self._execute_query(query)

    def insert_user(self, username: str, password: str, role_id: int,
                    remark: str = None):
        query = '''
            INSERT INTO users (username, password, role_id, remark)
            VALUES (?, ?, ?, ?)
        '''
        self._execute_query(query, (username, password, role_id, remark))

    def update_user(self, user_id: int, role_id: int, username: str,
                    password: str, remark: str = None):
        query = '''
            UPDATE users
            SET username = ?, role_id = ?, password = ?, remark = ?
            WHERE id = ?
        '''
        self._execute_query(query,
                            (username, role_id, password, remark, user_id))

    def delete_user(self, user_id: int):
        query = '''
            DELETE FROM users
            WHERE id = ?
        '''
        self._execute_query(query, (user_id,))

    def check_exists(self, user_id: int, username: str) -> bool:
        if user_id is None:
            query = '''
                SELECT 1
                FROM users
                WHERE username = ?
            '''
            param = (username,)
        else:
            query = '''
                SELECT 1
                FROM users
                WHERE id != ? and username = ?
            '''
            param = (user_id, username)
        _, exists = self._fetch_one(query, param)
        return exists

    def get_user(self, key, value) -> Dict:
        query = "SELECT users.id, users.username, users.role_id, users.remark, roles.name as role_name, " \
                "roles.permissions, users.last_login, users.is_online FROM users " \
                f"LEFT JOIN roles ON users.role_id = roles.id WHERE users.{key} = ?"

        row, exists = self._fetch_one(query, (value,))
        if not exists:
            return dict()
        return dict(
            id=row[0],
            username=row[1],
            role_id=row[2],
            remark=row[3],
            role_name=row[4],
            permissions=json.loads(row[5]),
            last_login=row[6],
            is_online=row[7],
        )

    def get_users(self) -> List[Dict]:
        query = '''
            SELECT id, username, role_id, remark
            FROM users
        '''
        return [
            dict(
                id=row[0],
                username=row[1],
                role_id=row[2],
                remark=row[3],
            ) for row in self._fetch_all(query)
        ]

    def get_users_for_role(self, role_id: int):
        query = '''
            SELECT id, username, role_id, remark
            FROM users
            WHERE users.role_id = ?
        '''
        return [
            dict(
                id=row[0],
                username=row[1],
                role_id=row[2],
                remark=row[3],
            ) for row in self._fetch_all(query, (role_id,))
        ]

    def update_login_status(self, username: str, is_login: bool = False):
        """更新登录信息"""
        if not username:
            return
        datetime_now = datetime.datetime.now().astimezone(tz).strftime(
            "%Y-%m-%d %H:%M:%S")
        if is_login:
            login_time = datetime_now
            is_login = 1
        else:
            login_time = ""
            is_login = 0
        query = '''
            UPDATE users
            SET last_login = ?, is_online = ?
            WHERE username = ?
        '''
        self._execute_query(query, (login_time, is_login, username))

    def get_user_by_name(self, username: str) -> Dict:
        query = '''
            SELECT id, username, last_login, is_online
            FROM users
            WHERE username = ?
        '''
        row, exists = self._fetch_one(query, (username,))
        if not exists:
            return dict()
        return dict(
            id=row[0],
            username=row[1],
            last_login=row[2],
            is_online=row[3],
        )

    def get_count(self):
        query = '''SELECT COUNT(*) FROM users'''
        row, _ = self._fetch_one(query)
        return row[0]


class RoleTable(BaseTable):
    def __init__(self, db_file):
        super().__init__(db_file)

    def create_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                permissions TEXT NOT NULL,
                remark TEXT NULL
            )
        '''
        self._execute_query(query)

    def insert_role(self, name: str, permissions: str, remark: str = None):
        query = '''
            INSERT INTO roles (name, permissions, remark)
            VALUES (?, ?, ?)
        '''
        self._execute_query(query, (name, permissions, remark))

    def update_role(self, role_id: int, name: str, permissions: str,
                    remark: str = None):
        query = '''
            UPDATE roles
            SET name = ?, permissions = ?, remark = ?
            WHERE id = ?
        '''
        self._execute_query(query, (name, permissions, remark, role_id))

    def delete_role(self, role_id: int):
        query = '''
            DELETE FROM roles
            WHERE id = ?
        '''
        self._execute_query(query, (role_id,))

    def check_exists(self, role_id: int, name: str) -> bool:
        if role_id is None:
            query = '''
                SELECT 1
                FROM roles
                WHERE name = ?
            '''
            param = (name,)
        else:
            query = '''
                SELECT 1
                FROM roles
                WHERE id != ? and name = ?
            '''
            param = (role_id, name)
        _, exists = self._fetch_one(query, param)
        return exists

    def get_role(self, role_id: int) -> Dict:
        query = '''
            SELECT id, name, permissions, remark
            FROM roles
            WHERE id = ?
        '''
        row, exists = self._fetch_one(query, (role_id,))
        if not exists:
            return dict()
        return dict(
            id=row[0],
            name=row[1],
            permissions=json.loads(row[2]),
            remark=row[3],
        )

    def get_roles(self) -> List[Dict]:
        query = '''
            SELECT id, name, permissions, remark
            FROM roles
        '''
        return [
            dict(
                id=row[0],
                name=row[1],
                permissions=json.loads(row[2]),
                remark=row[3],
            ) for row in self._fetch_all(query)
        ]


class PermissionTable(BaseTable):
    def __init__(self, db_file: str):
        super().__init__(db_file)

    def create_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            )
        '''
        self._execute_query(query)

    def insert_permission(self, name: str):
        query = '''
            INSERT INTO permissions (name)
            VALUES (?)
        '''
        self._execute_query(query, (name,))

    def update_permission(self, permission_id: int, name: str):
        query = '''
            UPDATE permissions
            SET name = ?
            WHERE id = ?
        '''
        self._execute_query(query, (name, permission_id))

    def delete_permission(self, permission_id: int):
        query = '''
            DELETE FROM permissions
            WHERE id = ?
        '''
        self._execute_query(query, (permission_id,))

    def get_permission(self, permission_id: int) -> Dict:
        query = '''
             SELECT id, name
             FROM permissions
             WHERE id = ?
         '''
        row, exists = self._fetch_one(query, (permission_id,))
        if not exists:
            return dict()
        return dict(
            id=row[0],
            name=row[1]
        )

    def get_permissions(self) -> List[Dict]:
        query = '''
            SELECT id, name
            FROM permissions
        '''
        return [
            dict(
                id=row[0],
                name=row[1]
            ) for row in self._fetch_all(query)
        ]


class LogTable(BaseTable):
    def __init__(self, db_file: str):
        super().__init__(db_file)

    def create_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                create_time TEXT NOT NULL,
                username TEXT NOT NULL,
                level INTEGER NOT NULL,
                description TEXT NOT NULL
            )
        '''
        self._execute_query(query)

    def insert_log_for_request(self, request: Request, level: int,
                               description: str):
        username = request.headers.get("X-KVMD-User", "")
        remote = request.headers.get("X-Real-IP", "")
        create_time = datetime.datetime.now().astimezone(tz).strftime(
            "%Y-%m-%d %H:%M:%S")
        description = f"用户:[{username}] IP地址:[{remote}] [{description}]"
        query = '''
            INSERT INTO logs (create_time, username, level, description)
            VALUES (?,?,?,?)
        '''
        self._execute_query(query, (create_time, username, level, description))

    def insert_log(self, username: str, level: int, description: str):
        create_time = datetime.datetime.now().astimezone(tz).strftime(
            "%Y-%m-%d %H:%M:%S")
        query = '''
            INSERT INTO logs (create_time, username, level, description)
            VALUES (?,?,?,?)
        '''
        self._execute_query(query, (create_time, username, level, description))

    def get_logs(self, page: int = 1, size: int = 20) -> List[Dict]:
        offset = (page - 1) * size
        query = '''
            SELECT id, create_time, username, level, description
            FROM logs ORDER BY id DESC LIMIT ? OFFSET ?
        '''
        return [
            dict(
                id=row[0],
                create_time=row[1],
                username=row[2],
                level=row[3],
                description=row[4],
            ) for row in self._fetch_all(query, (size, offset))
        ]

    def get_count(self) -> int:
        query = '''
            SELECT COUNT(*)
            FROM logs
        '''
        row, exists = self._fetch_one(query)
        if not exists:
            return 0
        return row[0]

    def delete_log(self):
        query = '''
        DELETE FROM logs
        WHERE date('now', '-30 day') >= date(create_time);
        '''
        self._execute_query(query)


class SystemSettingTable(BaseTable):
    def __init__(self, db_file):
        super().__init__(db_file)

    def create_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS system_settings (
                id INTEGER PRIMARY KEY,
                system_name TEXT UNIQUE NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                create_time TEXT NULL,
                update_time TEXT NULL
            )
        '''
        self._execute_query(query)

    def insert_system_setting(self, system_name: str, content: str):
        datetime_now = datetime.datetime.now().astimezone(tz).strftime(
            "%Y-%m-%d %H:%M:%S")
        query = '''
            INSERT INTO system_settings (system_name, content, create_time)
            VALUES (?,?,?)
        '''
        self._execute_query(query, (system_name, content, datetime_now))

    def update_system_setting(self, system_name: str, content: str):
        datetime_now = datetime.datetime.now().astimezone(tz).strftime(
            "%Y-%m-%d %H:%M:%S")
        query = '''
            UPDATE system_settings SET
            content=?, update_time=?
            WHERE system_name=?
        '''
        self._execute_query(query, (content, datetime_now, system_name))

    def get_setting_content(self, system_name: str) -> dict:
        query = '''
            SELECT id, system_name, content
            FROM system_settings where system_name=?
        '''
        row, exists = self._fetch_one(query, (system_name,))
        if not exists:
            return {}
        return json.loads(row[2])

    def check_setting_status(self, system_name: str) -> bool:
        query = '''
            SELECT count(1)
            FROM system_settings where system_name=?
        '''
        row, exists = self._fetch_one(query, (system_name,))
        if not row[0]:
            return False
        return True


class LoginFailMsgTable(BaseTable):
    """登录失败信息"""

    def __init__(self, db_file):
        super().__init__(db_file)
        self.init_db = False
        if not self.init_db:
            self.delete_row()
            self.init_db = True

    def create_table(self):
        query = '''
            CREATE TABLE IF NOT EXISTS login_fail_msg
            (
                id               INTEGER PRIMARY KEY,
                username         TEXT    NULL,
                user_addr        TEXT    NULL,
                login_fail_time  TEXT    NULL,
                login_fail_count INTEGER NOT NULL DEFAULT 0,
                lock_status      INTEGER NOT NULL DEFAULT 0,
                is_delete        INTEGER NOT NULL DEFAULT 0
            )
        '''
        self._execute_query(query)

    def insert_login_fail_msg(
            self, username: str, user_addr: str, login_fail_count: int,
            lock_status: int, is_delete: int
    ):
        datetime_now = datetime.datetime.now().astimezone(tz).strftime(
            "%Y-%m-%d %H:%M:%S")
        query = '''
            INSERT INTO login_fail_msg 
            (username, user_addr, login_fail_time, login_fail_count, lock_status, is_delete)
            VALUES (?,?,?,?,?,?)
        '''
        params = (
            username, user_addr, datetime_now, login_fail_count, lock_status,
            is_delete)
        self._execute_query(query, params)

    def update_login_fail_msg(
            self, msg_id: int, login_fail_count: int, lock_status: int,
            is_delete: int
    ):
        if is_delete:
            datetime_now = ""
        else:
            datetime_now = datetime.datetime.now().astimezone(tz).strftime(
                "%Y-%m-%d %H:%M:%S")
        query = '''
            UPDATE login_fail_msg SET
            login_fail_time=?, login_fail_count=?, lock_status=?, is_delete=?
            WHERE id=?
        '''
        params = (
            datetime_now, login_fail_count, lock_status, is_delete, msg_id)
        self._execute_query(query, params)

    def get_account_login_fail_msg(self, username: str):
        if not username:
            return {}
        query = '''
                    SELECT id, username, user_addr, login_fail_time, login_fail_count, lock_status, is_delete
                    FROM login_fail_msg where username=?
                '''
        return self.get_login_fail_msg(query=query, args=(username,))

    def get_client_login_fail_msg(self, user_addr: str):
        if not user_addr:
            return {}
        query = '''
                    SELECT id, username, user_addr, login_fail_time, login_fail_count, lock_status, is_delete
                    FROM login_fail_msg where user_addr=?
                '''
        return self.get_login_fail_msg(query=query, args=(user_addr,))

    def get_login_fail_msg(self, query: str, args: tuple) -> dict:
        if not query:
            return {}
        row, exists = self._fetch_one(query, args)
        if not exists:
            return {}
        return dict(
            id=row[0],
            username=row[1],
            user_addr=row[2],
            login_fail_time=row[3],
            login_fail_count=row[4],
            lock_status=row[5],
            is_delete=row[6],
        )

    def get_many_account_login_fail_msg(self, usernames: list) -> dict:
        data = {}
        query = '''
            SELECT username, lock_status FROM login_fail_msg WHERE is_delete=0
        '''
        if len(usernames) < 1:
            return data
        if len(usernames) == 1:
            query += f" AND username='{usernames[0]}'"
        else:
            query += f" AND username in {tuple(usernames)}"
        rows = self._fetch_all(query, )
        if not rows:
            return data
        for row in rows:
            data[row[0]] = row[1]
        return data

    def get_many_client_login_fail_msg(self) -> list:
        data = []
        query = """
            SELECT id, user_addr, lock_status FROM login_fail_msg WHERE lock_status=1 AND username=''
        """
        rows = self._fetch_all(query, )
        if not rows:
            return data
        for row in rows:
            data.append({"id": row[0], "user_addr": row[1]})
        return data

    def update_many_client_login_fail_msg(self, filter_macs: list,
                                          mac_include: bool = False):
        """
        更新多个，解锁客户端PC
        """
        macs = self.get_many_client_login_fail_msg()
        for mac in macs:
            if not filter_macs:
                self.update_login_fail_msg(msg_id=mac["id"], login_fail_count=0,
                                           lock_status=0, is_delete=1)
                continue
            user_addr = mac.get("user_addr", "").lower()
            if mac_include and (user_addr in filter_macs):
                self.update_login_fail_msg(msg_id=mac["id"], login_fail_count=0,
                                           lock_status=0, is_delete=1)
            elif (not mac_include) and (user_addr not in filter_macs):
                self.update_login_fail_msg(msg_id=mac["id"], login_fail_count=0,
                                           lock_status=0, is_delete=1)

    def update_all_login_fail_msg(self, update_type: int = 1):
        """
        刷新全部信息，update_type：1->账号；2->客户端PC
        """
        if update_type == 1:
            query = """
                UPDATE login_fail_msg SET login_fail_count=0, lock_status=0, is_delete=1
                WHERE username != '' 
            """
        elif update_type == 2:
            query = """
                UPDATE login_fail_msg SET login_fail_count=0, lock_status=0, is_delete=1
                WHERE username = ''
            """
        else:
            return
        self._execute_query(query)

    def check_one_exists(self, username: str):
        """检查账号是否存在记录"""
        if not username:
            return 0, False
        query = '''
            SELECT id FROM login_fail_msg WHERE username=?
        '''
        row, exists = self._fetch_one(query, (username,))
        if not exists:
            return 0, False
        return row[0], True

    def delete_row(self):
        """
        每次重启服务之后，将登录失败信息重置
        """
        query_count = """
            SELECT username, count(username) FROM login_fail_msg GROUP BY username
        """
        query_msg = """
            SELECT id FROM login_fail_msg WHERE username=?
        """
        query_del = '''
            DELETE FROM login_fail_msg WHERE id=? 
        '''
        rows = self._fetch_all(query_count)
        for row in rows:
            username = row[0]
            count = row[1]
            if count > 1:
                lines = self._fetch_all(query_msg, (username,))
                user_data = [x[0] for x in lines]
                for line in user_data[:-1]:
                    self._execute_query(query_del, (line,))
