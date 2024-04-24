import datetime
import json
import os
import socket
import subprocess
import threading

import psutil
from aiohttp.web import Request, Response

from ..auth import AuthManager
from ..table import SystemSettingTable, LogTable, LoginFailMsgTable
from ...kvmd.report_log import update_kvm_addr
from ...utils.system import get_system_version
from ....logging import get_logger
from ....validators.auth import valid_auth_token
from ....htserver import (
    exposed_http, make_json_response, ForbiddenError, HttpError, RequestMsgControl
)

NTP_SERVERS = [
    "0.debian.pool.ntp.org",
    "1.debian.pool.ntp.org",
    "2.debian.pool.ntp.org",
    "3.debian.pool.ntp.org",
    "0.cn.pool.ntp.org",
    "1.cn.pool.ntp.org",
    "2.cn.pool.ntp.org",
    "3.cn.pool.ntp.org",
    "ntp.ntsc.ac.cn",
    "ntp.tencent.com",
    "ntp.aliyun.com",
    "time.edu.cn",  # 只会同步时间，不会同步日期
    "s2c.time.edu.cn",
    "s2f.time.edu.cn",
    "s2k.time.edu.cn",
]

# 时区配置
ZONE_MAP = {
    "Asia/Shanghai": ["[亚洲] 中国/上海", 0],
    "Asia/Tokyo": ["[亚洲] 日本/东京", 1],
    "Asia/Singapore": ["[亚洲] 新加坡", 0],
    "Asia/Bangkok": ["[亚洲] 泰国/曼谷", -1],
    "Asia/Colombo": ["[亚洲] 印度/斯里兰卡/科伦坡", -3],
    "Asia/Kabul": ["[亚洲] 阿富汗/喀布尔", -4],
    "Asia/Baghdad": ["[亚洲] 伊拉克/巴格达", -5],
    "Asia/Dubai": ["[亚洲] 阿联/迪拜", -4],
    "Europe/Moscow": ["[欧洲] 俄罗斯/莫斯科", -5],
    "Europe/Paris": ["[欧洲] 法国/巴黎", -6],
    "Europe/Berlin": ["[欧洲] 德国/柏林", -6],
    "Europe/London": ["[欧洲] 英国/伦敦", -7],
    "Europe/Dublin": ["[欧洲] 爱尔兰/都柏林", -7],
    "Europe/Istanbul": ["[欧洲] 土耳其/伊斯坦布尔", -5],
    "Europe/Bucharest": ["[欧洲] 罗马尼亚/布加勒斯", -5],
    "America/Los_Angeles": ["[北美洲] 美国/洛杉矶", -15],
    "America/New_York": ["[北美洲] 美国/纽约", -12],
    "America/Lima": ["[南美洲] 秘鲁/利马", -13],
    "America/Sao_Paulo": ["[南美洲] 巴西/圣保罗", -11],
    "Australia/Sydney": ["[大洋洲] 澳大利亚/悉尼", 2],
    "Pacific/Auckland": ["[大洋洲] 新西兰/奥克兰", 4],
    "Africa/Nairobi": ["[非洲] 肯尼亚/内罗毕", -5],
    "Africa/Lagos": ["[非洲] 尼日利亚/拉各斯", -7]
}


class StaticFilePath:
    HARDWARE_SETTING_DIR_PATH = "/root/user_settings"
    NETWORK_SETTING_FILE_NAME = "network_setting.txt"  # 保存的网络配置内容
    SAFETY_SETTING_FILE_NAME = "safety_setting.txt"  # 保存的安全设置内容

    NGINX_FILE_PATH = "/etc/kvmd/nginx/nginx.conf"  # 项目的nginx配置文件路径
    NGINX_HTTP_FILE_PATH = "/etc/kvmd/nginx/nginx-http.conf"  # 项目的nginx-http配置文件路径
    NGINX_HTTPS_FILE_PATH = "/etc/kvmd/nginx/nginx-https.conf"  # 项目的nginx-https配置文件路径
    HTTP_NGINX_FILE_PATH = "/etc/kvmd/nginx/listen-http.conf"  # http的nginx配置文件路径
    HTTPS_NGINX_FILE_PATH = "/etc/kvmd/nginx/listen-https.conf"  # https的nginx配置文件路径
    INET_FILE_PATH = "/etc/network/interfaces"  # 网络配置信息配置文件路径
    SSH_PORT_FILE_PATH = "/etc/ssh/sshd_config"  # ssh的nginx配置文件路径
    SERVICES_FILE_PATH = "/etc/services"  # 服务器端口号记录文件，这里用来读写 telnet 的端口号
    EQU_NAME_FILE_PATH = "/proc/device-tree/model"  # 记录设备型号的文件目录
    SN_FILE_PATH = "/proc/device-tree/serial-number"  # 记录FMG序列号的文件目录
    DNS_FILE_PATH = '/etc/resolv.conf'  # 记录DNS服务器地址的文件目录
    ZONEINFO_FILE_PATH = "/usr/share/zoneinfo/zone.tab"  # 记录时区列表的文件目录
    NTP_FILE_PATH = "/etc/ntp.conf"  # 时间服务器文件目录
    TIMEZONE_FILE_PATH = "/etc/timezone"  # 时区配置文件目录
    NGINX_INIT_PATH = "/app/nginx"  # 系统更新升级时读取的 nginx 类型文件


class DefaultMaps:
    SAFETY_LEVEL_MAP = {
        0: "自定义",
        1: "中",
        2: "中-高",
        3: "高",
    }

    SAFETY_LEVEL_CHOICE_MAP = {
        1: "启动ICMP",
        2: "启用Telnet服务",
        3: "启用SSH联机",
        4: "启用HTTP联机",
        5: "启用HTTPS联机",
    }

    TLS_VERSION_MAP = {
        1: "TLS 1.2",
        2: "TLS 1.0,1.1,1.2",
    }

    SAFETY_LEVEL_HIGH_MAP = {"choice": [3, 5], "tls": 1}
    SAFETY_LEVEL_MIDDLE_HIGH_MAP = {"choice": [1, 3, 4, 5], "tls": 1}
    SAFETY_LEVEL_MIDDLE_MAP = {"choice": [1, 3, 4, 5], "tls": 2}

    OPERATING_MODE_MAP = {
        1: "启用FIPS",
        2: "允许多用户操作",
        3: "开启虚拟储存写入功能",
        # 4: "关闭认证",
    }

    USERS_MODE_MAP = {
        1: "共享",
        2: "排他",
        3: "独占",
        4: "待机模式",
    }

    NETWORK_RATE_MAP = {
        "1000": "1000M网络适配器",
    }


class SystemSettingName:
    TIME_SETTING = "time"
    NETWORK_SETTING = "network"
    SAFETY_SETTING = "safety"


class ReadOrWriteFile(object):
    def __init__(self):
        self.logger = get_logger()

    @staticmethod
    async def read_file(path: str, text: bool = False):
        """
        读取文件
        """
        if not path:
            raise HttpError("系统配置文件不存在", 400)
        with open(path, 'r', encoding='utf-8') as f:
            if not text:
                return f.readlines()
            else:
                return f.read()

    @staticmethod
    async def write_file(path: str, data, lines: bool = False, style: str = "w"):
        """覆盖写入文件"""
        write_data = json.dumps(data, ensure_ascii=False)
        with open(path, style, encoding="utf-8") as f:
            if not lines:
                f.write(write_data)
            else:
                for line in data:
                    f.write(line)

    async def get_project_server_port(self):
        """读项目的nginx配置，解析出项目使用的端口号"""
        file_path = StaticFilePath.NGINX_FILE_PATH
        file_content = await self.read_file(path=file_path)
        project_port = None
        server_flag = False
        for line in file_content:
            if line.strip().startswith("server"):
                server_flag = True
            if server_flag and line.strip().startswith("}"):
                server_flag = False
            if server_flag and line.strip().startswith("listen"):
                port = line.strip().split(' ')[-1][:-1]
                if "ssl" in port:
                    continue
                else:
                    project_port = port
                    break
        return project_port

    async def get_http_port(self, http: bool = True) -> int:
        """
        获取http或和https的端口号

        http:
            listen 80;
            listen [::]:80;
        https:
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
        """
        file_path = StaticFilePath.HTTP_NGINX_FILE_PATH if http else StaticFilePath.HTTPS_NGINX_FILE_PATH
        file_content = await self.read_file(path=file_path)
        http_port = 80 if http else 443
        for line in file_content:
            if not line.startswith("listen"):
                continue
            if "[::]" in line:
                continue
            line_datas = line.strip()[:-1].split(" ")
            line_datas = [x for x in line_datas if x]
            try:
                http_port = int(line_datas[1])
            except (ValueError, IndexError):
                pass
        return http_port

    async def get_https_port(self):
        return await self.get_http_port(http=False)

    async def get_ssh_port(self):
        """
        获取ssh服务的端口号，默认情况为22,一般都是被注释了的
        eg:
            ...
            # default value.

            #Port 22
            #AddressFamily any
            #ListenAddress 0.0.0.0
            #ListenAddress ::
            ...
        """
        file_path = StaticFilePath.SSH_PORT_FILE_PATH
        ssh_port = None
        file_content = await self.read_file(path=file_path)
        for line in file_content:
            if line.strip().startswith("#Port"):
                port_line = line.strip().split(" ")
                if not ssh_port:
                    ssh_port = port_line[-1]
            elif line.strip().startswith("Port"):
                real_port_line = line.strip().split(" ")
                ssh_port = real_port_line[-1]
                break

        return ssh_port

    async def get_telnet_port(self):
        """获取telnet的端口号"""
        file_path = StaticFilePath.SERVICES_FILE_PATH
        file_content = await self.read_file(path=file_path)
        telnet_port = None
        for line in file_content:
            line = line.strip()
            line_datas = line.split(" ")
            if line_datas[0] == "telnet":
                line_datas = [x for x in line_datas if x]
                telnet_port_str = line_datas[1]
                telnet_port_data = telnet_port_str.strip().split("/")
                telnet_port = telnet_port_data[0]
                break
        return telnet_port

    async def write_project_port(self, port: int):
        """将设置的项目端口号写入配置中"""
        file_path = StaticFilePath.NGINX_FILE_PATH
        listen_line = f"\t\tlisten {port};\n"
        file_content = await self.read_file(path=file_path)
        listen_flag, listen_index, server_index = False, 0, 0
        server_flag = False
        for index, line in enumerate(file_content):
            line = line.strip()
            if line == "":
                continue
            if line.startswith("server"):
                server_flag = True
                server_index = index
            if server_flag and line.startswith("}"):
                server_flag = False
            if server_flag and line.startswith("listen"):
                listen_flag = True
                listen_index = index
        if listen_flag:
            file_content[listen_index] = listen_line
        else:
            file_content.insert(server_index + 1, listen_line)
        self.logger.info(f"write_project_port to file content: {file_content}")
        await self.write_file(path=file_path, data=file_content, lines=True)

    async def write_http_port(self, http_port: int, https_port: int, http: bool = True):
        """将设置的http端口号写入配置中"""
        file_path = StaticFilePath.HTTP_NGINX_FILE_PATH if http else StaticFilePath.HTTPS_NGINX_FILE_PATH
        file_content = await self.read_file(path=file_path)
        for index, line in enumerate(file_content):
            line = line.strip()
            if line == "":
                continue
            if line.startswith("listen"):
                line_datas = line.split(" ")
                line_datas = [x for x in line_datas if x]
                if "[::]" not in line:
                    port_str = f"{http_port if http else https_port}{';' if http else ''}"
                else:
                    port_str = f"[::]:{http_port if http else https_port}{';' if http else ''}"
                file_content[index] = line.replace(line_datas[1], port_str) + "\n"

        self.logger.info(f"write_http_port to file content: {file_content}")
        await self.write_file(path=file_path, data=file_content, lines=True)
        if http:
            await self.write_file(
                path=StaticFilePath.NGINX_INIT_PATH,
                data=["http\n", f"{http_port}\n", f"{https_port}\n"],
                lines=True
            )
        else:
            await self.write_file(
                path=StaticFilePath.NGINX_INIT_PATH,
                data=["https\n", f"{http_port}\n", f"{https_port}\n"],
                lines=True
            )

    async def write_https_port(self, http_port: int, https_port: int):
        """将设置的https端口号写入配置中"""
        await self.write_http_port(http_port=http_port, https_port=https_port, http=False)

    async def write_ssh_port(self, port: int):
        """将设置的ssh端口号写入配置中"""
        file_path = StaticFilePath.SSH_PORT_FILE_PATH
        port_index, real_index = 0, 0
        file_content = await self.read_file(path=file_path)
        for index, line in enumerate(file_content):
            line = line.strip()
            if line.startswith("#Port"):
                port_index = index
            if line.startswith("Port"):
                real_index = index
                break
        index_line = real_index if real_index != 0 else port_index
        if index_line:
            file_content[index_line] = f"Port {port}\n"
        else:
            file_content.append(f"Port {port}\n")
        self.logger.info(f"write_ssh_port to file content: {file_content}")
        await self.write_file(path=file_path, data=file_content, lines=True)

    async def write_telnet_port(self, port: int):
        """将设置的 telnet 端口号写入配置中"""
        file_path = StaticFilePath.SERVICES_FILE_PATH
        file_content = await self.read_file(path=file_path)
        for line in file_content:
            line_content = line.split("#")
            if str(port) in line_content[0]:
                raise ForbiddenError
        telnet_index = 0
        for index, line in enumerate(file_content):
            if line.startswith("telnet "):
                telnet_index = index
                break
        file_content[telnet_index] = f"telnet {port}/tcp\n"
        self.logger.info(f"write_telnet_port to file content: {file_content}")
        await self.write_file(path=file_path, data=file_content, lines=True)
        # os.system("service xinetd restart")

    async def write_inet(self, inet: dict):
        """将设置好的网络IP信息写入配置文件中"""
        ipv4 = inet.get("ipv4", {})
        ipv4_auto_ip = ipv4.get("auto_ip", False)
        ipv6 = inet.get("ipv6", {})
        ipv6_auto_ip = ipv6.get("auto_ip", False)

        def get_reduce_map(param: dict, ip4: bool = False):
            address = param.get("address", "")
            netmask = param.get("netmask", "")
            broadcast = param.get("broadcast", "")  # 网关
            prefix_len = param.get("prefix_len", "")  # 网关
            reduce_map = {
                "address": address if ip4 else f"{address}/{prefix_len}",
                "netmask": netmask,
                "gateway": broadcast,
            }
            return reduce_map

        reduce_map_ipv4 = get_reduce_map(ipv4, ip4=True)
        reduce_map_ipv6 = get_reduce_map(ipv6)

        file_path = StaticFilePath.INET_FILE_PATH
        file_exists = os.path.exists(file_path)
        # 先把文件内容读出来，如果文件本身不存在，则直接新建
        new_lines = []
        ax = ["auto", "iface", "address", "gateway", "netmask"]
        if file_exists:
            file_content = await self.read_file(path=file_path)
            for line in file_content:
                if line.strip() == "":
                    continue
                line_ax = line.strip().split(" ")[0]
                if line_ax not in ax:
                    new_lines.append(line)

        # 然后追加新的内容
        new_lines.append("auto eth1\n")
        if not ipv4_auto_ip:
            new_lines.append("iface eth1 inet static\n")
            for k, v in reduce_map_ipv4.items():
                if not v:
                    continue
                new_lines.append(f"{k} {v}\n")

        new_lines.append("\n")
        if not ipv6_auto_ip:
            new_lines.append("iface eth1 inet6 static\n")
            for k, v in reduce_map_ipv6.items():
                if not v:
                    continue
                new_lines.append(f"{k} {v}\n")
        self.logger.info(f"write_inet to file content: {new_lines}")
        await self.write_file(path=file_path, data=new_lines, lines=True)


class KVMHardWareInfoAPI(object):
    """
    KVM硬件信息
    """

    def __init__(
        self,
        settings_table: SystemSettingTable,
        log_table: LogTable,
        login_fail_msg_table: LoginFailMsgTable,
        auth_manager: AuthManager
    ):
        self.read_or_write_file = ReadOrWriteFile()
        self.settings_table = settings_table
        self.login_fail_msg_table = login_fail_msg_table
        self.logger = get_logger()
        self.cookie_auth_token = "auth_token"
        self.__auth_manager = auth_manager
        self.__log_table = log_table
        self.__user = None
        self.send_button_permission = False
        # self.ntp_thread()

    def insert_log(self, request: Request, desc: str):
        token = valid_auth_token(request.headers.get("Authorization", ""))
        user = self.__auth_manager.check(valid_auth_token(token))
        remote = request.headers.get("X-Real-IP", "")
        self.__log_table.insert_log(
            username=user,
            level=5,
            description=f"用户: [{user}] IP地址:[{remote}] [{desc}]"
        )

    async def zone_time(self, zone: str):
        """计算指定时区的当前时间"""
        if zone not in ZONE_MAP:
            return ""
        zone_info = await self.get_system_zoneinfo()
        zone_msg = ZONE_MAP.get(zone, [])
        num = zone_msg[1]

        zone_info_msg = ZONE_MAP.get(zone_info, [])
        zone_info_num = zone_info_msg[1] if zone_info_msg else 0
        datetime_now = datetime.datetime.now()
        datetime_zone = datetime_now + datetime.timedelta(hours=num - zone_info_num)
        time_string = datetime_zone.strftime("%Y-%m-%d %H:%M:%S")
        return time_string

    @staticmethod
    def ntp_thread():
        """定时执行自动同步时间的任务"""
        # if xxxxxx:
        #     return
        file_path = "/etc/ntp.conf"
        ntp_servers = []
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.readlines()
        for line in file_content:
            if not line.startswith('server'):
                continue
            line_list = [x for x in line.strip().split(' ') if x]
            if line_list[-1] == 'prefer':
                ntp_servers.insert(0, line_list[1])
                break
            ntp_servers.append(line_list[1])
            break
        if ntp_servers:
            os.system(f"ntpdate {ntp_servers[0]}")
        # threading.Timer(24 * 60 * 60, self.ntp_thread).start()

    @staticmethod
    def check_date_time(date_time: str):
        """校验时间格式是否正确，需要传入 YY-mm-dd HH:MM:DD 的格式"""
        if not date_time:
            return False
        try:
            time_strp = datetime.datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
            return time_strp
        except ValueError:
            return False

    async def get_network_info(self):
        """获取网络信息最基本的数据"""
        dns = await self.get_dns_master()
        info = {  # ip信息
            'inet': '',  # IPv4 地址
            'netmask': '',  # 子网掩码
            'broadcast': await self.__get_broadcast(),  # 网关
            'dns_master_1': dns[0] if len(dns) >= 1 else '',  # 主要DNS服务器1
            'dns_auxiliary_1': dns[1] if len(dns) >= 2 else '',  # 备用DNS服务器1
            'inet6': '',  # IPv6地址
            'prefix_len': 64  # IPv6子网络前缀长度
        }

        net_msg = psutil.net_if_addrs()
        net_info = list()
        for k, v in net_msg.items():
            if k == "lo":
                continue
            data = info.copy()
            data["ether_name"] = k
            for val in v:
                name = val.family.name
                if name == 'AF_INET':  # IPv4
                    data['inet'] = val.address  # IPv4地址
                    data['netmask'] = val.netmask  # 子网掩码
                elif name == 'AF_INET6':  # IPv6
                    inet6 = val.address.split('%')[0]
                    data['inet6'] = inet6  # IPv6地址
                    data['prefix_len'] = self.__get_prefix_len(inet6)  # IPv6地址
                elif name == 'AF_PACKET':  # mac
                    data['ether'] = val.address.replace(":", "-")  # MAC
            net_info.append(data)
        # print(net_info)
        return net_info

    async def __get_equ_name(self):
        """获取设备型号"""
        file_content = await self.read_or_write_file.read_file(path=StaticFilePath.EQU_NAME_FILE_PATH, text=True)
        return file_content.strip().replace("\x00", "")

    async def __get_mfg(self):
        """获取序列号"""
        file_content = await self.read_or_write_file.read_file(path=StaticFilePath.SN_FILE_PATH, text=True)
        return file_content.strip().replace("\x00", "")

    @staticmethod
    def __get_hostname():
        """获取主机名"""
        return socket.gethostname()

    async def __get_ip_v4(self):
        """获取IPv4地址"""
        ip_msg = await self.get_network_info()
        for data in ip_msg:
            if data["inet"] != "127.0.0.1":
                return data["inet"]
        return "127.0.0.1"

    @staticmethod
    def __get_mac():
        """获取MAC地址"""
        mac_list = []
        for k, v in psutil.net_if_addrs().items():
            if k == "lo":
                continue
            for val in v:
                if val.family.name != "AF_PACKET":
                    continue
                address = val.address
                if len(address) != 17:
                    continue
                mac_list.append(address.replace(":", "-"))
        return mac_list

    async def __get_netmask(self):
        """获取子网掩码"""
        ip_msg = await self.get_network_info()
        for data in ip_msg:
            if not data["netmask"]:
                continue
            return data["netmask"]
        return ""

    @staticmethod
    async def __get_broadcast():
        """获取网关"""
        res = subprocess.Popen(
            'routel',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True
        )
        result = res.stdout.readlines()
        gateway = ""
        for line in result:
            line_content = line.strip().decode()
            if not line_content.startswith("default"):
                continue
            contents = line_content.split(" ")
            default_line = [x.strip() for x in contents if x]
            gateway = default_line[1]
            break
        return gateway

    async def get_dns_master(self):
        """获取主要DNS服务器"""
        file_content = await self.read_or_write_file.read_file(path=StaticFilePath.DNS_FILE_PATH)
        dns = []
        for line in file_content:
            if not line.startswith('nameserver'):
                continue
            dns_msg = line.strip().split(' ')
            dns_msg = [x for x in dns_msg if x]
            dns.append(dns_msg[1])
        return dns

    def __get_net_name(self):
        """获取当前使用的网卡名称"""

    async def __get_inet6(self):
        """获取IPv6地址"""
        ip_msg = await self.get_network_info()
        for data in ip_msg:
            if len(data["inet6"]) < 14:
                continue
            return data["inet6"]
        return "::1"

    @staticmethod
    def __get_prefix_len(ipv6: str):
        """获取IPv6子网络前缀长度"""
        if ipv6 == "::1":
            return 128
        ipv6_prefix = ipv6.split("::")
        if not ipv6_prefix[0]:
            return 128
        # ipv6_mas = ipv6_prefix[0].split(":")

        return 64

    @staticmethod
    async def __get_version():
        """
        获取固件版本号
        版本号文件位置：/app/version
        如果文件不存在，或者没有内容，使用默认版本号: RccKVMD1.0.0
        """
        default_version = "RccKVMD1.0.0"
        version_msg = await get_system_version()
        return version_msg.get("version", default_version)

    async def __equ_info(self):
        equ_info = {
            "equ_info": {  # 设备信息
                "equ_name": await self.__get_equ_name(),  # 设备型号
                "MFG": await self.__get_mfg(),  # MFG#(序列号)
                "ether": self.__get_mac(),  # [MAC地址1, MAC地址2]
                "version": await self.__get_version()  # 固件版本号
            },
            "ip_info": await self.get_network_info()
        }
        return equ_info

    @staticmethod
    async def __zoneinfo_map():
        zone_info_map = {}
        for k, v in ZONE_MAP.items():
            zone_info_map[k] = v[0]
        return zone_info_map

    async def __get_network_speed(self):
        speed_nums = 0
        try:
            cmd = "ethtool eth1 | grep -i speed"
            res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            result = res.stdout.readlines()
            for line in result:
                line_content = line.decode().strip()
                if not line_content.startswith("Speed"):
                    continue
                # Speed: 100Mb/s
                speed_lines = line_content.split(":")
                speed_content = speed_lines[1]
                speed_nums_text = speed_content.strip().split("Mb/s")[0]
                speed_nums = int(speed_nums_text)
                break
        except Exception as e:
            self.logger.warning(f"system not have cmd [ethtool], if need , please install it. -> {e.__str__()}")
        return speed_nums

    @staticmethod
    async def get_system_zoneinfo():
        with open(StaticFilePath.TIMEZONE_FILE_PATH, 'r', encoding='utf-8') as f:
            zone_info = f.readline()
        return zone_info.strip()

    @staticmethod
    def get_pid(process):
        """获取进程pid"""
        cmd = "ps aux| grep '%s' | grep -v grep " % process
        out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        infos = out.stdout.read().splitlines()
        pid_list = []
        for i in infos:
            pid = i.split()[1]
            if pid not in pid_list:
                pid_list.append(int(pid.decode()))
        return pid_list

    @staticmethod
    def chose_dst():
        """读取系统当前时区是否采用夏时制"""
        return False

    async def read_file_port(self, name: str):
        """
        读取nginx文件，解析内容，获取配置的端口号
        """
        func_map = {
            # "project": self.read_or_write_file.get_project_server_port,
            "project": "",
            "http": self.read_or_write_file.get_http_port,
            "https": self.read_or_write_file.get_https_port,
            "ssh": self.read_or_write_file.get_ssh_port,
            "telnet": self.read_or_write_file.get_telnet_port
        }
        if name not in func_map:
            return None
        read_func = func_map.get(name)
        port = await read_func()
        return port

    async def read_ntp_server(self) -> dict:
        """获取时间服务器"""
        ntp_server = {}
        if not os.path.exists(StaticFilePath.NTP_FILE_PATH):
            return ntp_server
        file_content = await self.read_or_write_file.read_file(path=StaticFilePath.NTP_FILE_PATH)
        for line in file_content:
            if not line.startswith("server"):
                continue
            lines = line.strip().split(' ')
            lines = [x for x in lines if x]
            if len(lines) < 2:
                continue
            if lines[-1] == "prefer":
                ntp_server["prefer"] = lines[1]
            else:
                ntp_server["bak"] = lines[1]
        return ntp_server

    async def auto_calibration(
        self, interval: int, master_datetime_server: str = '', subsidiary_datetime_server: str = ''
    ):
        """
        配置时间自动校准
        master_datetime_server: 首选时间服务器
        subsidiary_datetime_server: 替代时间服务器
        """
        if not interval:
            return
        # 准备工作：读出ntp.conf内容，看看校准服务器是否已经添加在配置文件中
        master_datetime_server_line = f"server {master_datetime_server} prefer\n"
        subsidiary_datetime_server_line = f"server {subsidiary_datetime_server}\n"

        # 1、先将时间服务器写入ntp.conf文件中
        ntp_conf = []
        # 1.1 重新读出ntp.conf的全部内容
        file_content = await self.read_or_write_file.read_file(path=StaticFilePath.NTP_FILE_PATH)
        # 1.2 将原文件内容整理，去掉原来配置好的时间服务器
        for line in file_content:
            if not line.startswith('server'):
                ntp_conf.append(line)
            else:
                ntp_conf.append(f'# {line}')
        # 1.3 将新配置的时间服务器添加到配置文件中
        ntp_conf.append(master_datetime_server_line)
        ntp_conf.append(subsidiary_datetime_server_line)
        await self.read_or_write_file.write_file(path=StaticFilePath.NTP_FILE_PATH, data=ntp_conf, lines=True)
        # 2、添加crontab配置
        # 3、刷新crontab服务
        return

    async def update_nginx_setting(
        self, safety_info: dict,
        http_port: int = 80, https_port: int = 443,
        is_set_network: bool = True
    ):
        """
        修改Nginx配置
        """
        http_type = 1  # 1: http; 2: https
        if safety_info:
            safe_level = safety_info.get("safe_level", {})
            # "level": 0,  # 级别等级，0-自定义，1-中，2-中-高，3-高
            # "choices": [1, 3, 4, 5],  # 自定义选项，
            level_num = safe_level.get("level", 0)
            level_choices = safe_level.get("choices", [])

            if level_num == 3:  # 安全级别: 高, 只允许HTTPS
                http_type = 2
            elif level_num in [1, 2]:  # 安全级别: 中 或者 中-高，都会开启 http 和 https，默认使用 http
                pass
            elif level_num == 0:  # 安全级别: 自定义，需要看是否开启 http 和 https
                if (4 not in level_choices) and (5 not in level_choices):
                    raise HttpError("不能同时禁用HTTP和HTTPS服务", 400)
                if 4 not in level_choices:
                    http_type = 2

        if http_type == 1:
            system_cmd = f"cp {StaticFilePath.NGINX_HTTP_FILE_PATH} {StaticFilePath.NGINX_FILE_PATH}"
            os.system(system_cmd)
            if is_set_network:
                await self.read_or_write_file.write_http_port(http_port, https_port)
        else:
            system_cmd = f"cp {StaticFilePath.NGINX_HTTPS_FILE_PATH} {StaticFilePath.NGINX_FILE_PATH}"
            os.system(system_cmd)
            if is_set_network:
                await self.read_or_write_file.write_https_port(http_port, https_port)

        await update_kvm_addr(
            kvm_ip=await self.__get_ip_v4(),
            kvm_port=http_port if http_type == 1 else https_port
        )

    async def save_system_setting(self, system_name: str, data: dict) -> None:
        check_status = self.settings_table.check_setting_status(system_name=system_name)
        if check_status:
            time_settings = self.settings_table.get_setting_content(system_name=system_name)
            time_settings.update(data)
            self.settings_table.update_system_setting(
                system_name=system_name,
                content=json.dumps(data, ensure_ascii=False)
            )
            self.logger.info(f"update datetime settings {system_name} >>>>")
        else:
            self.settings_table.insert_system_setting(
                system_name=system_name,
                content=json.dumps(data, ensure_ascii=False)
            )
            self.logger.info(f"create datetime settings {system_name} >>>>")

    @exposed_http("GET", "/hardware_info/equipment")
    async def get_equipment_info(self, _: Request) -> Response:
        """
        获取设备信息
        设备信息：
            设备型号: str
            MFG#: str {序列号}
            MAC1地址: str
            MAC2地址: str
            固件版本: str
        IP信息:
            IP地址1: str
            子网掩码1: str
            网关1: str
            主要DNS服务器1: str
            备用DNS服务器1: str
            IPv6地址1: str
            IPv6子网络前缀长度1: int
            IP地址2: str
            子网掩码2: str
            ...
        """
        return make_json_response(await self.__equ_info())

    @exposed_http("POST", "/hardware_info/equipment")
    async def update_equipment_info(self, request: Request) -> Response:
        """
        修改设备信息
        """
        self.insert_log(request=request, desc="修改设备信息")
        return make_json_response()

    @exposed_http("GET", "/hardware_info/network_rates")
    async def get_network_rates(self, _: Request) -> Response:
        """获取网络适配器可选选项"""
        return make_json_response(DefaultMaps.NETWORK_RATE_MAP)

    @exposed_http("GET", "/hardware_info/network")
    async def get_network_message(self, _: Request) -> Response:
        """
        获取已经保存的网络设置信息
        Service 连接端口
            程序: int
            HTTP: int
            HTTPS: int
            SSH: int
            Telnet: int
        备援NIC: bool
        网络适配器: enum
        设定IPv4
            IP地址
                IP地址设置方式: 自动/手动
                IP地址: str
                子网掩码: str
                默认网关: str
            DNS服务器
                域名服务器地址获取方式: 自动/手动
                首选DNS服务器: str
                备用DSN服务器: str
        设定IPv6
            IP地址
                IPv6地址设置方式: 自动/手动
                IPv6地址: str
                子网络前缀长度: int
                默认网关: str
            DNS服务器
                域名服务器地址获取方式: 自动/手动
                首选DNS服务器: str
                备用DSN服务器: str
        网络数据转移率: float
        DDNS
            是否开启: bool
            主机名称: str
            DDNS: str?
            用户名: str
            密码: str?(是否密文展示)
            DDNS重试时间: float
        """
        network_info = self.settings_table.get_setting_content(SystemSettingName.NETWORK_SETTING)

        dns = await self.get_dns_master()
        # project_port = await self.read_file_port(name="project")
        http_port = await self.read_file_port(name="http")
        https_port = await self.read_file_port(name="https")
        ssh_port = await self.read_file_port(name="ssh")
        telnet_port = await self.read_file_port(name="telnet")

        if network_info:
            service = {
                # 'project': 80,
                'HTTP': int(http_port) if http_port else 80,
                'HTTPS': int(https_port) if https_port else 443,
                'SSH': int(ssh_port) if ssh_port else 22,
                'Telnet': int(telnet_port) if telnet_port else 23
            }
            network_info.update({"Service": service})
            return make_json_response(network_info)

        ipv6 = await self.__get_inet6()
        response_data = {
            'Service': {
                # 'project': 80,
                'HTTP': int(http_port) if http_port else 80,
                'HTTPS': int(https_port) if https_port else 443,
                'SSH': int(ssh_port) if ssh_port else 22,
                'Telnet': int(telnet_port) if telnet_port else 23
            },
            'NIC': False,
            'network': await self.__get_network_speed(),
            'ipv4': {
                'auto_ip': False,
                'address': await self.__get_ip_v4(),
                'netmask': await self.__get_netmask(),
                'broadcast': await self.__get_broadcast(),
                'auto_dns': False,
                'master_dns': dns[0] if len(dns) >= 1 else '',  # 首选DNS服务器
                'auxiliary_dns': dns[1] if len(dns) >= 2 else '',  # 备用DNS服务器
            },
            'ipv6': {
                'auto_ip': False,
                'address': ipv6,
                'prefix_len': self.__get_prefix_len(ipv6),
                'broadcast': await self.__get_broadcast(),
                'auto_dns': False,
                'master_dns': dns[0] if len(dns) >= 1 else '',
                'auxiliary_dns': dns[1] if len(dns) >= 2 else ''
            },
            'network_rate': 9999,
            'DDNS': {
                'status': False,
                'hostname': self.__get_hostname(),
                'ddns': '',
                'username': '',
                'password': '',
                'retry_time': 0
            }
        }
        return make_json_response(response_data)

    @exposed_http("POST", "/hardware_info/network")
    async def update_network_info(self, request: Request) -> Response:
        """
        修改网络设置信息
        """
        params = await request.json()

        service = params.get("Service", {})
        http = service.get("HTTP", "")  # HTTP端口号
        https = service.get("HTTPS", "")  # HTTPS端口号

        try:
            http_port = int(http)
            https_port = int(https)
        except Exception as e:
            self.insert_log(request=request, desc=f"修改网络设置信息失败:参数错误, {e.__str__()}")
            raise HttpError("参数错误", 400)

        # 将Service连接端口配置写入系统配置文件中
        try:
            if not os.path.exists(StaticFilePath.NGINX_INIT_PATH):
                path_list = StaticFilePath.NGINX_INIT_PATH.split("/")
                path_dir = "/".join(path_list[:-1])
                if not os.path.exists(path_dir):
                    os.mkdir(path_dir)
            safety_info = self.settings_table.get_setting_content(SystemSettingName.SAFETY_SETTING)
            await self.update_nginx_setting(
                safety_info=safety_info,
                http_port=http_port,
                https_port=https_port,
                is_set_network=True
            )

            # 保存网络ip配置信息
            await self.read_or_write_file.write_inet(params)
        except Exception as e:
            self.logger.error(f"save safety msg error: {e.__str__()}")
            self.insert_log(request=request, desc=f"修改网络设置信息失败: {e.__str__()}")
            raise ForbiddenError()

        check_status = self.settings_table.check_setting_status(system_name=SystemSettingName.NETWORK_SETTING)
        if check_status:
            self.settings_table.update_system_setting(
                system_name=SystemSettingName.NETWORK_SETTING,
                content=json.dumps(params, ensure_ascii=False)
            )
        else:
            self.settings_table.insert_system_setting(
                system_name=SystemSettingName.NETWORK_SETTING,
                content=json.dumps(params, ensure_ascii=False)
            )

        self.insert_log(request=request, desc="修改网络设置信息")
        return make_json_response({
            "code": 200,
            "msg": "设置成功，需要重启服务器生效"
        })

    @exposed_http("GET", "/hardware_info/safety_maps")
    async def get_safety_enums(self, _: Request) -> Response:
        """获取安全设置中需要做map映射的对照关系"""
        maps = {
            "safety_level_map": DefaultMaps.SAFETY_LEVEL_MAP,
            "safety_level_choice_map": DefaultMaps.SAFETY_LEVEL_CHOICE_MAP,
            "operating_mode_map": DefaultMaps.OPERATING_MODE_MAP,
            "users_mode_map": DefaultMaps.USERS_MODE_MAP,
            "tls_version_map": DefaultMaps.TLS_VERSION_MAP,
            "safety_level_high_map": DefaultMaps.SAFETY_LEVEL_HIGH_MAP,
            "safety_level_middle_high_map": DefaultMaps.SAFETY_LEVEL_MIDDLE_HIGH_MAP,
            "safety_level_middle_map": DefaultMaps.SAFETY_LEVEL_MIDDLE_MAP,
        }
        return make_json_response(maps)

    @exposed_http("GET", "/hardware_info/safety")
    async def get_safety_info(self, _: Request) -> Response:
        """
        获取已经保存的安全设置信息

        登录失败
            是否开启: bool
            允许: int {单位：次}
            超时登出: int {单位：分}
            锁定客户端PC: bool
            锁定账号: bool
        过滤
            允许IP过滤: list[str, str, str ...]
            IP过滤是否包括: bool
            登录字符串: str
            允许MAC过滤: list[str, str, str ...]
            MAC过滤是否包括: bool
        安全级别
            级别: enum
            自定义: list[bool, bool, bool, ...]
        工作模式: list[int, int, ...]
        多用户模式:
            多用户模式: enum
            超时注销: int {单位秒，0-255秒}
        """
        lock_macs = self.login_fail_msg_table.get_many_client_login_fail_msg()
        safety_info = self.settings_table.get_setting_content(SystemSettingName.SAFETY_SETTING)
        if safety_info:
            operating_mode = safety_info.get("operating_mode", [])
            if 2 not in operating_mode:
                safety_info["users_mode"]["users_mode"] = 1
            macs = safety_info.get("filter", {}).get("macs", [])
            new_macs = [x.lower() for x in macs]
            for mac_msg in lock_macs:
                mac = mac_msg.get("user_addr", "")
                if mac and (mac not in macs):
                    new_macs.append(mac.lower())
            safety_info["filter"]["macs"] = new_macs
            return make_json_response(safety_info)
        response_data = {
            "login_fail": {  # 登录失败
                "open": False,  # 是否开启
                "recycle": 0,  # 允许失败次数
                "timeout": 0,  # 超时登出
                "lock_client": False,  # 锁定客户端PC
                "lock_account": False  # 锁定账号
            },
            "filter": {  # 过滤
                "filter_ip": False,  # 允许过滤IP
                "ip_include": False,  # 包括/不包括
                "ips": [],  # 过滤的IP
                "login_str": "",  # 登录字符串
                "filter_mac": False,  # 允许过滤MAC
                "mac_include": False,  # 包括/不包括
                "macs": [x["user_addr"].lower() for x in lock_macs if x.get("user_addr")]  # 过滤的MAC地址
            },
            "safe_level": {  # 安全级别
                "level": 0,  # 级别等级，0-自定义，1-中，2-中-高，3-高
                "choices": [1, 3, 4, 5],  # 自定义选项，
                "tls_version": 1
            },
            "operating_mode": [2],  # 工作模式
            "users_mode": {  # 多用户模式
                "users_mode": 1,  # 多用户模式
                # "timeout": 0  # 超时注销
            }
        }
        return make_json_response(response_data)

    @exposed_http("POST", "/hardware_info/safety")
    async def update_safety_info(self, request: Request) -> Response:
        """
        保存安全设置信息
        """
        params = await request.json()

        login_fail = params.get("login_fail", {})
        # login_fail_open = login_fail.get("open", False)
        recycle = login_fail.get("recycle", 0)
        timeout = login_fail.get("timeout", 0)

        operating_mode = params.get("operating_mode", [])
        safe_level = params.get("safe_level", {})
        safe_level_level = safe_level.get("level", 0)
        safe_level_choices = safe_level.get("choices", [])

        users_mode = params.get("users_mode", {})
        users_mode_num = users_mode.get("users_mode")
        try:
            # 参数类型转换：将前端传入的字符串类型的数字强转为数字
            login_fail["recycle"] = int(recycle)
            login_fail["timeout"] = int(timeout)
            new_operating_mode = []
            for operating in operating_mode:
                new_operating_mode.append(int(operating))
            if 2 in new_operating_mode:
                users_mode["users_mode"] = int(users_mode_num)
            else:
                users_mode["users_mode"] = 1
            params["operating_mode"] = new_operating_mode
            safe_level["level"] = int(safe_level_level)
            safe_level["safe_level_choices"] = [int(new_level) for new_level in safe_level_choices]
        except ValueError:
            raise HttpError("参数错误", 400)

        # 更新全局多用户模式变量，只有在发生变化的时候才更新并推送消息
        old_user_mode = RequestMsgControl.USERS_MODE
        new_user_mode = users_mode["users_mode"]
        if old_user_mode != new_user_mode:
            RequestMsgControl.USERS_MODE = users_mode["users_mode"]
            self.send_button_permission = True

        # 更新锁定信息
        login_fail_open = login_fail.get("open", False)
        if login_fail_open:
            lock_client = login_fail.get("lock_client", False)
            lock_account = login_fail.get("lock_account", False)
        else:
            lock_client, lock_account = False, False
        if not lock_client:
            self.login_fail_msg_table.update_all_login_fail_msg(update_type=2)
        if not lock_account:
            self.login_fail_msg_table.update_all_login_fail_msg(update_type=1)

        # 解锁客户端PC
        filter_data = params.get("filter", dict())
        filter_mac = filter_data.get("filter_mac", False)
        mac_include = filter_data.get("mac_include", False)
        macs = filter_data.get("macs", [])
        macs_lower = [x.lower() for x in macs]
        params["filter"]["macs"] = macs_lower
        if not filter_mac:
            macs_lower = []
        self.login_fail_msg_table.update_many_client_login_fail_msg(
            filter_macs=macs_lower, mac_include=mac_include
        )

        # 更新Nginx配置
        http_port = await self.read_or_write_file.get_http_port()
        https_port = await self.read_or_write_file.get_https_port()
        await self.update_nginx_setting(
            safety_info=params,
            http_port=http_port,
            https_port=https_port,
            is_set_network=False
        )
        check_status = self.settings_table.check_setting_status(system_name=SystemSettingName.SAFETY_SETTING)
        if check_status:
            self.settings_table.update_system_setting(
                system_name=SystemSettingName.SAFETY_SETTING,
                content=json.dumps(params, ensure_ascii=False)
            )
            self.logger.info(f"update safety settings {SystemSettingName.SAFETY_SETTING} >>>>")
        else:
            self.settings_table.insert_system_setting(
                system_name=SystemSettingName.SAFETY_SETTING,
                content=json.dumps(params, ensure_ascii=False)
            )
            self.logger.info(f"create safety settings {SystemSettingName.SAFETY_SETTING} >>>>")
        self.insert_log(request=request, desc="保存安全设置信息")
        return make_json_response()

    @exposed_http("GET", "/hardware_info/zoneinfo_map")
    async def get_zoneinfo_map(self, _: Request) -> Response:
        """获取时区对照表，暂时还没实现时区对中文的翻译"""
        return make_json_response(await self.__zoneinfo_map())

    @exposed_http("GET", "/hardware_info/ntp_servers")
    async def get_net_servers(self, _: Request) -> Response:
        """获取时间服务器"""
        return make_json_response({'net_servers': NTP_SERVERS})

    @exposed_http("GET", "/hardware_info/get_zone_time")
    async def get_zone_time(self, request: Request) -> Response:
        """获取指定时区的当前时间"""
        params = request.query
        zone_info = params.get('zone_info', None)
        service_zone_infos = await self.__zoneinfo_map()
        if zone_info not in service_zone_infos:
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            time = datetime.datetime.now().strftime("%H:%M:%S")
        else:
            date_time = await self.zone_time(zone=zone_info)
            date, time = date_time.split(" ")
        return make_json_response({"date": date, "time": time})

    @exposed_http("POST", "/hardware_info/zoneinfo")
    async def set_zoneinfo(self, request: Request) -> Response:
        """设置系统时区，将前端传入的时区匹配出时区绝对路径，然后将时区创建软连接，最后修改时区文件中的内容"""
        params = await request.json()
        save_zone_info = params.get('zone_info', None)
        service_zone_infos = await self.__zoneinfo_map()
        if save_zone_info not in service_zone_infos:
            self.insert_log(request=request, desc="设置系统时区失败: 参数错误")
            raise HttpError("参数错误", 400)
        # 创建时区软连接
        zone_info_path = f'/usr/share/zoneinfo/{save_zone_info}'
        os.system(f'ln -sf {zone_info_path} /etc/localtime')

        # 获取传入时区对应的时间
        date_time = await self.zone_time(save_zone_info)
        # 将时间同步到系统中
        os.system(f"date -s '{date_time}'")
        # 将系统时间同步到硬件时间中
        os.system("hwclock --systohc")
        self.insert_log(request=request, desc="保存时间设置信息成功")

        # 修改时区配置文件
        with open(StaticFilePath.TIMEZONE_FILE_PATH, 'w', encoding='utf-8') as f:
            f.write(save_zone_info)
        self.insert_log(request=request, desc="设置系统时区成功")
        return make_json_response({'zone_info': save_zone_info})

    @exposed_http("POST", "/hardware_info/dst")
    async def set_dst(self, request: Request) -> Response:
        """修改夏令时，只有在支持夏令时的时区设置才有效"""
        params = await request.json()
        dst = params.get('dst', False)
        if not isinstance(dst, bool):
            self.insert_log(request=request, desc="修改夏令时失败: 参数类型错误")
            raise HttpError("参数类型错误", 400)
        # #######################
        # 在这里实现修改夏令时
        await self.save_system_setting(
            system_name=SystemSettingName.TIME_SETTING,
            data=params
        )
        # #######################
        self.insert_log(request=request, desc="修改夏令时成功")
        return make_json_response({'dst': dst})

    @exposed_http("GET", "/hardware_info/datetime")
    async def get_datetime_info(self, _: Request) -> Response:
        """
        获取已经保存的时间设置信息

        时区: enum
        夏时制: bool
        日期: date
        时间: datetime
        网络时间
            启用自动校准: bool
            首选时间服务器: enum
            主要客制服务器IP: str
            是否使用替代时间服务器: bool
            替代时间服务器: enum
            替代客制时间服务器IP: str
            校准时间间隔: float
        """
        zone_info = await self.get_system_zoneinfo()
        ntp_server = await self.read_ntp_server()
        time_settings = self.settings_table.get_setting_content(system_name=SystemSettingName.TIME_SETTING)
        network_datetime = time_settings.get("network_datetime")
        if not network_datetime:
            network_datetime = {
                'auto_calibration': True,
                'master_datetime_server': ntp_server.get("prefer", ""),
                'master_server_ip': [False, None],
                'subsidiary_server_status': False,
                'subsidiary_datetime_server': ntp_server.get("bak", ""),
                'subsidiary_server_ip': [False, None],
                'auto_calibration_interval': 1
            }
        datetime_info = {
            'zone_info': zone_info,
            'dst': time_settings.get("dst", False),
            'date': datetime.datetime.now().strftime('%Y-%m-%d'),
            'time': datetime.datetime.now().strftime('%H:%M:%S'),
            'network_datetime': network_datetime
        }
        return make_json_response(datetime_info)

    @exposed_http("POST", "/hardware_info/datetime")
    async def update_datetime_info(self, request: Request) -> Response:
        """
        保存时间设置信息
        """
        params = await request.json()
        date_time = params.get('date_time', None)
        if not date_time:
            self.insert_log(request=request, desc="保存时间设置信息失败: 参数缺失")
            return make_json_response()
        if not self.check_date_time(date_time):  # 时间格式错误
            self.insert_log(request=request, desc="保存时间设置信息失败: 时间格式错误")
            raise HttpError("时间格式错误", 400)
        os.system(f"date -s '{date_time}'")
        # 将系统时间同步到硬件时间中
        os.system("hwclock --systohc")
        self.insert_log(request=request, desc="保存时间设置信息成功")
        return make_json_response(
            {
                "receive": date_time,
                "response": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        )

    @exposed_http("POST", "/hardware_info/calibration")
    async def calibration_date_time(self, request: Request) -> Response:
        """校准时间"""
        params = await request.json()
        auto_calibration = params.get('auto_calibration', False)
        master_datetime_server = params.get('master_datetime_server', None)  # 首选时间服务器
        subsidiary_server_status = params.get('subsidiary_server_status', False)  # 是否使用替代时间服务器
        subsidiary_datetime_server = params.get('subsidiary_datetime_server', None)  # 替代时间服务器
        auto_calibration_interval = params.get('auto_calibration_interval', 0)  # 自动校准时间间隔

        # 如果不需要使用自动校准，那么也不需要再去开启 ntp 服务了
        if not auto_calibration:
            self.insert_log(request=request, desc="时间校准失败: 未开启自动校准")
            return make_json_response()

        # 如果首选时间服务器和替代时间服务器都没有的时候，报错返回
        # 因为这个时候是要进行自动同步的，如果都没填，无法进行同步
        if not any([master_datetime_server, subsidiary_datetime_server]):
            self.insert_log(request=request, desc="时间校准失败: 未选择时间服务器")
            raise HttpError("未选择时间服务器", 400)

        # 选了勾选了启用替代时间服务器，就必选选择替代时间服务器
        if subsidiary_server_status and not subsidiary_datetime_server:
            self.insert_log(request=request, desc="时间校准失败: 参数缺失")
            raise HttpError("参数缺失", 400)

        if master_datetime_server and master_datetime_server not in NTP_SERVERS:
            self.insert_log(request=request, desc="时间校准失败: 参数错误")
            raise HttpError("参数错误", 400)

        if subsidiary_datetime_server and subsidiary_datetime_server not in NTP_SERVERS:
            self.insert_log(request=request, desc="时间校准失败: 参数错误")
            raise HttpError("参数错误", 400)

        # 执行命令之前，先将停掉ntp服务，手动同步完成之后再将ntp服务开启
        if master_datetime_server:
            cmd = f"ntpdate {master_datetime_server}"  # 当有首选时间服务器的时候，同步首选时间服务器
        else:
            cmd = f"ntpdate {subsidiary_datetime_server}"  # 当没有首选时间服务器的时候，同步替代时间服务器

        # 这几个命令比较耗时，如果与主程序同步执行，该接口响应时间很长
        # 这里放到另外的线程中去执行，不占用主程序的时间

        def system_cmd():
            os.system("systemctl stop ntp")
            os.system(cmd)
            os.system("hwclock --systohc")
            # 启用自动校准，先开启 ntp 服务
            os.system("systemctl start ntp")

        t = threading.Thread(target=system_cmd, args=())
        t.start()

        try:
            auto_calibration_interval = int(auto_calibration_interval)
        except ValueError:
            self.insert_log(request=request, desc="时间校准失败: 参数数据类型错误")
            raise ForbiddenError()
        await self.auto_calibration(
            interval=auto_calibration_interval,
            master_datetime_server=master_datetime_server,
            subsidiary_datetime_server=subsidiary_datetime_server
        )

        table_params = {"network_datetime": params}
        await self.save_system_setting(
            system_name=SystemSettingName.TIME_SETTING,
            data=table_params
        )
        self.insert_log(request=request, desc="校准时间成功")
        return make_json_response()

    @exposed_http("GET", "/hardware_info/get_settings")
    async def get_all_settings(self, _: Request) -> Response:
        response = {}
        for name in [SystemSettingName.TIME_SETTING, SystemSettingName.NETWORK_SETTING,
                     SystemSettingName.SAFETY_SETTING]:
            content = self.settings_table.get_setting_content(system_name=name)
            if not content:
                continue
            response[name] = content
        return make_json_response(response)
