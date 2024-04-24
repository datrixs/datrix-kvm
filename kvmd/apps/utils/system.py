import os
import configparser

from .common import *
from ...htserver import set_value


async def get_system_version():
    """
    获取系统固件版本号
    """
    version = {"version": DEFAULT_VERSION}
    if not os.path.exists(APP_VER_PATH):
        return version
    with open(APP_VER_PATH, "r") as fp:
        cur_version = fp.readline()
    if cur_version:
        version["version"] = cur_version.strip()
    return version


def get_settings() -> dict:
    """
    获取RCC平台请求地址
    """
    if not os.path.exists(RCC_SERVER_SETTINGS):
        return dict(
            addr="127.0.0.1",
            port=80,
            protocol="http"
        )

    settings = configparser.ConfigParser()
    settings.read(RCC_SERVER_SETTINGS)
    return dict(
        addr=settings.get("platform", "addr"),
        protocol=settings.get("platform", "protocol"),
        port=settings.getint("platform", "port")
    )


def reset_settings(data: dict):
    """
    设置RCC平台请求地址
    """
    protocol = data.get("protocol", "")
    addr = data.get("addr", "")
    port = str(data.get("port", ""))
    if not all([protocol, addr, port]):
        raise Exception("rcc地址不正确")
    config = configparser.ConfigParser()
    if not os.path.exists(RCC_SERVER_SETTINGS):
        config["platform"] = {
            "addr": addr,
            "port": port,
            "protocol": protocol
        }
    else:
        config.read(RCC_SERVER_SETTINGS)
        if config.has_section("platform"):
            config.set("platform", "addr", addr)
            config.set("platform", "port", port)
            config.set("platform", "protocol", protocol)
        else:
            config.add_section("platform")
            config.set("platform", "addr", addr)
            config.set("platform", "port", port)
            config.set("platform", "protocol", protocol)

    with open(RCC_SERVER_SETTINGS, "w") as fp:
        config.write(fp)

    # # 更新前端JS文件
    # rcc_addr = f"{protocol}://{addr}:{port}"
    # set_value(filepath=SETTINGS_FILE, key=RCC_BASE_URL, new_value=rcc_addr)
