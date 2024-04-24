#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import traceback

# here put the import lib
import aiohttp
from urllib.parse import urljoin

from .table import LogTable
from .check import UpgradeInfo
from .check import PlatformSettings

from ...logging import get_logger

logger = get_logger(0)

sqlite_path = "/etc/kvmd/sqlite.db"

log_table = LogTable(sqlite_path)


def get_check_url(uri):
    settings = PlatformSettings()
    base_url = "{protocol}://{addr}:{port}/".format(
        protocol=settings.get_protocol,
        addr=settings.get_ip, port=settings.get_port)
    return urljoin(base_url, uri)


async def record_log(status: int, down_status: int = 1) -> int:
    """
    level:
        0:DEBUG
        5:INFO
        10:WARNING
        15:ERROR

    POST /api/equipment/kvm/kvm_upgrade_record

    :param down_status:
        0:failed
        1:success
    :param status:
        0:failed
        1:success
    :return: int
    """
    infos = UpgradeInfo().read()
    primary_id = infos["primary_id"]
    if primary_id is None:
        await save_upgrade_record(
            upgrade_result=status,
            download_result=down_status,
            kvm_ip=infos["ip"],
            version=infos["version"],
        )
    else:
        await put_upgrade_record_upgrade(
            primary_id=infos["primary_id"], upgrade_result=status)
    try:
        if status:
            description = "用户：{0}升级{1}版本的包成功".format(
                infos["username"], infos["version"])
            level = 5
        else:
            description = "用户：{0}升级{1}版本的包失败".format(
                infos["username"], infos["version"])
            level = 15
        log_table.insert_log(
            username=infos["username"],
            level=level,
            description=description)
    except Exception as e:
        print(e)
        logger.error(traceback.format_exc())

    return 1


async def save_upgrade_record(
    kvm_ip: str,
    version: str,
    upgrade_result: int = 2,
    download_result: int = 2,
):
    """
    POST /api/equipment/kvm/kvm_upgrade_record

    :param upgrade_result:
        0:failed
        1:success
        2:wait
    :param download_result:
        0:failed
        1:success
        2:un download
    :param kvm_ip:
    :param version:
    :return:
    """
    try:
        report_uri = "/api/equipment/kvm/kvm_upgrade_record"
        report_url = get_check_url(report_uri)
        async with aiohttp.ClientSession() as session:
            record = dict(
                upgrade_result=upgrade_result,
                download_result=download_result,
                kvm_ip=kvm_ip,
                version=version,
            )
            async with session.post(url=report_url, json=record) as resp:
                if resp.status == 200:
                    logger.info("升级日志上报成功")
                    data = await resp.json()
                    return data["data"]["id"]
    except Exception as e:
        print(e)
        logger.error(traceback.format_exc())


async def put_upgrade_record_download(primary_id: int, download_result: int):
    """
        PUT /api/equipment/kvm/kvm_upgrade_record/{primary_id}/download

    :param primary_id:
    :param download_result:
    :return:
    """
    try:
        report_uri = f"/api/equipment/kvm/kvm_upgrade_record/{primary_id}/download"
        report_url = get_check_url(report_uri)
        async with aiohttp.ClientSession() as session:
            data = dict(
                download_result=download_result,
            )
            async with session.put(url=report_url, json=data) as resp:
                if resp.status == 200:
                    logger.info("升级日志更新成功-下载")
    except Exception as e:
        print(e)
        logger.error(traceback.format_exc())


async def put_upgrade_record_upgrade(primary_id: int, upgrade_result: int):
    """
        PUT /api/equipment/kvm/kvm_upgrade_record/{primary_id}/upgrade

    :param primary_id:
    :param upgrade_result:
    :return:
    """
    try:
        report_uri = f"/api/equipment/kvm/kvm_upgrade_record/{primary_id}/upgrade"
        report_url = get_check_url(report_uri)
        async with aiohttp.ClientSession() as session:
            data = dict(
                upgrade_result=upgrade_result,
            )
            async with session.put(url=report_url, json=data) as resp:
                if resp.status == 200:
                    logger.info("升级日志更新成功-升级")
    except Exception as e:
        print(e)
        logger.error(traceback.format_exc())


async def update_kvm_addr(kvm_ip: str, kvm_port: int):
    """
    修改RCC配置的KVM端口
    POST /api/equipment/kvm/update_port

    :param kvm_ip: 当前kvm的ip地址
    :param kvm_port: 当前系统使用的端口号
    :return:
    """
    try:
        report_uri = f"/api/equipment/kvm/update_port"
        report_url = get_check_url(report_uri)
        async with aiohttp.ClientSession() as session:
            data = dict(
                kvm_ip=kvm_ip,
                kvm_port=kvm_port,
            )
            async with session.post(url=report_url, json=data) as resp:
                if resp.status == 200:
                    logger.info(f"更新RCC: {report_url} 配置的KVM: {kvm_ip} 端口号:{kvm_port} 成功")
                else:
                    logger.error(f"更新RCC: {report_url} 配置的KVM: {kvm_ip} 端口号:{kvm_port} 失败，{await resp.text()}")
    except Exception as e:
        print(e)
        logger.error(traceback.format_exc())
