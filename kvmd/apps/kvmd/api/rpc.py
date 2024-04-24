#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@File    : rpc.py
@version : V0.0.1
@Time    : 2023-02-10 10:52:58
@Desc    :
"""

import time
import traceback
from typing import Callable

from ....htserver import exposed_rpc
from ....logging import get_logger
from ....mouse import MouseRange
from ....plugins.hid import BaseHid
from ....validators.basic import valid_bool
from ....validators.hid import valid_hid_key
from ....validators.hid import valid_hid_mouse_button
from ....validators.hid import valid_hid_mouse_delta
from ....validators.hid import valid_hid_mouse_move


class RPCServerApi(object):
    DEF_WIDTH, DEF_HEIGHT = 1920, 1080

    def __init__(
            self, hid: BaseHid, ignore_keys: list[str],
            mouse_x_range: tuple[int, int],
            mouse_y_range: tuple[int, int]):
        self.__hid = hid
        self._logger = get_logger(0)
        self.__ignore_keys = ignore_keys
        self.__mouse_x_range = mouse_x_range
        self.__mouse_y_range = mouse_y_range

    def __process_delta(
            self, event: dict, handler: Callable[[int, int], None]) -> None:
        try:
            raw_delta = event["delta"]
            deltas = [
                (valid_hid_mouse_delta(delta["x"]),
                 valid_hid_mouse_delta(delta["y"]))
                for delta in
                (raw_delta if isinstance(raw_delta, list) else [raw_delta])
            ]
            squash = valid_bool(event.get("squash", False))
        except Exception as e:
            self._logger.error(
                f"Error message: {e}\n, %s", traceback.print_exc())
            return
        if squash:
            prev = (0, 0)
            for cur in deltas:
                if abs(prev[0] + cur[0]) > 127 or abs(prev[1] + cur[1]) > 127:
                    handler(*prev)
                    prev = cur
                else:
                    prev = (prev[0] + cur[0], prev[1] + cur[1])
            if prev[0] or prev[1]:
                handler(*prev)
        else:
            for xy in deltas:
                handler(*xy)

    def __send_mouse_move_event(self, to_x: int, to_y: int) -> None:
        if self.__mouse_x_range != MouseRange.RANGE:
            to_x = MouseRange.remap(to_x, *self.__mouse_x_range)
        if self.__mouse_y_range != MouseRange.RANGE:
            to_y = MouseRange.remap(to_y, *self.__mouse_y_range)
        self.__hid.send_mouse_move_event(to_x, to_y)

    @exposed_rpc("mouse_move")
    async def mouse_on_move(self, event: dict):
        # 过滤数据，解决鼠标托送延迟问题
        self._logger.debug(
            f"Mouse move event: {event}, event_time={time.time()}")
        try:
            event_ = event.get("event")
            if not event_:
                return
            to_move = event_["to"]
            to_x = valid_hid_mouse_move(to_move.get("x", 0))
            to_y = valid_hid_mouse_move(to_move.get("y", 0))
        except Exception as e:
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())
            return {"errmsg": e}
        self.__send_mouse_move_event(to_x, to_y)

    @exposed_rpc("mouse_button")
    async def mouse_on_click(self, event: dict):
        self._logger.debug(
            f"Mouse Click event: {event}, event_time={time.time()}")
        try:
            event_ = event.get("event")
            if not event_:
                return
            button = valid_hid_mouse_button(event_["button"])
            state = valid_bool(event_["state"])
            self.__hid.send_mouse_button_event(button, state)
        except Exception as e:
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())

    @exposed_rpc("mouse_wheel")
    async def mouse_on_scroll(self, event: dict):
        self._logger.debug(
            f"Mouse scroll event: {event}, event_time={time.time()}")
        try:
            scroll_event = event.get("event")
            if not scroll_event:
                return
            self.__process_delta(
                scroll_event, self.__hid.send_mouse_wheel_event)
        except Exception as e:
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())
            return {"errmsg": e}

    @exposed_rpc("key")
    async def keyboard_event(self, event: dict):
        self._logger.debug(
            f"Keyboard event: {event}, event_time={time.time()}")
        try:
            event_ = event.get("event")
            if not event_:
                return

            key = valid_hid_key(event_["key"])
            state = valid_bool(event_["state"])
        except Exception as e:
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())
            return {"errmsg": e}
        if key not in self.__ignore_keys:
            self.__hid.send_key_events([(key, state)])

    @exposed_rpc("mouse_relative")
    async def mouse_on_relative(self, event: dict) -> \
            dict[str, Exception] | None:
        self._logger.debug(
            f"Keyboard event: {event}, event_time={time.time()}")
        try:
            event_ = event.get("event")
            if not event_:
                return

            to_move = event_["to"]
            to_x = valid_hid_mouse_move(to_move.get("x", 0))
            to_y = valid_hid_mouse_move(to_move.get("y", 0))

        except Exception as e:
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())
            return {"errmsg": e}

        self.__hid.send_mouse_relative_event(delta_x=to_x, delta_y=to_y)
