#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import atexit
import ctypes.util
import os
import re
import struct
import time
import traceback
from collections import namedtuple, defaultdict
from concurrent.futures import ThreadPoolExecutor
from ctypes import c_uint32, c_uint, c_int, c_void_p, byref
from dataclasses import dataclass
from glob import glob
from subprocess import check_output
from time import time as now

from jsonrpclib import Server

try:
    from queue import Queue
except ImportError:
    from Queue import Queue

from ._constants import AT1_TO_LOCAL
from ._constants import BTN_LEFT, BTN_RIGHT, BTN_SIDE, BTN_MIDDLE, BTN_EXTRA
from ._constants import EV_SYN, EV_MSC, DOWN, UP, EV_REL
from ._constants import LEFT, RIGHT, MIDDLE, X, X2, KEY_UP, EV_KEY
from ._constants import KEY_DOWN, REL_WHEEL, ABS_X, ABS_Y
from ._canonical_names import normalize_name, all_modifiers
from ...logging import get_logger

event_bin_format = "llHHI"
DeviceDescription = namedtuple(
    'DeviceDescription', 'event_file is_mouse is_keyboard')
device_pattern = r"""N: Name="([^"]+?)".+?H: Handlers=([^\n]+)"""
event_state = {"down": True, "double": True, "up": False}
display, window, x11 = None, None, None
to_name = defaultdict(list)
from_name = defaultdict(list)
keypad_scan_codes = set()
pressed_modifiers = set()

ButtonEvent = namedtuple('ButtonEvent', ['event_type', 'button', 'times'])
WheelEvent = namedtuple('WheelEvent', ['delta', 'times'])
MoveEvent = namedtuple('MoveEvent', ['x', 'y', 'times'])
button_code = {
    BTN_LEFT: LEFT,
    BTN_RIGHT: RIGHT,
    BTN_MIDDLE: MIDDLE,
    BTN_SIDE: X,
    BTN_EXTRA: X2,
}


def ensure_root():
    if os.geteuid() != 0:
        raise ImportError('You must be root to use this library on linux.')


def build_display():
    global display, window, x11
    if display and window and x11: return
    x11 = ctypes.cdll.LoadLibrary(ctypes.util.find_library('X11'))
    # Required because we will have multiple threads calling x11,
    # such as the listener thread and then main using "move_to".
    x11.XInitThreads()
    # Explicitly set XOpenDisplay.restype to avoid segfault on 64 bit OS.
    # http://stackoverflow.com/questions/35137007/get-mouse-position-on-linux-pure-python
    x11.XOpenDisplay.restype = c_void_p
    display = c_void_p(x11.XOpenDisplay(0))
    window = x11.XDefaultRootWindow(display)


def get_position():
    build_display()
    root_id, child_id = c_void_p(), c_void_p()
    root_x, root_y, win_x, win_y = c_int(), c_int(), c_int(), c_int()
    mask = c_uint()
    x11.XQueryPointer(
        display, c_uint32(window), byref(root_id),
        byref(child_id), byref(root_x), byref(root_y),
        byref(win_x), byref(win_y), byref(mask))
    return root_x.value, root_y.value


def register_key(key_and_modifiers, name):
    if name not in to_name[key_and_modifiers]:
        to_name[key_and_modifiers].append(name)
    if key_and_modifiers not in from_name[name]:
        from_name[name].append(key_and_modifiers)


def cleanup_key(name):
    """ Formats a dumpkeys format to our standard. """
    name = name.lstrip('+')
    is_keypad = name.startswith('KP_')
    for mod in ('Meta_', 'Control_', 'dead_', 'KP_'):
        if name.startswith(mod):
            name = name[len(mod):]

    # Dumpkeys is weird like that.
    if name == 'Remove':
        name = 'Delete'
    elif name == 'Delete':
        name = 'Backspace'

    if name.endswith('_r'):
        name = 'right ' + name[:-2]
    if name.endswith('_l'):
        name = 'left ' + name[:-2]

    return normalize_name(name), is_keypad


def build_tables():
    if to_name and from_name: return
    ensure_root()

    modifiers_bits = {
        'shift': 1,
        'alt gr': 2,
        'ctrl': 4,
        'alt': 8,
    }
    keycode_template = r'^keycode\s+(\d+)\s+=(.*?)$'
    dump = check_output(['dumpkeys', '--keys-only'], universal_newlines=True)
    for str_scan_code, str_names in re.findall(
            keycode_template, dump, re.MULTILINE):
        scan_code = int(str_scan_code)
        for i, str_name in enumerate(str_names.strip().split()):
            modifiers = tuple(sorted(
                modifier for modifier, bit in modifiers_bits.items() if
                i & bit))
            name, is_keypad = cleanup_key(str_name)
            register_key((scan_code, modifiers), name)
            if is_keypad:
                keypad_scan_codes.add(scan_code)
                register_key((scan_code, modifiers), 'keypad ' + name)

    # dumpkeys consistently misreports the Windows key, sometimes
    # skipping it completely or reporting as 'alt. 125 = left win,
    # 126 = right win.
    if (125, ()) not in to_name or to_name[(125, ())] == 'alt':
        register_key((125, ()), 'windows')
    if (126, ()) not in to_name or to_name[(126, ())] == 'alt':
        register_key((126, ()), 'windows')

    # The menu key is usually skipped altogether, so we also add it manually.
    if (127, ()) not in to_name:
        register_key((127, ()), 'menu')

    synonyms_template = r'^(\S+)\s+for (.+)$'
    dump = check_output(['dumpkeys', '--long-info'], universal_newlines=True)
    for synonym_str, original_str in re.findall(
            synonyms_template, dump, re.MULTILINE):
        synonym, _ = cleanup_key(synonym_str)
        original, _ = cleanup_key(original_str)
        if synonym != original:
            from_name[original].extend(from_name[synonym])
            from_name[synonym].extend(from_name[original])


@dataclass(frozen=True)
class KeyboardEvent:
    event_type: str
    scan_code: int
    name: str
    times: float
    device: str
    modifiers: tuple
    is_keypad: bool


class EventDevice(object):
    def __init__(self, path=None):
        self.path = path
        self._input_file = None
        self._output_file = None

    @property
    def input_file(self):
        if self._input_file is None:
            try:
                self._input_file = open(file=self.path, mode="rb")
            except IOError as e:
                if e.strerror == 'Permission denied':
                    print(
                        'Permission denied ({}). You must be '
                        'sudo to access global events.'.format(self.path))
                    exit()

            def try_close():
                try:
                    self._input_file.close
                except Exception as ex:
                    print(ex)

            atexit.register(try_close)
        return self._input_file

    @property
    def output_file(self):
        if self._output_file is None:
            self._output_file = open(self.path, 'wb')
            atexit.register(self._output_file.close)
        return self._output_file

    def read_event(self):
        try:
            data = self.input_file.read(struct.calcsize(event_bin_format))
        except OSError as e:
            raise OSError(e)
        seconds, microseconds, event_type, code, value = struct.unpack(
            event_bin_format, data)
        return seconds + microseconds / 1e6, event_type, code, value, self.path

    def write_event(self, event_type, code, value):
        integer, fraction = divmod(now(), 1)
        seconds = int(integer)
        microseconds = int(fraction * 1e6)
        data_event = struct.pack(
            event_bin_format, seconds, microseconds, event_type, code, value)

        # Send a sync event to ensure other programs update.
        sync_event = struct.pack(
            event_bin_format, seconds, microseconds, EV_SYN, 0, 0)

        self.output_file.write(data_event + sync_event)
        self.output_file.flush()


class KbdEventDevice(EventDevice):
    def __init__(self, path: str, threads: set, logger, rpc_cli: Server):
        super(KbdEventDevice, self).__init__(path=path)
        self._threads = threads
        self._logger = logger
        self._rpc_cli = rpc_cli

    def event_handler(self):
        while True:
            try:
                times, key_type, code, value, device_id = self.read_event()
                # 当返回值都为None是否，说明设备驱动被移除（设备已拔出）

                if key_type != EV_KEY:
                    continue

                event_type = KEY_DOWN if value else KEY_UP  # 0 = UP, 1 = DOWN, 2 = HOLD
                pressed_modifiers_tuple = tuple(sorted(pressed_modifiers))
                names = to_name[(code, pressed_modifiers_tuple)
                        ] or to_name[(code, ())] or ['unknown']
                name = names[0]

                if name in all_modifiers:
                    continue
                if event_type == KEY_DOWN:
                    pressed_modifiers.add(name)
                else:
                    pressed_modifiers.discard(name)

                is_keypad = code in keypad_scan_codes

                event = KeyboardEvent(
                    event_type=event_type,
                    scan_code=code,
                    name=normalize_name(name),
                    times=times,
                    device=device_id,
                    is_keypad=is_keypad,
                    modifiers=pressed_modifiers_tuple)

                if event is None:
                    continue

                self._on_key(event)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print("Error: Device ({}), {}".format(self.path, e))
        print(
            "Device ({}), The device listen thread will down".format(self.path))
        self._threads.remove(self.path)

    def _on_key(self, event: KeyboardEvent) -> None:
        key = AT1_TO_LOCAL.get(event.scan_code)
        state = event_state.get(event.event_type)
        try:
            event_ = {
                "event_type": "key",
                "event": {
                    "key": key,
                    "state": state
                }
            }
            self._rpc_cli.keyboard_event(event_)
        except Exception as e:
            self._logger.error(
                f"Error message: {e}\n, %s", traceback.print_exc())


class MouseEventDevice(EventDevice):
    pos_x, pos_y, last_x, last_y = 0, 0, 0, 0
    _CONST_SIZE, _ZERO, _counter = 6, 1, 0

    def __init__(self, path: str, threads: set, logger, rpc_cli: Server,
                 mode: bool = False, height: int = 1080, width: int = 1920):
        super(MouseEventDevice, self).__init__(path=path)
        self._threads = threads
        self._logger = logger
        self._rpc_cli = rpc_cli
        self._mouse_mode = mode
        self._height = height
        self._width = width

    def event_handler(self):
        while True:
            try:
                times, key_type, code, value, device_id = self.read_event()
                if key_type == EV_SYN or key_type == EV_MSC:
                    continue

                event = None
                # 整合鼠标事件数据
                if key_type == EV_KEY:
                    event = ButtonEvent(
                        DOWN if value else UP, button_code.get(code, '?'),
                        times)
                    self._on_click(event=event)

                elif key_type == EV_REL:
                    value, = struct.unpack('i', struct.pack('I', value))
                    if code == REL_WHEEL:
                        self._on_scroll(event=WheelEvent(value, times))

                    elif code in [ABS_X, ABS_Y]:
                        if code == ABS_X:
                            self.pos_x = value
                        elif code == ABS_Y:
                            self.pos_y = value
                        if self.pos_y<=2 and self.pos_x <=2:
                            continue
                        self._on_move(MoveEvent(self.pos_x, self.pos_y, times))

                if event is None:
                    continue

            except KeyboardInterrupt:
                break
            except Exception as e:
                self._logger("Error: Device ({}), {}".format(self.path, e))
                break
        self._logger("Device ({}), The device Remove".format(self.path))
        self._threads.remove(self.path)

    @staticmethod
    def __transformation(value: int, xs=1920, range_value=65535):
        return int((value - xs / 2) * (range_value / xs))

    def _on_move(self, event: MoveEvent) -> None:
        # 过滤数据，解决鼠标托送延迟问题
        x, y = event.x, event.y
        self._logger.debug(f"Mouse move event: {event}")
        if self._mouse_mode:
            try:
                event_ = {
                    "event_type": "mouse_relative",
                    "event": {
                        "to": {
                            "x": x,
                            "y": y
                        }
                    }
                }

                self._rpc_cli.mouse_on_relative(event_)
            except Exception as e:
                self._logger.error(
                    f"Error message: {e}\n, %s", traceback.print_exc())
        else:
            if self._counter == self._CONST_SIZE or self._counter == self._ZERO or (x != self.last_x or y != self.last_y):
                try:
                    event_ = {
                        "event_type": "mouse_move",
                        "event": {
                            "to": {
                                "x": self.__transformation(x, self._width),
                                "y": self.__transformation(y, self._height)
                            }
                        }
                    }

                    self._rpc_cli.mouse_on_move(event_)
                    self.last_y, self.last_x = y, x
                except Exception as e:
                    self._logger.error(
                        f"Error message: {e}\n, %s", traceback.print_exc())

    def _on_click(self, event: ButtonEvent):
        self._logger.debug(f"Mouse Click event: {event}")
        try:
            event_ = {
                "event_type": "mouse_button",
                "event": {
                    "button": event.button,
                    "state": event_state[event.event_type]
                }
            }

            self._rpc_cli.mouse_on_click(event_)
        except Exception as e:
            self._logger.error(
                f"Error message: {e}\n, %s",traceback.print_exc())

    def _on_scroll(self, event: WheelEvent) -> None:
        self._logger.debug(f"Mouse scroll event: {event}")
        try:
            event_ = {
                "event_type": "mouse_wheel",
                "event": {
                    "delta": {
                        "x": 0,
                        "y": event.delta * 5
                    }
                }
            }
            self._rpc_cli.mouse_on_scroll(event_)
        except Exception as e:
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())


class EventHandler(object):
    last_x, last_y = 0, 0
    _CONST_SIZE, _ZERO = 6, 1

    def __init__(
            self, queue: Queue, rpc_uri: str,
            height: int = 1080, width: int = 1920, mode: bool = False):
        self._rpc_uri = rpc_uri
        self._height = height
        self._width = width
        self._eq = queue
        self._mode = mode
        self._logger = get_logger(0)
        self._event_functions = {
            "MoveEvent": self._on_move,
            "ButtonEvent": self._on_click,
            "WheelEvent": self._on_scroll,
            "KeyboardEvent": self._on_key
        }
        self._counter = 0

    @staticmethod
    def __transformation(value: int, xs=1920, range_value=65535):
        return int((value - xs / 2) * (range_value / xs))

    def _on_move(self, event: MoveEvent) -> None:
        # 过滤数据，解决鼠标托送延迟问题
        x, y = event.x, event.y
        self._logger.debug(f"Mouse move event: {event}")
        if self._mode:
            try:
                event_ = {
                    "event_type": "mouse_relative",
                    "event": {
                        "to": {
                            "x": x,
                            "y": y
                        }
                    }
                }
                with Server(self._rpc_uri) as rpc:
                    rpc.mouse_on_relative(event_)
            except Exception as e:
                self._logger.error(
                    f"Error message: {e}\n, %s", traceback.print_exc())
        else:
            if self._counter == self._CONST_SIZE or self._counter == self._ZERO or (
                    x != self.last_x or y != self.last_y):
                try:
                    event_ = {
                        "event_type": "mouse_move",
                        "event": {
                            "to": {
                                "x": self.__transformation(x, self._width),
                                "y": self.__transformation(y, self._height)
                            }
                        }
                    }
                    with Server(self._rpc_uri) as rpc:
                        rpc.mouse_on_move(event_)
                    self.last_y, self.last_x = y, x
                except Exception as e:
                    self._logger.error(
                        f"Error message: {e}\n, %s", traceback.print_exc())

    def _on_click(self, event: ButtonEvent):
        self._logger.debug(f"Mouse Click event: {event}")
        try:
            event_ = {
                "event_type": "mouse_button",
                "event": {
                    "button": event.button,
                    "state": event_state[event.event_type]
                }
            }
            with Server(self._rpc_uri) as rpc:
                rpc.mouse_on_click(event_)
        except Exception as e:
            self._logger.error(
                f"Error message: {e}\n, %s", traceback.print_exc())

    def _on_scroll(self, event: WheelEvent) -> None:
        self._logger.debug(f"Mouse scroll event: {event}")
        try:
            event_ = {
                "event_type": "mouse_wheel",
                "event": {
                    "delta": {
                        "x": 0,
                        "y": event.delta * 5
                    }
                }
            }
            with Server(self._rpc_uri) as rpc:
                rpc.mouse_on_scroll(event_)
        except Exception as e:
            self._logger.info(
                f"Error message: {e}\n, %s", traceback.print_exc())

    def _on_key(self, event: KeyboardEvent) -> None:
        key = AT1_TO_LOCAL.get(event.scan_code)
        state = event_state.get(event.event_type)
        try:
            event_ = {
                "event_type": "key",
                "event": {
                    "key": key,
                    "state": state
                }
            }
            with Server(self._rpc_uri) as rpc:
                rpc.keyboard_event(event_)

        except Exception as e:
            self._logger.error(
                f"Error message: {e}\n, %s", traceback.print_exc())

    def consumer(self):
        while True:
            try:
                event = self._eq.get()
                if event is None:
                    continue
                self._event_functions[event.__class__.__name__](event)
            except KeyboardInterrupt:
                self._logger.info("Bye-Bye")
                SystemExit(0)


class MainListener(object):
    def __init__(
            self, rpc_uri: str, height: int, width: int, workers: int = 6,
            mode: bool = False):
        self._listen_threads = set()
        self._rpc_uri = rpc_uri
        self._height = height
        self._width = width
        self._mode = mode
        self._queue = Queue()
        self._logger = get_logger(0)
        self._pool = ThreadPoolExecutor(max_workers=workers)
        self._rpc_client = Server(uri=self._rpc_uri)

    def start(self) -> None:
        try:
            # 声明消费事件数据线程
            # consumer_th = EventHandler(
            #     queue=self._queue, rpc_uri=self._rpc_uri,
            #     height=self._height, width=self._width, mode=self._mode)
            # self._pool.submit(consumer_th.consumer)

            while True:
                # 键盘事件监听事件线程
                key_devices = self.check_device("kbd")
                for device in key_devices:
                    if device in self._listen_threads:
                        continue
                    key_device = KbdEventDevice(
                        path=device, threads=self._listen_threads,
                        logger=self._logger, rpc_cli=self._rpc_client)
                    self._pool.submit(key_device.event_handler)
                    self._listen_threads.add(device)
                    print("Reload kbd device {} success".format(device))

                    # 键盘事件监听事件线程
                mouse_devices = self.check_device("mouse")
                for device in mouse_devices:
                    if device in self._listen_threads:
                        continue
                    mouse_device = MouseEventDevice(
                        path=device,
                        threads=self._listen_threads,
                        logger=self._logger,
                        rpc_cli=self._rpc_client,
                        mode=self._mode,
                        height=self._height,
                        width=self._width)
                    self._pool.submit(mouse_device.event_handler)
                    self._listen_threads.add(device)
                    print("Reload mouse device {} success".format(device))

                time.sleep(30)
        except KeyboardInterrupt:
            self._logger.info("Bye-Bye")
            SystemExit(0)

    @staticmethod
    def check_device(type_name: str) -> list:
        """
        检查驱动是否存在
        :param type_name: 设备类型
        :return:
        """
        devices = list()
        try:
            with open("/proc/bus/input/devices") as f:
                description = f.read()
            for name, handlers in re.findall(
                    device_pattern, description, re.DOTALL):
                if type_name not in handlers:
                    continue

                path = '/dev/input/event' + re.search(
                    r'event(\d+)', handlers).group(1)
                if os.path.exists(path):
                    devices.append(path)
            if devices:
                return devices
        except FileNotFoundError:
            print(
                "Warning device file [/proc/bus/input/devices] is not found")

        for path in glob('/dev/input/by-id/*-event-' + type_name):
            if os.path.exists(path=path):
                devices.append(path)

        return devices


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kvmd-localer",
        description="KVMD Local Mouse & Keyboard listen tools",
    )

    parser.set_defaults(cmd=(lambda *_: parser.print_help()))
    parser.add_argument(
        "-U", "--uri", dest="uri", type=str, default="http://localhost/api/rpc",
        help="WebSocket Service uri")
    parser.add_argument(
        "-W", "--width", dest="width", type=int, default=1920,
        help="The width of DRM Device")
    parser.add_argument(
        "-H", "--height", dest="height", type=int, default=1080,
        help="The height of DRM Device")

    parser.add_argument(
        "-WK", "--workers", dest="workers", type=int, default=6,
        help="Thread pool max workers")

    parser.add_argument(
        "-M", "--mode", dest="mode", type=bool, default=False,
        help="mouse mode (relative/absolute) coordinate")

    args = parser.parse_args()

    if "localhost" not in args.uri and "127.0.0.1" not in args.uri:
        raise RuntimeError("URI参数值只能为本地地址")

    try:
        listen = MainListener(
            rpc_uri=args.uri, height=args.height,
            width=args.width, workers=args.workers, mode=args.mode)
        listen.start()
    except KeyboardInterrupt:
        get_logger(0).info("Bye-Bye")
    except Exception as e:
        get_logger(0).error(e)
