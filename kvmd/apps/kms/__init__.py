#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Project : pikvm-backend
@File    : __init__.py.py
@Version : V1.0.0
@Author  : wu.changwen
@Time    : 2023-03-02 14:13:26
@Desc    : 
"""

import argparse
import fcntl
import os.path
import selectors
import time
from ctypes import *
from mmap import mmap, MAP_SHARED, PROT_WRITE, ACCESS_READ

import pykms

from ...logging import get_logger

logger = get_logger(0)

DEFAULT_BUFFER_MAX_SIZE = 33554432

# -1, -5, -9, -13, -17, -21
EXTRA_SIZE = -13


class MemoryShareExtraInfo(LittleEndianStructure):
    _fields_ = [
        ("magic", c_uint64),
        ("version", c_uint32),
        ("id", c_uint64),
        ("used", c_size_t),
        ("width", c_uint),
        ("height", c_uint),
        ("format", c_uint),
        ("stride", c_uint),
        ("online", c_byte),
        ("key", c_byte),
        ("gop", c_uint),
        ("grab_ts", c_longdouble),
        ("encode_begin_ts", c_longdouble),
        ("encode_end_ts", c_longdouble),
        ("last_client_ts", c_longdouble),
        ("key_requested", c_byte),
    ]


class KmsSinkMemory(object):
    _share_memory_id = 0
    _memory_file_path = "/dev/shm"

    def __init__(self, fourcc, dev_crtc, width, height, mem_file):
        fmt = pykms.fourcc_to_pixelformat(fourcc)

        self._card = pykms.Card()
        res = pykms.ResourceManager(self._card)
        conn = res.reserve_connector(dev_crtc)
        self._crtc = res.reserve_crtc(conn)
        self._plane = res.reserve_overlay_plane(self._crtc, fmt)
        self._output_fb = pykms.DumbFramebuffer(self._card, width, height, fmt)
        memory_file = os.path.join(self._memory_file_path, mem_file)
        if not os.path.exists(memory_file):
            raise RuntimeError(f"KVMD sink device {memory_file} not exists\n")

        self._input_fd = open(memory_file, "r+b")
        self._buffer_size = 0

    def _load(self):
        with mmap(self._input_fd.fileno(), length=0, access=ACCESS_READ) as mm:
            memory_buf = None
            try:
                fcntl.flock(
                    self._input_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                extra_size = (mm.size() - DEFAULT_BUFFER_MAX_SIZE) + EXTRA_SIZE
                extra_data = mm.read(extra_size)
                c_str_buffer = create_string_buffer(extra_data)
                instance = cast(pointer(c_str_buffer),
                                POINTER(MemoryShareExtraInfo)).contents
                self._buffer_size = int(instance.used)

                if instance.id != self._share_memory_id:
                    memory_buf = mm.read(instance.used)
                    self._share_memory_id = instance.id
                fcntl.flock(self._input_fd.fileno(), fcntl.LOCK_UN)
                return memory_buf
            except BlockingIOError:
                return memory_buf

    def _output(self, conn, mask):
        assert self._output_fb is not None
        start_time = time.time()
        mem_buffer = self._load()
        if mem_buffer is None:
            return
        logger.debug("Read------> {}".format(time.time() - start_time))
        assert self._buffer_size < DEFAULT_BUFFER_MAX_SIZE

        with mmap(self._output_fb.fd(0), self._buffer_size, MAP_SHARED,
                  PROT_WRITE) as mm:
            mm.write(mem_buffer)

        if self._card.has_atomic:
            self._plane.set_props({
                "FB_ID": self._output_fb.id,
                "CRTC_ID": self._crtc.id,
                "SRC_W": self._output_fb.width << 16,
                "SRC_H": self._output_fb.height << 16,
                "CRTC_W": self._output_fb.width,
                "CRTC_H": self._output_fb.height})
        else:
            self._crtc.set_plane(
                self._plane, self._output_fb, 0, 0, self._output_fb.width,
                self._output_fb.height, 0, 0, self._output_fb.width,
                self._output_fb.height)
        logger.debug("Write------> {}".format(time.time() - start_time))

    def run(self):
        sel = selectors.DefaultSelector()
        sel.register(
            self._output_fb.fd(0), selectors.EVENT_READ, self._output)
        try:
            while True:
                events = sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
        except KeyboardInterrupt:
            logger.info("Bye-Bye")
            exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kvmd-kms-sink",
        description="KVMD Local video on DRM")

    parser.set_defaults(cmd=(lambda *_: parser.print_help()))
    parser.add_argument(
        "-W", "--width", dest="width", type=int, default=1920,
        help="The width of DRM Device")
    parser.add_argument(
        "-H", "--height", dest="height", type=int, default=1080,
        help="The height of DRM Device")
    parser.add_argument(
        "-F", "--fourcc", dest="fourcc", type=str, default="VYUY",
        help="DRM device encoder")
    parser.add_argument(
        "-M", "--memfile", dest="memfile", type=str,
        default="kvmd::ustreamer::uyvy", help="DRM device encoder")
    parser.add_argument(
        "-C", "--crtc", dest="crtc", type=str, default="hdmi",
        help="The type of audio/video interface")
    parser.add_argument(
        "-T", "--type", dest="type", type=str, default="drm",
        help="buffer type (drm/v4l2)")
    args = parser.parse_args()
    if not args.type in ["drm", "v4l2"]:
        logger.error("Bad buffer type", args.type)
        exit(0)

    try:
        KmsSinkMemory(
            fourcc=args.fourcc, dev_crtc=args.crtc,
            width=args.width, height=args.height, mem_file=args.memfile
        ).run()
    except Exception as e:
        logger.error(e)


if __name__ == '__main__':
    main()
