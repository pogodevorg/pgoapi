"""
pgoapi - Pokemon Go API
Copyright (c) 2016 tjado <https://github.com/tejado>
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
Author: tjado <https://github.com/tejado>
"""

import re
import time
import struct
import ctypes
import logging
import os
import sys
import platform

from json import JSONEncoder
from binascii import unhexlify

# other stuff
from google.protobuf.internal import encoder
from geopy.geocoders import GoogleV3
from s2sphere import LatLng, Angle, Cap, RegionCoverer, math

log = logging.getLogger(__name__)

HASH_SEED = 0x46E945F8  # static hash seed from app
EARTH_RADIUS = 6371000  # radius of Earth in meters

def f2i(float):
  return struct.unpack('<Q', struct.pack('<d', float))[0]


def f2h(float):
  return hex(struct.unpack('<Q', struct.pack('<d', float))[0])


def h2f(hex):
  return struct.unpack('<d', struct.pack('<Q', int(hex,16)))[0]

def d2h(f):
    hex_str = f2h(f)[2:].replace('L','')
    hex_str = ("0" * (len(hex_str) % 2)) + hex_str
    return unhexlify(hex_str)

def to_camel_case(value):
  return ''.join(word.capitalize() if word else '_' for word in value.split('_'))


# JSON Encoder to handle bytes
class JSONByteEncoder(JSONEncoder):
    def default(self, o):
        return o.decode('utf-8')


def get_pos_by_name(location_name):
    geolocator = GoogleV3()
    loc = geolocator.geocode(location_name, timeout=10)
    if not loc:
        return None

    log.info("Location for '%s' found: %s", location_name, loc.address)
    log.info('Coordinates (lat/long/alt) for location: %s %s %s', loc.latitude, loc.longitude, loc.altitude)

    return (loc.latitude, loc.longitude, loc.altitude)


def get_cell_ids(lat, long, radius=500):
    # Max values allowed by server according to this comment:
    # https://github.com/AeonLucid/POGOProtos/issues/83#issuecomment-235612285
    if radius > 1500:
        radius = 1500  # radius = 1500 is max allowed by the server
    region = Cap.from_axis_angle(LatLng.from_degrees(lat, long).to_point(), Angle.from_degrees(360*radius/(2*math.pi*EARTH_RADIUS)))
    coverer = RegionCoverer()
    coverer.min_level = 15
    coverer.max_level = 15
    cells = coverer.get_covering(region)
    cells = cells[:100]  # len(cells) = 100 is max allowed by the server
    return sorted([x.id() for x in cells])


def get_time(ms = False):
    if ms:
        return int(time.time() * 1000)
    else:
        return int(time.time())


def get_format_time_diff(low, high, ms = True):
    diff = (high - low)
    if ms:
        m, s = divmod(diff / 1000, 60)
    else:
        m, s = divmod(diff, 60)
    h, m = divmod(m, 60)

    return (h, m, s)


def parse_api_endpoint(api_url):
    if not api_url.startswith("https"):
        api_url = 'https://{}/rpc'.format(api_url)

    return api_url


class Rand48(object):
    def __init__(self, seed):
        self.n = seed
    def seed(self, seed):
        self.n = seed
    def srand(self, seed):
        self.n = (seed << 16) + 0x330e
    def next(self):
        self.n = (25214903917 * self.n + 11) & (2**48 - 1)
        return self.n
    def drand(self):
        return self.next() / 2**48
    def lrand(self):
        return self.next() >> 17
    def mrand(self):
        n = self.next() >> 16
        if n & (1 << 31):
            n -= 1 << 32
        return n


def long_to_bytes(val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.
    :param long val: The value to pack
    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.
    If you want byte- and word-ordering to differ, you're on your own.
    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s

def get_lib_paths():
    # win32 doesn't mean necessarily 32 bits
    hash_lib = None
    arch = platform.architecture()[0]
    if sys.platform == "win32" or sys.platform == "cygwin":
        if arch == '64bit':
            encrypt_lib = "libpcrypt-windows-x86-64.dll"
            hash_lib = "libniahash-windows-x86-64.dll"
        else:
            encrypt_lib = "libpcrypt-windows-i686.dll"
            hash_lib = "libniahash-windows-i686.dll"
    elif sys.platform == "darwin":
        if arch == '64bit':
            encrypt_lib = "libpcrypt-macos-x86-64.dylib"
            hash_lib = "libniahash-macos-x86-64.dylib"
        else:
            encrypt_lib = "libpcrypt-macos-i386.dylib"
            hash_lib = "libniahash-macos-i386.dylib"
    elif os.uname()[4].startswith("arm") and arch == '32bit':
        encrypt_lib = "libpcrypt-linux-arm32.so"
        hash_lib = "libniahash-linux-arm32.so"
    elif os.uname()[4].startswith("aarch64") and arch == '64bit':
        encrypt_lib = "libpcrypt-linux-arm64.so"
        hash_lib = "libniahash-linux-arm64.so"
    elif sys.platform.startswith('linux'):
        if arch == '64bit':
            encrypt_lib = "libpcrypt-linux-x86-64.so"
            hash_lib = "libniahash-linux-x86-64.so"
        else:
            encrypt_lib = "libpcrypt-linux-i386.so"
            hash_lib = "libniahash-linux-i386.so"
    elif sys.platform.startswith('freebsd'):
        if arch == '64bit':
            encrypt_lib = "libpcrypt-freebsd-x86-64.so"
            hash_lib = "libniahash-freebsd-x86-64.so"
        else:
            encrypt_lib = "libpcrypt-freebsd-i386.so"
            hash_lib = "libniahash-freebsd-i386.so"
    else:
        err = "Unexpected/unsupported platform '{}'".format(sys.platform)
        log.error(err)
        raise Exception(err)

    encrypt_lib_path = os.path.join(os.path.dirname(__file__), "lib", encrypt_lib)
    hash_lib_path = os.path.join(os.path.dirname(__file__), "lib", hash_lib)

    if not os.path.isfile(encrypt_lib_path):
        err = "Could not find {} encryption library {}".format(sys.platform, encrypt_lib_path)
        log.error(err)
        raise Exception(err)
    if not os.path.isfile(hash_lib_path):
        err = "Could not find {} hashing library {}".format(sys.platform, hash_lib_path)
        log.error(err)
        raise Exception(err)

    return encrypt_lib_path, hash_lib_path


class HashGenerator:
    def __init__(self, library_path):
        self._hash_lib = ctypes.cdll.LoadLibrary(library_path)
        self._hash_lib.compute_hash.argtypes = (ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32)
        self._hash_lib.compute_hash.restype = ctypes.c_uint64

    def generate_location_hash_by_seed(self, authticket, lat, lng, acc=5):
        first_hash = self.hash32(authticket, seed=HASH_SEED)
        location_bytes = d2h(lat) + d2h(lng) + d2h(acc)
        loc_hash = self.hash32(location_bytes, seed=first_hash)
        return ctypes.c_int32(loc_hash).value

    def generate_location_hash(self, lat, lng, acc=5):
        location_bytes = d2h(lat) + d2h(lng) + d2h(acc)
        loc_hash = self.hash32(location_bytes, seed=HASH_SEED)
        return ctypes.c_int32(loc_hash).value

    def generate_request_hash(self, authticket, request):
        first_hash = self.hash64salt32(authticket, seed=HASH_SEED)
        req_hash = self.hash64salt64(request, seed=first_hash)
        return ctypes.c_uint64(req_hash).value

    def hash64salt32(self, buf, seed):
        buf = struct.pack(">I", seed) + buf
        return self.calcHash(buf)

    def hash64salt64(self, buf, seed):
        buf = struct.pack(">Q", seed) + buf
        return self.calcHash(buf)

    def hash32(self, buf, seed):
        buf = struct.pack(">I", seed) + buf
        hash64 = self.calcHash(buf)
        signedhash64 = ctypes.c_int64(hash64)
        return ctypes.c_uint(signedhash64.value).value ^ ctypes.c_uint(signedhash64.value >> 32).value

    def calcHash(self, buf):
        buf = list(bytearray(buf))
        num_bytes = len(buf)
        array_type = ctypes.c_ubyte * num_bytes

        data = self._hash_lib.compute_hash(array_type(*buf), ctypes.c_uint32(num_bytes));
        return ctypes.c_uint64(data).value
