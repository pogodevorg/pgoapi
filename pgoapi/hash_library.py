from __future__ import absolute_import

import ctypes
import struct

from pgoapi.hash_engine import HashEngine
from pgoapi.utilities import d2h

HASH_SEED = 0x46E945F8  # static hash seed from app

class HashLibrary(HashEngine):
    def __init__(self, library_path):
        self._hash_lib = ctypes.cdll.LoadLibrary(library_path)
        self._hash_lib.compute_hash.argtypes = (ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32)
        self._hash_lib.compute_hash.restype = ctypes.c_uint64

    def hash(self, timestamp, latitude, longitude, altitude, authticket, sessiondata, requests):
        self.location_hash = None
        self.location_auth_hash = None
        self.request_hashes = []

        first_hash = self.hash32(authticket, seed=HASH_SEED)
        location_bytes = d2h(latitude) + d2h(longitude) + d2h(altitude)
        loc_hash = self.hash32(location_bytes, seed=first_hash)
        self.location_auth_hash = ctypes.c_int32(loc_hash).value

        loc_hash = self.hash32(location_bytes, seed=HASH_SEED)
        self.location_hash = ctypes.c_int32(loc_hash).value

        first_hash = self.hash64salt32(authticket, seed=HASH_SEED)
        for request in requests:
            req_hash = self.hash64salt64(request.SerializeToString(), seed=first_hash)
            self.request_hashes.append(ctypes.c_int64(req_hash).value)

    def hash64salt32(self, buf, seed):
        buf = struct.pack(">I", seed) + buf
        return self.call_hash(buf)

    def hash64salt64(self, buf, seed):
        buf = struct.pack(">Q", seed) + buf
        return self.call_hash(buf)

    def hash32(self, buf, seed):
        buf = struct.pack(">I", seed) + buf
        hash64 = self.call_hash(buf)
        signedhash64 = ctypes.c_int64(hash64)
        return ctypes.c_uint(signedhash64.value).value ^ ctypes.c_uint(signedhash64.value >> 32).value

    def call_hash(self, buf):
        buf = list(bytearray(buf))
        num_bytes = len(buf)
        array_type = ctypes.c_ubyte * num_bytes

        data = self._hash_lib.compute_hash(array_type(*buf), ctypes.c_uint32(num_bytes))
        return ctypes.c_uint64(data).value
