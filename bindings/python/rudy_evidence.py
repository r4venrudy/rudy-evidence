"""Standard-library binding to Rudy Evidence C ABI v1. No subprocess or network access."""
import ctypes
import json
import os
from pathlib import Path

class EvidenceError(ValueError):
    pass

class _Buffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("size", ctypes.c_size_t)]

class Evidence:
    def __init__(self, library=None):
        path = library or os.environ.get("RUDY_EVIDENCE_LIBRARY")
        if not path or not Path(path).is_absolute():
            raise EvidenceError("Supply an absolute trusted library path or RUDY_EVIDENCE_LIBRARY.")
        self._lib = ctypes.CDLL(str(path))
        self._lib.re_abi_version.restype = ctypes.c_uint
        if self._lib.re_abi_version() != 1:
            raise EvidenceError("Unsupported Rudy Evidence C ABI.")
        self._lib.re_process.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(_Buffer), ctypes.POINTER(_Buffer)]
        self._lib.re_process.restype = ctypes.c_int
        self._lib.re_free.argtypes = [ctypes.POINTER(_Buffer)]
        self._lib.re_free.restype = None

    def process(self, request):
        raw = json.dumps(request, ensure_ascii=True, allow_nan=False).encode("utf-8")
        result, error = _Buffer(), _Buffer()
        try:
            status = self._lib.re_process(raw, len(raw), ctypes.byref(result), ctypes.byref(error))
            if status:
                message = ctypes.string_at(error.data, error.size).decode("utf-8") if error.data else "Native API call failed."
                raise EvidenceError(message)
            return json.loads(ctypes.string_at(result.data, result.size))
        finally:
            self._lib.re_free(ctypes.byref(result))
            self._lib.re_free(ctypes.byref(error))

    def normalize(self, format, scope, document):
        return self.process(dict(operation="normalize", format=format, scope=scope, document=document))
