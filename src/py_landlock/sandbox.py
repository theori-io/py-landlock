import ctypes
import errno
import os
import platform
from dataclasses import dataclass, field
from typing import Iterable, Sequence


_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
_LIBC.syscall.restype = ctypes.c_long
_LIBC.prctl.restype = ctypes.c_int

_PR_SET_NO_NEW_PRIVS = 38

_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1

_LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
_LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12

_WRITE_ACCESS = (
    _LANDLOCK_ACCESS_FS_WRITE_FILE
    | _LANDLOCK_ACCESS_FS_REMOVE_DIR
    | _LANDLOCK_ACCESS_FS_REMOVE_FILE
    | _LANDLOCK_ACCESS_FS_MAKE_CHAR
    | _LANDLOCK_ACCESS_FS_MAKE_DIR
    | _LANDLOCK_ACCESS_FS_MAKE_REG
    | _LANDLOCK_ACCESS_FS_MAKE_SOCK
    | _LANDLOCK_ACCESS_FS_MAKE_FIFO
    | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | _LANDLOCK_ACCESS_FS_MAKE_SYM
)

_SUPPORTED_ARCHS = {"x86_64", "aarch64"}
_LANDLOCK_CREATE_RULESET_NR = 444
_LANDLOCK_ADD_RULE_NR = 445
_LANDLOCK_RESTRICT_SELF_NR = 446


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneath(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]


def _ensure_supported_arch() -> None:
    if platform.machine() not in _SUPPORTED_ARCHS:
        raise RuntimeError("Unsupported architecture for Landlock syscalls")


def _syscall(number: int, *args: object) -> int:
    res = _LIBC.syscall(number, *args)
    if res == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(res)


def _landlock_create_ruleset(
    handled_access_fs: int | None, flags: int = 0
) -> int:
    if handled_access_fs is None:
        attr = ctypes.c_void_p()
        _ensure_supported_arch()
        return _syscall(_LANDLOCK_CREATE_RULESET_NR, attr, 0, flags)
    attr = _LandlockRulesetAttr(handled_access_fs=handled_access_fs)
    _ensure_supported_arch()
    return _syscall(
        _LANDLOCK_CREATE_RULESET_NR,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        flags,
    )


def _landlock_add_rule(ruleset_fd: int, rule_type: int, path_fd: int, allowed: int) -> None:
    _ensure_supported_arch()
    rule = _LandlockPathBeneath(allowed_access=allowed, parent_fd=path_fd)
    _syscall(
        _LANDLOCK_ADD_RULE_NR,
        ruleset_fd,
        rule_type,
        ctypes.byref(rule),
        0,
    )


def _landlock_restrict_self(ruleset_fd: int) -> None:
    _ensure_supported_arch()
    _syscall(_LANDLOCK_RESTRICT_SELF_NR, ruleset_fd, 0)


def is_supported() -> bool:
    if platform.machine() not in _SUPPORTED_ARCHS:
        return False
    try:
        _landlock_create_ruleset(None, _LANDLOCK_CREATE_RULESET_VERSION)
    except OSError as exc:
        if exc.errno in (errno.ENOSYS, errno.EOPNOTSUPP):
            return False
        raise
    return True


@dataclass
class Sandbox:
    write_paths: Sequence[str] = field(default_factory=tuple)
    _applied: bool = field(default=False, init=False, repr=False)

    def apply(self) -> None:
        if self._applied:
            raise RuntimeError("Sandbox has already been applied")

        ruleset_fd = _landlock_create_ruleset(_WRITE_ACCESS, 0)
        try:
            for path in self._normalized_paths():
                self._allow_write(ruleset_fd, path)
            self._set_no_new_privs()
            _landlock_restrict_self(ruleset_fd)
        finally:
            os.close(ruleset_fd)

        self._applied = True

    def _normalized_paths(self) -> list[str]:
        paths = []
        for path in self.write_paths:
            abs_path = os.path.abspath(path)
            if not os.path.exists(abs_path):
                raise FileNotFoundError(abs_path)
            paths.append(abs_path)
        return paths

    def _allow_write(self, ruleset_fd: int, path: str) -> None:
        o_path = getattr(os, "O_PATH", None)
        if o_path is None:
            raise RuntimeError("O_PATH is not supported on this platform")
        fd = os.open(path, o_path | os.O_CLOEXEC)
        try:
            _landlock_add_rule(
                ruleset_fd,
                _LANDLOCK_RULE_PATH_BENEATH,
                fd,
                _WRITE_ACCESS,
            )
        finally:
            os.close(fd)

    def _set_no_new_privs(self) -> None:
        res = _LIBC.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if res != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
