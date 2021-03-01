"""Block socket syscalls with libseccomp

Copyright (c) 2021 Christian Heimes

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import socket
import errno

import ctypes
import ctypes.util


# actions
SCMP_ACT_KILL_PROCESS = 0x80000000
SCMP_ACT_ALLOW = 0x7FFF0000


def SCMP_ACT_ERRNO(x):
    return 0x00050000 | (x & 0x0000FFFF)


# compare operators for scmp_arg_cmp
SCMP_CMP_NE = 1
SCMP_CMP_LT = 2
SCMP_CMP_LE = 3
SCMP_CMP_EQ = 4
SCMP_CMP_GE = 5
SCMP_CMP_GT = 6
SCMP_CMP_MASKED_EQ = 7

# architectures
SCMP_ARCH_NATIVE = 0
# define AUDIT_ARCH_I386         (EM_386|__AUDIT_ARCH_LE)
SCMP_ARCH_X86 = 3 | 0x40000000
# define AUDIT_ARCH_I386         (EM_386|__AUDIT_ARCH_LE)
SCMP_ARCH_X86_64 = 62 | 0x80000000 | 0x40000000
# define SCMP_ARCH_X32           (EM_X86_64|__AUDIT_ARCH_LE)
SCMP_ARCH_X32 = 62 | 0x40000000


def _check_init(result, func, args):
    if result is None:
        raise OSError(func.__name__, args)
    return result


def _check_success(result, func, args):
    if result != 0:
        raise OSError(result, func.__name__, args)
    return result


def _check_syscall(result, func, args):
    if result < 0:
        raise OSError(result, func.__name__, args)
    return result


class _scmp_filter(ctypes.Structure):
    __slots__ = ()


scmp_filter_ctx = ctypes.POINTER(_scmp_filter)


class scmp_arg_cmp(ctypes.Structure):
    __slots__ = ()
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]

    def __init__(self, arg, op, datum_a, datum_b=None):
        if op == SCMP_CMP_MASKED_EQ:
            if datum_b is None:
                raise ValueError
        else:
            if datum_b is not None:
                raise ValueError
            datum_b = 0
        super().__init__(arg, op, datum_a, datum_b)


_lsc_path = ctypes.util.find_library("seccomp")
if _lsc_path is None:
    raise RuntimeError("Unable to find libseccomp")

_lsc = ctypes.CDLL(_lsc_path)

_lsc.seccomp_init.argtypes = (ctypes.c_uint32,)
_lsc.seccomp_init.restype = scmp_filter_ctx
_lsc.seccomp_init.errcheck = _check_init

_lsc.seccomp_release.argtypes = (scmp_filter_ctx,)
_lsc.seccomp_release.restype = None

_lsc.seccomp_load.argtypes = (scmp_filter_ctx,)
_lsc.seccomp_load.restype = ctypes.c_int
_lsc.seccomp_load.errcheck = _check_success

_lsc.seccomp_arch_add.argtypes = (scmp_filter_ctx, ctypes.c_uint32)
_lsc.seccomp_arch_add.restype = ctypes.c_int
_lsc.seccomp_arch_add.errcheck = _check_success

_lsc.seccomp_arch_native.argtypes = ()
_lsc.seccomp_arch_native.restype = ctypes.c_uint32

_lsc.seccomp_rule_add_array.argtypes = (
    scmp_filter_ctx,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.POINTER(scmp_arg_cmp),
)
_lsc.seccomp_rule_add_array.restype = ctypes.c_int
_lsc.seccomp_rule_add_array.errcheck = _check_success

_lsc.seccomp_syscall_resolve_name_arch.argtypes = (ctypes.c_uint32, ctypes.c_char_p)
_lsc.seccomp_syscall_resolve_name_arch.restype = ctypes.c_int
_lsc.seccomp_syscall_resolve_name_arch.errcheck = _check_syscall


NATIVE_ARCH = _lsc.seccomp_arch_native()


def add_sibbling_archs(ctx):
    if NATIVE_ARCH == SCMP_ARCH_X86:
        _lsc.seccomp_arch_add(ctx, SCMP_ARCH_X86_64)
        _lsc.seccomp_arch_add(ctx, SCMP_ARCH_X32)
    elif NATIVE_ARCH == SCMP_ARCH_X86_64:
        _lsc.seccomp_arch_add(ctx, SCMP_ARCH_X86)
        _lsc.seccomp_arch_add(ctx, SCMP_ARCH_X32)
    elif NATIVE_ARCH == SCMP_ARCH_X32:
        _lsc.seccomp_arch_add(ctx, SCMP_ARCH_X86_64)
        _lsc.seccomp_arch_add(ctx, SCMP_ARCH_X86)


def resolve_syscall(name, arch_token=NATIVE_ARCH):
    """Resolve syscall by name (default: native arch)"""
    return _lsc.seccomp_syscall_resolve_name_arch(arch_token, name.encode("ascii"))


def rule_add_array(ctx, action, syscall, *args):
    syscall_nr = resolve_syscall(syscall)

    if len(args) > 6:
        raise ValueError(args)
    arg_array = (scmp_arg_cmp * len(args))()
    for i, arg in enumerate(args):
        arg_array[i] = arg
    _lsc.seccomp_rule_add_array(ctx, action, syscall_nr, len(arg_array), arg_array)


def block_socket(action=SCMP_ACT_ERRNO(errno.EPERM)):
    # allow all syscalls by default
    sc = _lsc.seccomp_init(SCMP_ACT_ALLOW)
    try:
        # create rules for sibbling archs (e.g. X86 on X86_64)
        add_sibbling_archs(sc)
        # use "action" for all socket syscalls except for local AF_UNIX IPC
        rule_add_array(
            sc,
            action,
            "socket",
            scmp_arg_cmp(0, SCMP_CMP_NE, socket.AF_UNIX),
        )
        # load seccomp rules
        _lsc.seccomp_load(sc)
    finally:
        _lsc.seccomp_release(sc)


def test():
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket.create_connection(("www.python.org", 443)).close()

    block_socket()

    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        socket.create_connection(("www.python.org", 443))
    except PermissionError as e:
        print(f"TCP/IP socket created failed as exepcted: {e}")
    else:
        raise RuntimeError("seccomp filtering has failed")


if __name__ == "__main__":
    test()
