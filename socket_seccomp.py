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
import enum
import errno

import ctypes
import ctypes.util


class HexEnum(enum.IntEnum):
    def __repr__(self):
        return "<{self.__class__.__name__}.{self._name_}: 0x{self._value_:x}>".format(self=self)


class ScmpAction(HexEnum):
    """SCMP_ACT actions"""

    KILL_PROCESS = 0x80000000
    KILL_THREAD = 0x00000000
    KILL = KILL_THREAD
    TRAP = 0x00030000
    NOTIFY = 0x7FC00000
    LOG = 0x7FFC0000
    ALLOW = 0x7FFF0000

    @classmethod
    def ERRNO(cls, x):
        return 0x00050000 | (x & 0x0000FFFF)

    @classmethod
    def TRACE(cls, x):
        return 0x7FF00000 | (x & 0x0000FFFF)


class ScmpCmp(enum.IntEnum):
    """SCMP_CMP compare operators"""

    NE = 1
    LT = 2
    LE = 3
    EQ = 4
    GE = 5
    GT = 6
    MASKED_EQ = 7


class ELF_EM(enum.IntEnum):
    """linux/elf-em.h"""

    I386 = 3
    MIPS = 8
    PARISC = 15
    PPC = 20
    PPC64 = 21
    S390 = 22
    ARM = 40
    X86_64 = 62
    AARCH64 = 183
    RISCV = 243


class AuditArch(enum.IntEnum):
    """audit.h"""

    CONVENTION_MIPS64_N32 = 0x20000000
    AA_64BIT = 0x80000000
    LE = 0x40000000


class ScmpArch(HexEnum):
    """SCMP_ARCH architectures"""

    NATIVE = 0
    X86 = ELF_EM.I386 | AuditArch.LE
    X86_64 = ELF_EM.X86_64 | AuditArch.AA_64BIT | AuditArch.LE
    X32 = ELF_EM.X86_64 | AuditArch.LE
    ARM = ELF_EM.ARM | AuditArch.LE
    AARCH64 = ELF_EM.AARCH64 | AuditArch.AA_64BIT | AuditArch.LE
    MIPS = ELF_EM.MIPS
    MIPS64 = ELF_EM.MIPS | AuditArch.AA_64BIT
    MIPS64N32 = ELF_EM.MIPS | AuditArch.AA_64BIT | AuditArch.CONVENTION_MIPS64_N32
    MIPSEL = ELF_EM.MIPS | AuditArch.LE
    MIPSEL64 = ELF_EM.MIPS | AuditArch.AA_64BIT | AuditArch.LE
    MIPSEL64N32 = (
        ELF_EM.MIPS
        | AuditArch.AA_64BIT
        | AuditArch.LE
        | AuditArch.CONVENTION_MIPS64_N32
    )
    PARISC = ELF_EM.PARISC
    PARISC64 = ELF_EM.PARISC | AuditArch.AA_64BIT
    PPC = ELF_EM.PPC
    PPC64 = ELF_EM.PPC64 | AuditArch.AA_64BIT
    PPC64LE = ELF_EM.PPC64 | AuditArch.AA_64BIT | AuditArch.LE
    S390 = ELF_EM.S390
    S390X = ELF_EM.S390 | AuditArch.AA_64BIT
    RISCV64 = ELF_EM.RISCV | AuditArch.AA_64BIT | AuditArch.LE


SIBBLING_ARCHS = {
    ScmpArch.X86: [ScmpArch.X86_64, ScmpArch.X32],
    ScmpArch.X86_64: [ScmpArch.X86, ScmpArch.X32],
    ScmpArch.X32: [ScmpArch.X86_64, ScmpArch.X86],
}


def _check_init(result, func, args):
    if result is None:
        # seccomp_init(3) returns negative errno
        raise OSError(-result, func.__name__, args)
    return result


def _check_success(result, func, args):
    if result != 0:
        raise OSError(-result, func.__name__, args)
    return result


def _check_syscall(result, func, args):
    if result < 0:
        raise OSError(errno.ENOSYS, func.__name__, args)
    return result


def _check_arch(result, func, args):
    if result == ScmpArch.NATIVE:
        raise OSError(errno.EINVAL, func.__name__, args)
    return ScmpArch(result)


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
        if op == ScmpCmp.MASKED_EQ:
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
_lsc.seccomp_arch_native.errcheck = _check_arch

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
    for sibbling in SIBBLING_ARCHS.get(NATIVE_ARCH, []):
        _lsc.seccomp_arch_add(ctx, sibbling)


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


def block_socket(action=ScmpAction.ERRNO(errno.EPERM)):
    # allow all syscalls by default
    sc = _lsc.seccomp_init(ScmpAction.ALLOW)
    try:
        # create rules for sibbling archs (e.g. X86 on X86_64)
        add_sibbling_archs(sc)
        # use "action" for all socket syscalls except for local AF_UNIX IPC
        rule_add_array(
            sc,
            action,
            "socket",
            scmp_arg_cmp(0, ScmpCmp.NE, socket.AF_UNIX),
        )
        # load seccomp rules
        _lsc.seccomp_load(sc)
    finally:
        _lsc.seccomp_release(sc)
