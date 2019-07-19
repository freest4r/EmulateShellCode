from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *




def test1():
    code = b"\x41\x4a"#INC ecx; DEC edx;
    ADDRESS = 0x1000000

    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    mu.mem_map(ADDRESS, 2*1024*1024)

    mu.mem_write(ADDRESS, code)

    mu.reg_write(UC_X86_REG_ECX, 0x123)
    mu.reg_write(UC_X86_REG_EDX, 0x456)

    mu.emu_start(ADDRESS, ADDRESS+len(code))

    ecx = mu.reg_read(UC_X86_REG_ECX)
    edx = mu.reg_read(UC_X86_REG_EDX)

    print(hex(ecx))
    print(hex(edx))


if __name__ == "__main__":
    test1()
