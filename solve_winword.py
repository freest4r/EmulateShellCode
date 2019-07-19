from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import sys

'''
eax=130e1032 ebx=032616e8 ecx=130e1000 edx=0052efa8 esi=0052e418 edi=00000000
eip=692dba19 esp=001ac49c ebp=001ac4c8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
'''

def getShellCode():
    return "\x60"
    #return open(sys.argv[1], "rb").read()

def initRegs():
    mu.reg_write(UC_X86_REG_EAX, 0xd7)
    mu.reg_write(UC_X86_REG_EBX, 0x032616e8 )
    mu.reg_write(UC_X86_REG_ECX, 0x130e1000)
    mu.reg_write(UC_X86_REG_EDX, 0x130e105a)
    mu.reg_write(UC_X86_REG_EIP, 0x130e3000)
    mu.reg_write(UC_X86_REG_ESP, 0x130e105e)
    mu.reg_write(UC_X86_REG_ESI, 0x0)
    mu.reg_write(UC_X86_REG_EDI, 0x0052e418)


def initMem():
    read mem
    write mem

def main():
    #read shellcode
    shellcode = getShellCode() 

    #init registers
    initRegs()

    #init mem
    initMem()


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
    main()
