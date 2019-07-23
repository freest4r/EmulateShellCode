from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import sys, binascii
import WinDump

'''
eax=130e1032 ebx=032616e8 ecx=130e1000 edx=0052efa8 esi=0052e418 edi=00000000
eip=692dba19 esp=001ac49c ebp=001ac4c8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
'''

class ESC:
    def __init__(self, dumpPath, initaddr):
        self.dmp = WinDump.WinDump(dumpPath)
        self.emul = Uc(UC_ARCH_X86, UC_MODE_32)
        self.emul.mem_map(initaddr, 0x14000000)

    def setFS(self, addr):
        self.FS = addr

    def setShellCode(self, addr, shellcode):
        self.shellcode = shellcode
        self.shellcode_addr = addr
        self.emul.mem_write(addr, self.shellcode)

    def getShellCode(self):
        return self.shellcode

    def initRegs(self):
        self.emul.reg_write(UC_X86_REG_EAX, 0xd7)
        self.emul.reg_write(UC_X86_REG_EBX, 0x032616e8 )
        self.emul.reg_write(UC_X86_REG_ECX, 0x130e1000)
        self.emul.reg_write(UC_X86_REG_EDX, 0x130e105a)
        self.emul.reg_write(UC_X86_REG_EIP, 0x130e3000)
        self.emul.reg_write(UC_X86_REG_ESP, 0x130e105e)
        self.emul.reg_write(UC_X86_REG_ESI, 0x0)
        self.emul.reg_write(UC_X86_REG_EDI, 0x0052e418)
        print("hi")
        self.emul.reg_write(UC_X86_REG_FS, 0x10000)

    def initMem(self, addr, size):
        data = self.dmp.readMem(addr, size)
        self.emul.mem_write(addr, data)


def main():
    esc = ESC("~/study/WINWORD3.DMP", 0x00010000)
    print(1)

    #init registers
    esc.initRegs()
    
    #init mem
    esc.initMem(0x130e0000, 0x1000)
    #esc.initMem(0x7ffde000, 0x1000)

    #setShellCode
    esc.setShellCode(0x130e3000, b"\x60")
    #esc.setShellCode(0x130e3000, b"\x60\x64\xa1\x00\x00\x00\x00")

    #start
    esc.emul.emu_start(esc.shellcode_addr, esc.shellcode_addr+len(esc.shellcode))




if __name__ == "__main__":
    main()
