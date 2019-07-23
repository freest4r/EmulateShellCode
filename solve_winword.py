from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import sys, binascii
import WinDump

'''
eax=130e1032 ebx=032616e8 ecx=130e1000 edx=0052efa8 esi=0052e418 edi=00000000
eip=692dba19 esp=001ac49c ebp=001ac4c8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
https://gist.github.com/sparktrend/256e3af76a2b542bff8c0bd647e3feca
'''

class ESC:
    def __init__(self, dumpPath, initaddr):
        self.dmp = WinDump.WinDump(dumpPath)
        self.emul = Uc(UC_ARCH_X86, UC_MODE_32)
        self.emul.mem_map(initaddr, 0x20000000)

    def setFS(self, addr):
        self.FS = addr

    def setShellCode(self, addr, shellcode):
        self.shellcode = shellcode
        self.shellcode_addr = addr
        self.emul.mem_write(addr, self.shellcode)

    def getShellCode(self):
        return self.shellcode

    def initRegs(self):
        print("1")
        '''
        self.emul.reg_write(UC_X86_REG_CS, 0x1b)
        self.emul.reg_write(UC_X86_REG_SS, 0x23)
        self.emul.reg_write(UC_X86_REG_DS, 0x23)
        self.emul.reg_write(UC_X86_REG_ES, 0x23)
        self.emul.reg_write(UC_X86_REG_FS, 0x3b)
        self.emul.reg_write(UC_X86_REG_GS, 0x00)
        print("2")
        '''

        self.emul.reg_write(UC_X86_REG_EAX, 0xd7)
        self.emul.reg_write(UC_X86_REG_EBX, 0x032616e8 )
        self.emul.reg_write(UC_X86_REG_ECX, 0x130e1000)
        self.emul.reg_write(UC_X86_REG_EDX, 0x130e105a)
        self.emul.reg_write(UC_X86_REG_EIP, 0x130e3000)
        self.emul.reg_write(UC_X86_REG_ESP, 0x130e105e)
        self.emul.reg_write(UC_X86_REG_ESI, 0x0)
        self.emul.reg_write(UC_X86_REG_EDI, 0x0052e418)

    def initMem(self, addr, size):
        data = self.dmp.readMem(addr, size)
        self.emul.mem_write(addr, data)

    def printStack(self, size=0x40):
        esp = self.emul.reg_read(UC_X86_REG_ESP)
        stack = self.emul.mem_read(esp, 0x40)
        stack = binascii.hexlify(stack)
        print(stack)


def main():
    esc = ESC("~/study/WINWORD3.DMP", 0x00010000)
    print("load DMP done")

    print(hex(UC_X86_REG_CS))
    print(hex(UC_X86_REG_SS))
    print(hex(UC_X86_REG_DS))
    print(hex(UC_X86_REG_ES))
    print(hex(UC_X86_REG_FS))
    print(hex(UC_X86_REG_GS))
    #init registers
    esc.initRegs()
    print("init regs done")
    
    #init mem
    esc.initMem(0x130e0000, 0x1000)
    #esc.initMem(0x7ffde000, 0x1000)
    print("init mem done")

    #setShellCode
    esc.setShellCode(0x130e3000, b"\x60")
    esc.setShellCode(0x130e3000, b"\x60\x64\xa1\x00\x00\x00\x00")
    print("set shellcode done")

    esc.printStack()
    print("GO")
    #start
    esc.emul.emu_start(esc.shellcode_addr, esc.shellcode_addr+len(esc.shellcode))
    print("DONE")
    esc.printStack()




if __name__ == "__main__":
    main()
