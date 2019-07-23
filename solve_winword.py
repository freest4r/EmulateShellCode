from __future__ import print_function from unicorn import *
from unicorn.x86_const import *
import sys, binascii
import WinDump

'''
eax=130e1032 ebx=032616e8 ecx=130e1000 edx=0052efa8 esi=0052e418 edi=00000000
eip=692dba19 esp=001ac49c ebp=001ac4c8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
https://gist.github.com/sparktrend/256e3af76a2b542bff8c0bd647e3feca
'''

STACK_BASE = 0x1b0000
STACK_TOP = 0x1a000
STACK_SIZE = STACK_BASE - STACK_TOP

CODE_BASE = 0x69291000
CODE_SIZE = 0x64000

TEB_BASE = 0x7ffde000
TEB_SIZE = 0x1000

HEAP_BASE = 0x130e0000
HEAP_SIZE = 0x100000

GDT_ADDR = 0x0
GDT_SIZE = 0x1000


class IGdt(object):
    def __init__(self, emu, gdt_address, gdt_size):
        self.emu = emu
        self.emu.mem_map(gdt_address, gdt_size)
        self.emu.reg_write(UC_X86_REG_GDTR, (0, gdt_address, gdt_size, 0x0))
        
        self.gdt_address = gdt_address
        self.gdt_entry_count = 0
        
    def create_selector(self, idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret
    
    def create_gdt_entry(self, base, limit, access, flags):
        to_ret = limit & 0xffff;
        to_ret |= (base & 0xffffff) << 16;
        to_ret |= (access & 0xff) << 40;
        to_ret |= ((limit >> 16) & 0xf) << 48;
        to_ret |= (flags & 0x0f) << 52;
        to_ret |= ((base >> 24) & 0xff) << 56;
        return pack('<Q',to_ret)
    
    def CreateSegmentSelector(self, seg_reg, seg_addr, seg_size, access):
        if self.gdt_entry_count < MAX_GDT:
            gdtidx = self.gdt_entry_count+1 # Add a gdt entry from index 1 (because the first entry is reserved?)
            
            gdt_entry = self.create_gdt_entry(seg_addr, seg_size, access, F_PROT_32 | F_PAGE_GRANULARITY)
            self.emu.mem_write(self.gdt_address + 8*gdtidx, gdt_entry)
    
            selector = self.create_selector(gdtidx, S_GDT | S_PRIV_3)
            self.emu.reg_write(seg_reg, selector)
            
            self.gdt_entry_count += 1
            
            return selector
        
    def Setup(self, teb):
        ds = self.CreateSegmentSelector(UC_X86_REG_DS, 0x0, 0xfffff, A_PRESENT | A_PRIV_3 | A_DATA | A_DATA_WRITABLE | A_DIRECTION_UP)
        es = self.CreateSegmentSelector(UC_X86_REG_ES, 0x0, 0xfffff, A_PRESENT | A_PRIV_3 | A_DATA | A_DATA_WRITABLE | A_DIRECTION_UP)
        fs = self.CreateSegmentSelector(UC_X86_REG_FS, teb, 1,      A_PRESENT | A_PRIV_3 | A_DATA | A_DATA_WRITABLE | A_DIRECTION_UP)   # FIXME: Correct the limit
        gs = self.CreateSegmentSelector(UC_X86_REG_GS, 0x0, 0xfffff, A_PRESENT | A_PRIV_3 | A_DATA | A_DATA_WRITABLE | A_DIRECTION_UP)            
        cs = self.CreateSegmentSelector(UC_X86_REG_CS, 0x0, 0xfffff, A_PRESENT | A_PRIV_3 | A_CODE | A_CODE_READABLE | A_CONFORMING)
        #ss = self.CreateSegmentSelector(UC_X86_REG_SS, 0x0, 0xfffff, A_PRESENT | A_PRIV_3 | A_DATA | A_DATA_WRITABLE | A_DIRECTION_DOWN) 
        
        #print ds, es, fs, gs, cs, ss
    

class ESC:
    def __init__(self, dumpPath):
        self.dmp = WinDump.WinDump(dumpPath)
        self.em = Uc(UC_ARCH_X86, UC_MODE_32)
        #
        self.em.mem_map(STACK_TOP, STACK_SIZE)
        self.em.mem_map(CODE_BASE, CODE_SIZE)
        self.em.mem_map(TEB_BASE, TEB_SIZE)
        self.em.mem_map(HEAP_BASE, HEAP_SIZE)

    def setShellCode(self, addr, shellcode):
        self.shellcode = shellcode
        self.shellcode_addr = addr
        self.em.mem_write(addr, self.shellcode)

    def initGDT(self):
        self.igdt = Igdt(self.em, 0x0, 0x1000)
        self.igdt.Setup(TEB_BASE)


    def initRegs(self):
        self.em.reg_write(UC_X86_REG_EAX, 0xd7)
        self.em.reg_write(UC_X86_REG_EBX, 0x032616e8 )
        self.em.reg_write(UC_X86_REG_ECX, 0x130e1000)
        self.em.reg_write(UC_X86_REG_EDX, 0x130e105a)
        self.em.reg_write(UC_X86_REG_EIP, 0x130e3000)
        self.em.reg_write(UC_X86_REG_ESP, 0x130e105e)
        self.em.reg_write(UC_X86_REG_ESI, 0x0)
        self.em.reg_write(UC_X86_REG_EDI, 0x0052e418)

    def initMem(self, addr, size):
        data = self.dmp.readMem(addr, size)
        self.em.mem_write(addr, data)

    def printStack(self, size=0x40):
        esp = self.em.reg_read(UC_X86_REG_ESP)
        stack = self.em.mem_read(esp, 0x40)
        stack = binascii.hexlify(stack)
        print(stack)


def main():
    esc = ESC("~/study/WINWORD3.DMP")
    print("load DMP done")

    #init GDT
    esc.initGDT()

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
    esc.em.emu_start(esc.shellcode_addr, esc.shellcode_addr+len(esc.shellcode))
    print("DONE")
    esc.printStack()




if __name__ == "__main__":
    main()
