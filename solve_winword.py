from __future__ import print_function
from capstone import *
from unicorn import *
from unicorn.x86_const import *
from struct import pack
import sys, binascii
import WinDump


'''
sc = "6064a1000000008b4004250000ffff6681384d5a751781783c00020000730e8b503c03d066813a50457502eb072d00000100ebdb8b7a1c8b722c03f003fe83ed048b4d003bce72183bcf73148079fdff750e8079fe5075088079ff107502eb02ebdc896c24186187e1608bece8000000008b34248d64240481ee7100000081c6a000000068dc000000598d3c8e6a1f58d12fd11683c6044875066a1f5883c7047177b2452c98c52d86c52d0ec52984452190c50d409c36003980ba04403c023b8031003a88409c268029803aef403c022b8021003a6b297428000000c5f2b061aa45f64162fc292b2b7400000080451e92c1e301c1737e5caaaaaa2afe99e424"

eax=130e1032 ebx=032616e8 ecx=130e1000 edx=0052efa8 esi=0052e418 edi=00000000
eip=692dba19 esp=001ac49c ebp=001ac4c8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
https://gist.github.com/sparktrend/256e3af76a2b542bff8c0bd647e3feca
https://scoding.de/setting-global-descriptor-table-unicorn
https://rev.ng/gitlab/angr/simuvex/blob/d8c932fe7eda9e17e7d555da8d7830b5b293cc6d/simuvex/plugins/unicorn_engine.py
'''
scode ="\x60"
scode+="\x64\xa1\x00\x00\x00\x00"
scode+="\x8b\x40\x04"
scode+="\x25\x00\x00\xff\xff"
scode+="\x66\x81\x38\x4d\x5a"
scode+="\x75\x17"
scode+="\x81\x78\x3c\x00\x02\x00\x00"
scode+="\x73\x0e"
scode+="\x8b\x50\x3c"
scode+="\x03\xd0"
scode+="\x66\x81\x3a\x50\x45"
scode+="\x75\x02"
scode+="\xeb\x07"
scode+="\x2d\x00\x00\x01\x00"
scode+="\xeb\xdb"
scode+="\x8b\x7a\x1c"
scode+="\x8b\x72\x2c"
scode+="\x03\xf0"
scode+="\x03\xfe"
scode+="\x83\xed\x04"
scode+="\x8b\x4d\x00"
scode+="\x3b\xce"
scode+="\x72\x18"
scode+="\x3b\xcf"
scode+="\x73\x14"
scode+="\x80\x79\xfd\xff"
scode+="\x75\x0e"
scode+="\x80\x79\xfe\x50"
scode+="\x75\x08"
scode+="\x80\x79\xff\x10"
scode+="\x75\x02"
scode+="\xeb\x02"
scode+="\xeb\xdc"
scode+="\x89\x6c\x24\x18"
scode+="\x61"
scode+="\x87\xe1"
scode+="\x60"
scode+="\x8b\xec"
scode+="\xe8\x00\x00\x00\x00"
scode+="\x8b\x34\x24"
scode+="\x8d\x64\x24\x04"
scode+="\x81\xee\x71\x00\x00\x00"
scode+="\x81\xc6\xa0\x00\x00\x00"
scode+="\x68\xdc\x00\x00\x00"
scode+="\x59"
scode+="\x8d\x3c\x8e"
scode+="\x6a\x1f"
scode+="\x58"
scode+="\xd1\x2f"
scode+="\xd1\x16"
scode+="\x83\xc6\x04"
scode+="\x48"
scode+="\x75\x06"#130e3098
scode+="\x6a\x1f"
scode+="\x58"
scode+="\x83\xc7\x04"
scode+="\x71\x77"
scode+="\xb2\x45"
scode+="\x2c\x98"
scode+="\xc5\x2d\x86\xc5\x2d\x0e"
scode+="\xc5\x29"
scode+="\x84\x45\x21"
scode+="\x90"#130e30b1 nop
scode+="\xc5\x0d\x40\x9c\x36\x00"
scode+="\x39\x80\xba\x04\x40\x3c"
scode+="\x02\x3b"
scode+="\x80\x31\x00"
#scode+="\x3a\x88\x40\x9c\x26\x80\x29\x80\x3a\xef\x40\x3c\x02\x2b\x80\x21\x00\x3a\x6b\x29\x74\x28\x00\x00\x00\xc5\xf2\xb0\x61\xaa\x45\xf6\x41\x62\xfc\x29\x2b\x2b\x74\x00\x00\x00\x80\x45\x1e\x92\xc1\xe3\x01\xc1\x73\x7e\x5c\xaa\xaa\xaa\x2a\xfe\x99\xe4\x24"

GDT_ADDR = 0x3000
GDT_LIMIT = 0x1000
GDT_ENTRY_SIZE = 0x8

GS_SEGMENT_ADDR = 0x5000
GS_SEGMENT_SIZE = 0x1000

F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1 

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_EXEC = 0x8
A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

#########
STACK_BASE = 0x1b0000
STACK_TOP = 0xb0000
STACK_SIZE = STACK_BASE - STACK_TOP

CODE_BASE = 0x69291000
CODE_SIZE = 0x64000

TEB_BASE = 0x7ffde000
TEB_SIZE = 0x1000

HEAP_BASE = 0x130e0000
HEAP_SIZE = 0x100000

def printStack(em, size=0x40):
    esp = em.reg_read(UC_X86_REG_ESP)
    stack = binascii.hexlify(em.mem_read(esp, size))
    data = ''
    for i in range(0,len(stack),8):
        if i%32 == 0:
            data = str(hex(esp))+"  "
            esp+=0x10
        data += stack[i:i+8]+" "
        if i%32 == 24:
            print(data)
            data = ''

def printRegs(em):
    eax = em.reg_read(UC_X86_REG_EAX)
    ebx = em.reg_read(UC_X86_REG_EBX)
    ecx = em.reg_read(UC_X86_REG_ECX)
    edx = em.reg_read(UC_X86_REG_EDX)
    esi = em.reg_read(UC_X86_REG_ESI)
    edi = em.reg_read(UC_X86_REG_EDI)
    eip = em.reg_read(UC_X86_REG_EIP)
    esp = em.reg_read(UC_X86_REG_ESP)
    ebp = em.reg_read(UC_X86_REG_EBP)
    print("eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x"%(eax,ebx,ecx,edx,esi,edi))
    print("eip=%x esp=%x ebp=%x"%(eip,esp,ebp))

def hook_code(em, addr, size, data):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    ins = em.mem_read(addr, size)
    print("--------------------------------------")
    asm = md.disasm(str(ins),addr)
    for a in asm:
        print("%x: %-8s\t%s\t%s" % (a.address, binascii.hexlify(ins), a.mnemonic, a.op_str) )
        if size == None:
            break
    printRegs(em)
    printStack(em) 

def hook_mem_invalid(em, access, addr, size, value, data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print("UNMAPPED MEMORY WRITE at 0x%x, size: %u, value: 0x%x"%(addr, size, value))
    else:
        print("UNMAPPED MEMORY READ at 0x%x, size: %u, value: 0x%x"%(addr, size, value))
    return False

def hook_mem_access(em, access, addr, size, value, data):
    if access == UC_MEM_WRITE:
        print("Memory write at 0x%x, size: %u, value: 0x%x"%(addr, size, value)) 
    else:
        print("Memory read at 0x%x, size: %u, value: 0x%x"%(addr, size, value)) 
    return False


class ESC:
    def __init__(self, dumpPath):
        self.dmp = WinDump.WinDump(dumpPath)
        self.em = Uc(UC_ARCH_X86, UC_MODE_32)
        #
        self.em.mem_map(STACK_TOP, STACK_SIZE)
        self.em.mem_map(CODE_BASE, CODE_SIZE)
        self.em.mem_map(0x69290000, 0x1000)
        self.em.mem_map(TEB_BASE, TEB_SIZE)
        self.em.mem_map(HEAP_BASE, HEAP_SIZE)
        #
        self.em.hook_add(UC_HOOK_CODE, hook_code)
        #self.em.hook_add(UC_HOOK_MEM_READ, hook_mem_access)
        #self.em.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)
        self.em.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid)
        self.em.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)


    def setShellCode(self, addr, shellcode):
        self.shellcode = shellcode
        self.shellcode_addr = addr
        self.em.mem_write(addr, self.shellcode)

    def create_selector(self, idx, flags):
	to_ret = flags
	to_ret |= idx << 3
	return to_ret

    def create_gdt_entry(self, base, limit, access, flags):
	to_ret = limit & 0xffff;
	to_ret |= (base & 0xffffff) << 16;
	to_ret |= (access & 0xff) << 40;
	to_ret |= ((limit >> 16) & 0xf) << 48;
	to_ret |= (flags & 0xff) << 52;
	to_ret |= ((base >> 24) & 0xff) << 56;
	return pack('<Q',to_ret)

    def write_gdt(self, gdt, mem):
	for idx, value in enumerate(gdt):
	    offset = idx * GDT_ENTRY_SIZE
	    self.em.mem_write(mem + offset, value)

    def initGDT(self):
        self.em.mem_map(GDT_ADDR, GDT_LIMIT)
        self.em.mem_map(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE)
        gdt = [self.create_gdt_entry(0,0,0,0) for i in range(31)]
        gdt[15] = self.create_gdt_entry(GS_SEGMENT_ADDR, GS_SEGMENT_SIZE, A_PRESENT | A_DATA |
                A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
        gdt[16] = self.create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)  # Data Segment
        gdt[17] = self.create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32)  # Code Segment
        gdt[18] = self.create_gdt_entry(0, 0xfffff000 , A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # Stack Segment
        gdt[19] = self.create_gdt_entry(0x7ffde000, 0x00000fff , A_PRESENT | A_DATA | A_DATA_WRITABLE |
                A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)  # FS 

        self.write_gdt(gdt, GDT_ADDR)
        self.em.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, len(gdt) * GDT_ENTRY_SIZE-1, 0x0))

        selector = self.create_selector(15, S_GDT | S_PRIV_3)
        self.em.reg_write(UC_X86_REG_GS, selector)

        selector = self.create_selector(16, S_GDT | S_PRIV_3)
        self.em.reg_write(UC_X86_REG_DS, selector)

        selector = self.create_selector(17, S_GDT | S_PRIV_3)
        self.em.reg_write(UC_X86_REG_CS, selector)

        selector = self.create_selector(18, S_GDT | S_PRIV_0)
        self.em.reg_write(UC_X86_REG_SS, selector)

        selector = self.create_selector(19, S_GDT | S_PRIV_0)
        self.em.reg_write(UC_X86_REG_FS, selector)

    def initRegs(self):
        self.em.reg_write(UC_X86_REG_EAX, 0xd7)
        self.em.reg_write(UC_X86_REG_EBX, 0x032616e8 )
        self.em.reg_write(UC_X86_REG_ECX, 0x130e1000)
        self.em.reg_write(UC_X86_REG_EDX, 0x130e105a)
        self.em.reg_write(UC_X86_REG_ESI, 0x0052e418)
        self.em.reg_write(UC_X86_REG_EDI, 0x0)
        self.em.reg_write(UC_X86_REG_EIP, 0x130e3000)
        self.em.reg_write(UC_X86_REG_ESP, 0x130e105e)
        self.em.reg_write(UC_X86_REG_EBP, 0x001ac4c8)

    def initMem(self, addr, size):
        data = self.dmp.readMem(addr, size)
        data = binascii.unhexlify(data)
        self.em.mem_write(addr, data)
        m = self.em.mem_read(addr, size)

    def printStack(self, size=0x40):
        esp = self.em.reg_read(UC_X86_REG_ESP)
        print('esp', hex(esp))
        stack = self.em.mem_read(esp, size)
        stack = binascii.hexlify(stack)
        print(stack)


def main():
    esc = ESC("~/study/WINWORD3.DMP")
    print("load DMP done")

    #init GDT
    esc.initGDT()
    print("init GDT done")

    #init registers
    esc.initRegs()
    print("init regs done")
    
    #init mem
    esc.initMem(0x69290000, 0xfff)
    for i in range(1,6):
        esc.initMem(CODE_BASE+0x10000*i, 0x10000)
    for i in range(10):
        esc.initMem(HEAP_BASE+0x10000*i, 0x10000)
    esc.initMem(TEB_BASE, 0x100)
    esc.initMem(0x1ac000, 0x1000)
    #print(binascii.hexlify(esc.em.mem_read(0x130e30a0, 0x40)))

    #setShellCode
    esc.setShellCode(0x130e3000, scode)
    print("set shellcode done")
    print(binascii.hexlify(esc.em.mem_read(0x130e30a0, 0x40)))

    '''
    #start
    print("GO\n\n")
    esc.em.emu_start(esc.shellcode_addr, esc.shellcode_addr+len(esc.shellcode))
    print("\n\nDONE")
    '''


if __name__ == "__main__":
    main()
