import struct
import string
import sys, binascii

def pop(em, esp):
    esp = em.mem_read(esp, 0x4)
    esp=struct.unpack("<I", esp)[0]
    return esp

def read_until_null(em, idx):
    ret = ''
    while True:
        c = em.mem_read(idx, 1)
        if c=="\x00":
            break
        ret += str(c)
        idx+=1
    return ret

def read_until_doublenull(em, idx):
    ret = ''
    while True:
        c = em.mem_read(idx, 2)
        if c=="\x00\x00":
            break
        ret += chr(c[0])
        idx+=2
    return ret

#FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
#);
def hook_GetProcAddress(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x8)
    lpProcName = read_until_null(em, arg2)
    print("GetProcAddress(%x, %s)"%(arg1, lpProcName))

#DWORD GetTempPathA(
#   WORD nBufferLength,
#   LPSTR lpBuffer
#);
def hook_GetTempPathA(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x8)
    print("GetTempPathA(0x%x, 0x%x)"%(arg1, arg2))

def hook_GetTempPathW(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x8)
    print("GetTempPathW(0x%x, 0x%x)"%(arg1, arg2))
    pass

#HANDLE CreateFileA(
#  LPCSTR                lpFileName,
#  DWORD                 dwDesiredAccess,
#  DWORD                 dwShareMode,
#  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#  DWORD                 dwCreationDisposition,
#  DWORD                 dwFlagsAndAttributes,
#  HANDLE                hTemplateFile
#);
def hook_CreateFileA(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x14)
    data = em.mem_read(arg1, 0x100)
    fname = read_until_null(em, arg1)
    print("CreateFileA(%s, %x)"%(str(fname), arg2))

def hook_CreateFileW(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x14)
    fname = read_until_doublenull(em, arg1)
    #data = em.mem_read(arg1, 0x100)
    #print binascii.hexlify(data)
    #print str(data)
    print("CreateFileW(%s, %x)"%(str(fname), arg2))

#BOOL WriteFile(
#   HANDLE hFile,
#   LPCVOID lpBuffer,
#   DWORD nNumberOfBytesToWrite,
#   LPDWORD lpNumberOfBytesWritten,
#   LPOVERLAPPED lpOverlapped
#);
def hook_WriteFile(em, esp):
    arg1 = pop(em, esp+0x4)
    arg2 = pop(em, esp+0x8)
    arg3 = pop(em, esp+0xc)
    arg4 = pop(em, esp+0x10)
    arg5 = pop(em, esp+0x14)
    print("WriteFile(%x, %x, %x, %x, %x)"%(arg1, arg2, arg3, arg4, arg5))
    data = em.mem_read(arg2, arg3)
    open("_write_file_","wb").write(data)

#BOOL CloseHandle(
#   HANDLE hObject
#);
def hook_CloseHandle(em, esp):
    arg1 = pop(em, esp+0x4)
    print("CloseHandle(%x)"%(arg1))

#HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
#);
def hook_LoadLibraryA(em, esp):
    arg1 = pop(em, esp+0x4)
    fname = read_until_null(em, arg1)
    print("LoadLibraryA(%s)"%(fname))
