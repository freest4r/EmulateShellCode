import os, re


class WinDump:
    def __init__(self, dumpPath):
        self.dump = dumpPath

    def readMem(self, addr, size=0x20):
        hexstr = ''
        p = os.popen("minidump -r "+str(addr)+" -s "+str(size)+" "+self.dump)
        data = p.read()
        for m in re.finditer("([0-9a-f]){2} ", data):
            hexstr += m.group()
        hexstr = hexstr.replace(" ", "")
        '''
        data = data.split("\n")
        for i in range(len(data)):
            line = data[i].split()
            for j in range(1, len(line)-1):
                hexstr += line[j]
        '''
        return hexstr

