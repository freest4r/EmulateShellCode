import os
class WinDump:
    def __init__(self, dumpPath):
        self.dump = dumpPath

    def readMem(self, addr, size=0x20):
        print("MINIDUMP -r %x -s %x"%(addr, size))
        hexstr = ''
        p = os.popen("minidump -r "+str(addr)+" -s "+str(size)+" "+self.dump)
        data = p.read()

        data = data.split("\n")
        for i in range(len(data)):
            line = data[i]
            line = line[18:67].split(" ")
            for j in range(len(line)):
                hexstr += line[j]
        return hexstr

