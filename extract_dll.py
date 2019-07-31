import WinDump, binascii


KERNEL32_BASE = [0x76580000, 0x76581000, 0x76646000, 0x76647000]
KERNEL32_SIZE = [0x1000,0xc5000,0x1000,0xd000]

wind = WinDump.WinDump("./WINWORD3.DMP")

fp = open("kernel32.dll","wb")
for i in range(len(KERNEL32_BASE)):
    data = wind.readMem(KERNEL32_BASE[i], KERNEL32_SIZE[i]-1)
    fp.write(binascii.unhexlify(data))
fp.close()
