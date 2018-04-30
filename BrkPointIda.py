import idaapi
import idc
class BrkPointIda:
    def __init__(self,filename):
        self.parsedRegData = self.readBTDump(filename)
        self.brk_addr = self.getBreakAddr(self.parsedRegData)
        self.ret_val = self.setBreakPointWithComment(self.brk_addr)


    def setComment(self, cmnt_values):
        MakeComm(ScreenEA(), cmnt_values)

    def readBTDump(self, filename):
        output=[]
        with open(filename,'r') as filein:
            output=filein.readlines()
        return output

    def getBreakAddr(self, output):
        eip_addr=0 # initialize eip_addr to zero incase reg not found
        for each_line in output: # search for the eip register in bt dump 
            if 'eip' in each_line: 
                eip_addr=int(each_line.split()[1],16) #extract register address
        return eip_addr

    def setBreakPointWithComment(self, brk_addr):
        idc.jumpto(brk_addr)
        self.setComment("")
        self.setComment("$EIP: 0x%x" % brk_addr)
        idc.AddBpt(brk_addr)

x = BrkPointIda('C:/Users/workshopadmin/Desktop/vm_share/dumptxt/btdump2018.04.19-01.29.41.log')
idc.jumpto(0x081012CF)
idc.AddBpt(0x081012CF)
