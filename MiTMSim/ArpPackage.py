import opcode


class ARPPackage:
    def __init__(self, srcMAC, srcIP, destMAC, destIP, Opcode) -> None:
        self.srcMAC = srcMAC
        if Opcode == 1:
            self.destMAC = 'ff:ff:ff:ff:ff:ff'
        else:
            self.destMAC = destMAC
        self.etherType = 0x0806

        self.Header = {
            'Destination': self.destMAC,
            'Source': self.srcMAC,
            'Type': self.etherType 
        }

        self.Payload = {
            'Hardware type': 1,
            'Protocol type': 0x0800,
            'Hardware size': 4,
            'Protocol size': 6,
            'Opcode': Opcode,
            'Sender MAC address': srcMAC,
            'Sender IP address': srcIP,
            'Target MAC address': self.destMAC,
            'Target IP address': destIP
        }