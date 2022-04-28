from email import message
from typing import Type
from xmlrpc.client import Boolean
from ArpPackage import ARPPackage


class Network:
    def __init__(self):
        self.hosts = []
        
    def Connect_computer_to_network(self, host):
        self.hosts.append(host)

    def Handle_ARP_Request(self, ARP_request: ARPPackage):
        destIP = ARP_request.Payload['Target IP address']

        if ARP_request.Payload['Opcode'] == 1:
            print(f"{self.findHost_From_Mac(ARP_request.Header['Source']).name} is requesting ARP reply from IP: {destIP}")
            for host in self.hosts:
                if host.IP == destIP:
                    ARP_Reply = host.Answer_ARP_Request(ARP_request)
                    self.Handle_ARP_Request(ARP_Reply)
        elif ARP_request.Payload['Opcode'] == 2:
            self.findHost_From_Mac(ARP_request.Header['Destination']).Recieve_ARP_Reply(ARP_request)

    def findRouter(self, inHost):
        for host in self.hosts:
            if host.isRouter:
                host.Add_To_Cache(inHost.IP, inHost.MAC)
                return host.IP

    def findHost(self, IP, MAC):
        for host in self.hosts:
            if host.IP == IP and host.MAC == MAC:
                return host
    
    def findHost_From_Mac(self, MAC):
        for host in self.hosts:
            if host.MAC == MAC:
                returnhost = host
                return returnhost

class Host:
    def __init__(self, name, IP, MAC, network: Network, isRouter: Boolean):
        self.name = name
        self.IP = IP
        self.MAC = MAC
        self.cache = {}
        self.network = network
        self.isRouter = isRouter
        self.relay = False
        self.spoofedMACS = []
        self.message_alter = ''
        network.Connect_computer_to_network(self)
        if not isRouter:
            ARP_request = ARPPackage(self.MAC, self.IP, '', self.network.findRouter(self), 1)
            self.network.Handle_ARP_Request(ARP_request)


    #Function regarding ARP requests/replies and caching
    def Add_To_Cache(self, IP, MAC):
        self.cache.update({IP: MAC})

    def Recieve_ARP_Reply(self, ARP_reply: ARPPackage):
        print(f"{self.name} has received ARP reply containing: IP: {ARP_reply.Payload['Sender IP address']} MAC: {ARP_reply.Payload['Sender MAC address']}")
        self.Add_To_Cache(ARP_reply.Payload['Sender IP address'], ARP_reply.Payload['Sender MAC address'])
    
    def Answer_ARP_Request(self, ARP_request: ARPPackage):
        print(f"{self.name} has received ARP request from: IP: {ARP_request.Payload['Sender IP address']} MAC: {ARP_request.Payload['Sender MAC address']}")
        self.Add_To_Cache(ARP_request.Payload['Sender IP address'], ARP_request.Payload['Sender MAC address'])
        ARP_Reply = ARPPackage(self.MAC, self.IP, ARP_request.Payload['Sender MAC address'], ARP_request.Payload['Sender IP address'], 2)
        return ARP_Reply

    #Everything under here is used to send a message(And is therefore simplified as it does not have anything to do with ARP)
    def SendMessage(self, destIP, message):
        MAC = ""
        if destIP in self.cache:
            print(f"{self.name} found MAC for {destIP} in cache")
            MAC = self.cache[destIP]
            dest_host = network.findHost_From_Mac(MAC)
            dest_host.ReceiveMessage('"' + message + '"' + ' from ' + self.name, self.MAC)
        else:
            ARP_request = ARPPackage(self.MAC, self.IP, '', destIP, 1)
            self.network.Handle_ARP_Request(ARP_request)
            self.SendMessage(destIP, message)

    def ReceiveMessage(self, message, MAC):
        if self.relay:
            self.Relay_Message(message, MAC)
        else:
            print(f"{self.name} has received message: {message}")


    #Everything under here is only used by attacker
    def Send_Spoofed_ARP_Reply(self, destIP, newIP):
        ARP_request = ARPPackage(self.MAC, self.IP, '', destIP, 1)
        self.network.Handle_ARP_Request(ARP_request)
        MAC = self.cache[destIP]
        self.spoofedMACS.append(MAC)

        spoofed_ARP_Reply = ARPPackage(self.MAC, newIP, MAC, destIP, 2)
        print(f"{self.name} is sending spoofed ARP reply to {self.network.findHost(destIP, MAC).name} containing: IP: {newIP} MAC: {self.MAC}")
        self.network.Handle_ARP_Request(spoofed_ARP_Reply)

    def Start_Relay(self, message_alter = ''):
        print(f"{self.name} relaying with message: {message_alter}")
        self.relay = True
        self.message_alter = message_alter

    def Relay_Message(self, message, MAC):
        if self.spoofedMACS[0] == MAC:
            self.__Send_altered_message(message, self.spoofedMACS[1])
        else:
            self.__Send_altered_message(message, self.spoofedMACS[0])
    
    def __Send_altered_message(self, message, MAC):
        dest_host = network.findHost_From_Mac(MAC)
        print(f'{self.name} relaying and reading message: {message}')
        dest_host.ReceiveMessage(message + self.message_alter, MAC)

    def __str__(self) -> str:
        return f"{self.name} || {self.IP} || {self.MAC}"

network = Network()
router = Host("Router", "192.60.20.0", "00-00-00-00-00-00", network, True)
computer1 = Host("Computer1", "192.60.20.1", "01-01-01-01-01-01", network, False)
computer2 = Host("Computer2", "192.60.20.2", "02-02-02-02-02-02", network, False)
attacker = Host("Attacker", "192.60.20.3", "03-03-03-03-03-03", network, False)

print("---------------------------------------------------------------------------------------------")
for host in network.hosts:
    print(f'{host.name} ARP cache | {host.cache}')
print("---------------------------------------------------------------------------------------------")
computer1.SendMessage(router.IP, "hello")
print("---------------------------------------------------------------------------------------------")
for host in network.hosts:
    print(f'{host.name} ARP cache | {host.cache}')
print("---------------------------------------------------------------------------------------------")
computer1.SendMessage(computer2.IP, "hello")
print("---------------------------------------------------------------------------------------------")
for host in network.hosts:
    print(f'{host.name} ARP cache | {host.cache}')
print("---------------------------------------------------------------------------------------------")
attacker.Send_Spoofed_ARP_Reply(computer1.IP, '192.60.20.0')
print("---------------------------------------------------------------------------------------------")
attacker.Send_Spoofed_ARP_Reply(router.IP, '192.60.20.1')
print("---------------------------------------------------------------------------------------------")
attacker.Start_Relay(" Altered by attacker")
print("---------------------------------------------------------------------------------------------")
router.SendMessage(computer1.IP, "hello")
print("---------------------------------------------------------------------------------------------")
computer1.SendMessage(router.IP, "hello")
print("---------------------------------------------------------------------------------------------")

for host in network.hosts:
    print(f'{host.name} ARP cache | {host.cache}')