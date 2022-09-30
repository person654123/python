#!/usr/bin/env python
import scapy.all as scapy
import optparse as opt


parser = opt.OptionParser()
parser.add_option("-t", "--target", dest = "ip", help ="enter ip address")
(option, arg) = parser.parse_args()
ip = option.ip
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    #print(arp_request.summary())
    #scapy.ls(scapy.ARP())
    #arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #broadcast.show()
    #print(broadcast.summary())
    arp_request_broadcast = broadcast/arp_request
    #print(arp_request_broadcast.summary())
    #arp_request_broadcast.show()
    answered_list= scapy.srp(arp_request_broadcast, timeout = 1, verbose=False)[0]
    
    #print("IP\t\t\tMAC Address\n---------------------------------------")
    clients_list = []
    for i in answered_list:
        client = {"ip":i[1].psrc, "mac":i[1].hwsrc}
        clients_list.append(client)
        #print(i[1].psrc + "\t\t" +         i[1].hwsrc)
       
        print("------------------------------------------------------------------")
    #print(clients_list)
    return clients_list        

def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] )

scan_result = scan(ip)
print_result(scan_result)
