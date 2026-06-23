
import scapy.all as scapy

def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast=broadcast/arp_request
    arp_request_broadcast.show()
    
    #answered,unanswered=scapy.srp(arp_request_broadcast,timeout=1)
    answered=scapy.srp(arp_request_broadcast,timeout=1)[0]
    
    for element in answered:
        print("ip >", element[1].psrc)
        print("mac >", element[1].hwsrc)
        print("--------------------------------------------------------")


    


scan("172.20.144.0/20")