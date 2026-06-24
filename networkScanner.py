import scapy.all as scapy
import argparse

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []

    for element in answered:
        client_dict = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        client_list.append(client_dict)

    return client_list


def print_result(result_list):
    print("\nIP\t\tMAC Address")
    print("----------------------------------")

    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


parser = argparse.ArgumentParser(description="ARP Scanner")
parser.add_argument("-t", "--target IP", dest="target", help="Target IP / subnet")
options = parser.parse_args()

result = scan(options.target)
print_result(result)