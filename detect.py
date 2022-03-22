#!/usr/bin/env python
import sys
import scapy.all as scapy
import time

def get_mac(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request_packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def sniff(interface):
    try:
        print("\nMAC adresiniz: ",scapy.Ether().src)
        print("\nIncelenebilir interfaceler: \n", scapy.get_if_list())
        get_interface = input("\nDinlemek istediginiz interface'i seciniz\n")
        print("Sectiginiz interface: ",get_interface,"\n",get_interface," dinleniyor...")
        interface = get_interface

        if get_interface == "":
            print("Lutfen bir interface belirtin...")
        else:
            scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)
    except (OSError, ValueError):
        print("Boyle bir interface bulunmuyor...")


def process_sniff_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                time.sleep(3)
                print("ARP Saldirisi Altindasiniz !")
                print(f"Gercek MAC: {real_mac.upper()},Saldiran kisi'nin MAC: {response_mac.upper()}")

        except IndexError:
            pass

sniff(interface="")


