# Evil-Twin-Attack

An Evil Twin Attack using Kali Linux and Python Scripts.

This project is a final project in a cyber course.

## How it works

1) Scan the networks.

2) Select network.

3) See all connected client to the selected network

4) A Deauthentication attack on selected client

5) Create one FakeAP imitating the original

6) A DHCP server is created on FakeAP

7) It creates a DNS server to redirect all requests to the Host

8) The web server with the selected interface is launched

9) The client connects to the fake ap and redirect to the fake web

10) The client enters his password and the password saved in the database

## Requirements

* scapy

* dnsmasq

* hostapd

## How To Use:
run:  sudo Python3 main.py

## References:

https://www.thepythoncode.com/code/building-wifi-scanner-in-python-scapy

https://www.thepythoncode.com/article/building-wifi-scanner-in-python-scapy

https://www.digitalwhisper.co.il/files/Zines/0x22/DW34-4-EvilTwinAttacks.pdf

https://rootsh3ll.com/evil-twin-attack/

https://duthcode.com/Blog/blogPostContent.php?post=deauthentication-attack-using-kali-linux-18

https://www.pentesteracademy.com/course?id=14
