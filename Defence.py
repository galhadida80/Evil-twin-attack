import os
import PySimpleGUI as sg

sg.theme('DarkTeal9')

from scapy.all import *

global command
global interfaces
global monitor_interface
interfaces = ['wlan0', 'wlan1']



def gui_line_printer(str):
    global command
    os.system(str)
    command = str


def monitor():
    global monitor_interface
    gui_line_printer('service NetworkManager stop')
    gui_line_printer('airmon-ng check kill')
    gui_line_printer('ifconfig ' + monitor_interface + ' down')
    gui_line_printer('iwconfig ' + monitor_interface + ' mode monitor')
    gui_line_printer('ifconfig ' + monitor_interface + ' up')



def layout_choose_adapters():
    global layout
    layout = [[sg.Text('Choose adapters')],
              [sg.Text('Please type the interface name you want to put in Monitor Mode')],
              [sg.Listbox(interfaces, size=(10, len(interfaces)), enable_events=True, key='_monitor_interface_')],
              [sg.Text('command run')],
              [sg.Text('', key='_printer_', size=(60, 1), justification='center', text_color='blue',
                       background_color='white')],
              [sg.Button('select adapter'), sg.Button('Cancel')]]
    return layout


### After we finish our attack, we want to switch back the interface to 'managed mode'.
def managed():
    global monitor_interface

    gui_line_printer('ifconfig ' + monitor_interface + ' down')
    gui_line_printer('iwconfig ' + monitor_interface + ' mode managed')
    gui_line_printer('ifconfig ' + monitor_interface + ' up')


##############################################
############## Deauthentication ##############
##############################################

### In this function we sniff all the packets, and if we recognize that 30 packets of deauthentication has been sniffed we will alert that there is attempt to do deathentication attack
def deathentication_check():
    global monitor_interface
    monitor_interface="wlan0"
    sniff(iface=monitor_interface, prn=packet_handler, stop_filter=stopfilter)
    sg.popup_error('your AP is under deauthattack')



count = 0


def packet_handler(pkt):
    global count

    if pkt.type == 0 or pkt.subtype == 0xC:
        count = count + 1


def stopfilter(x):
    if count == 25:
        return True
    else:
        return False

def thread_side(fun):
    ap_thread = Thread(target=fun)
    ap_thread.daemon = True
    ap_thread.start()

if __name__ == "__main__":
    global monitor_interface
    global command
    command=''
    window = sg.Window('evil-twin attack', size=(550, 300), element_justification='c'). \
        Layout(layout_choose_adapters())

    while True:
        event, values = window.read(timeout=10)
        if event == 'select adapter':
            monitor_interface=values['_monitor_interface_'][0]
            time.sleep(1)

            monitor()
            deathentication_check()
            managed()
        if command !='':
            window['_printer_'].update(command)
        if event == sg.WIN_CLOSED or event == 'Cancel':  # if user closes window or clicks cancel
            break

