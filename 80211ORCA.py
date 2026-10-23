print("""\033[35m
⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠺⢿⣿⣿⣿⣿⣿⣿⣷⣦⣠⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿\033[31mHACK\033[34m⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣿⣿⣷⣄⠀⠀
⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣀⠀⠀⠀⣀⣿⣿⣿⣆⠀
⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄
⠀⠀⠀⠀⣾⣿⣿⡿⠋⠁⣀⣠⣬⣽⣿⣿\033[31mTHE\033[34m⣿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠁
⠀⠀⠀⢀⣿⣿⡏⢀⣴⣿⠿⠛⠉⠉⠀⢸⣿⣿⠿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣿⣿⢠⣾⡟⠁⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣿⣿⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣸⣿⣿⣿⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣾⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾\033[31mPLANET\033[34m⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⡿⠛⠉⠀⠀⠀⠈⠙⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
\033[0m""")

import os
import psutil
from rich import print
from rich.prompt import Prompt
from threading import Thread
from time import sleep
from datetime import datetime
from scapy.all import *

if os.getuid() != 0:
    print("\033[31m[-] NEED ROOT.\033[0m")
    exit(1)

def getPCAPfilename():
    d = datetime.now()
    return f"{d.day}_{d.month}_{d.year}__{d.hour}-{d.minute}.pcap"

PCAP = getPCAPfilename()

def handshake_sniffer(pkt):
    global handshake_fragments

    pktdmp = PcapWriter(PCAP,append=True,sync=True)
    pktdmp.write(pkt)

    if EAPOL in pkt:
        handshake_fragments += 1
        print(f"[bright_black]+[/bright_black] Captured [green][underline]{handshake_fragments}[/underline][/green] EAPOL packets")

    if handshake_fragments >= 10:
        return True

def intercept_handshakes(interf):
    sniff(stop_filter=handshake_sniffer, iface=interf, monitor=True)

def channel_switcher(interface):
    while True:
        for channel in range(1,14):
            os.popen(f"iwconfig {interface} channel {channel}").read()
            print(f"[bright_cyan]Channel[/bright_cyan]: [gray]{channel}[/gray]",end="\r")
            sleep(0.2)

addrs = list(psutil.net_if_addrs())
interface = Prompt.ask("Select an [bold][cyan]interface[/cyan][/bold]",choices=addrs,default=addrs[-1])

Thread(target=intercept_handshakes, args=(interface,)).start()
Thread(target=channel_switcher, args=(interface,)).start()
