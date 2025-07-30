import os
import sys
import time
import ctypes
from collections import defaultdict
#defayktdict is used to store and manage packet counts for each ip address
from scapy.all import sniff, IP
#we import the sniff and IP class which allows us to analyze network packets here

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")
# threshold for a DOS attack

def is_admin():
    try:
        return os.geteuid() == 0
    except AttributeError:
        # we're likely in Windows
        return ctypes.windll.shell32.IsUserAnAdmin()


#callback function to increment packet counts for each source ip address calculating the packet rate and blocking the IP etherade exceeds the threshold
def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            # print(f"IP: {ip}, Packet rate: {packet_rate}")
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

#main to check root privileges, initializing packet count and start time variables and starting the packet snapping process with a specified callback function
if __name__ == "__main__":

    if not is_admin():
        print("this script requires admin/root privileges.")
        sys.exit(1)

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)
