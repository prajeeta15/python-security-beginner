import sys
from scapy.all import ICMP, IP, sr1
from netaddr import IPNetwork
# net adder is used to handle ip address manipulation and calculations

# ping sweeper is a simple and useful tool that we can use in order to find all active hosts on a subnet
# so if we give it a subnet and net mask -a range of ips on the same subnet then it will detect which of those ips are actually live


def ping_sweep(network, netmask):
    live_hosts = []
    total_hosts = 0
    scanned_hosts = 0

    ip_network = IPNetwork(network + '/' + netmask)
    for host in ip_network.iter_hosts():
        total_hosts += 1

    for host in ip_network.iter_hosts():  # scanning ips
        scanned_hosts += 1
        print(f"Scanning: {scanned_hosts}/{total_hosts}", end="\r")
        # arg sent to sr1 function part of scapy that changes the packet and waits for a single reponse - icmp echo request packet, timeout value, verbosity
        response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)
        if response is not None:  # if any of the 3 values mainly response packet is returned then active ip
            live_hosts.append(str(host))
            print(f"Host {host} is online.")

    return live_hosts
# receives a given network and net mask from the user and then performs a ping sweep on each associated IP and ultimately returns a list of live hosts


if __name__ == "__main__":
    network = sys.argv[1]
    netmask = sys.argv[2]

    live_hosts = ping_sweep(network, netmask)
    print("Completed\n")
    print(f"Live hosts: {live_hosts}")
