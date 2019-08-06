import socket
import os, sys
import threading
import subprocess, multiprocessing
import ipaddress
from queue import Queue
from scapy.all import *
from datetime import datetime

class Net_tool():
    def __init__(self, hosts):
        self.hosts = hosts

    def general_scan(self, culo):
        scan_result = {}
        print_lock = threading.Lock()
        socket.setdefaulttimeout(1.5)
        temp = []

        def port_test(host, port):
            sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            scan_result[host] = []

            try:
                connection = sckt.connect_ex((host, port))
                with print_lock:
                    if connection == 0:
                        p_name = socket.getservbyport(port, "tcp")
                        temp.append([port, p_name])
                scan_result[host] = temp
                sckt.close()
            except:
                pass

        def threader():
            while 1:
                worker = stack.get()
                port_test(culo, worker)
                stack.task_done()
        stack = Queue()

        for tr in range(300):
            work = threading.Thread(target = threader)
            work.daemon = True
            work.start()

        for worker in range(1, 1025):
            stack.put(worker)
        stack.join()

        for host in scan_result.keys():
            print("\33[94m\nHost ---> {}".format(host))
            for port in scan_result[host]:
                print(f"\33[92mPort\33[94m{port[0]:5}   \33[92mservice   \33[94m{port[1]:10}")

        print("=" * 45)

    def run_GScan(self):
        for i in self.hosts:
            self.general_scan(i)

"""
class text_colors:
    CRED2    = '\33[91m'
    CGREEN2  = '\33[92m'
    CYELLOW2 = '\33[43m'
    CBLUE2   = '\33[94m'
"""

banner = """
    \33[91m     _   _      \33[93m  _____
    \33[91m    | \ | |     \33[93m / ____|
    \33[91m    |  \| |\33[94m_____\33[93m| (___   ___ __ _ _ __
    \33[91m    | . ` |\33[94m______\33[93m\___ \ / __/ _` | '_  \\
    \33[91m    | |\\  |    \33[93m  ____) | (_| (_| | | | |
    \33[91m    |_| \_|     \33[93m|_____/ \___\__,_|_| |_|

                                          \33[91mBy Ramphy\33[92m
"""
print(banner)
time_0 = datetime.now()
user_input = input("[*]IP address: ")
ip_address = str(user_input).split(".")
net_ip = ip_address[0] + "." + ip_address[1] + "." + ip_address[2] + "."
dict_l_hosts = []

range_s = []
test_hosts = []
if "-" in ip_address[3]:
    for val in ip_address[3].split("-"): range_s.append(int(val))
    if range_s[-1] != 255: range_s[-1] += 1
elif "/" in ip_address[3]:
    hosts_num = pow(2, 32 - int(ip_address[3].split("/")[1]))
    range_s.append(1)
    range_s.append(hosts_num)
    if range_s[-1] < 255:
        range_s[-1] += 1
    else:
        range_s[-1] -= 1
else:
    if len(user_input.split(" ")) > 1:
        for host in user_input.split(" "):
            test_hosts.append(host)
    else:
        range_s.append(int(ip_address[3]))
        range_s.append(int(ip_address[3]) + 1)

if len(test_hosts) == 0:
    for host in range(range_s[0], range_s[1]):
        test_hosts.append(net_ip + str(host))

lr_hosts = []; l_hosts = []

'''for host in test_hosts:
    ICMP_test = IP(dst = host) / ICMP()
    check = sr1(ICMP, timeout = 0.01)

    if check != None:
        l_host.append(host)
    else:
        pass
'''

def ping(host):

    test_host = subprocess.call(
        ['ping', '-W', str(1), '-c', '1', host],
        stdout=subprocess.DEVNULL)
    if test_host == 0:
        return host
    else:
        return "Down"

with multiprocessing.Pool(100) as p:
    lr_hosts = p.map(ping, test_hosts)

for val in lr_hosts:
    if val != 'Down': l_hosts.append(val)


test = Net_tool(l_hosts)
test.run_GScan()

print("\33[92m\n[*]Finished in {}".format(datetime.now() - time_0))
