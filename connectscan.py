import socket, sys, random, time
import threading
from struct import *



def TCP_connect(ip, port_number):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(5)
    try:
        s.connect((ip, port_number))
        print(port_number)
    except:
        a=0

    s.close()

global_source_port = random.randrange(5000, 6000)

target_device = raw_input('enter target  address : ')
ip_scan = socket.gethostbyname(target_device)


print('The list of open ports:')

threads = []
for j in range(10, 1000):
    t = threading.Thread(target=TCP_connect, args=(ip_scan, j))
    threads.append(t)
    t.start()

for j in range(1000 - 10):
    threads[j].join()
