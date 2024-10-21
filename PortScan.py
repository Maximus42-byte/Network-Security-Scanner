import socket, sys, random, time
import threading
from struct import *


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s


def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


def create_packet(source_ip, dest_ip, source_port, dest_port, mode):
    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = random.randrange(18000, 65535, 1)  # Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                     ip_saddr, ip_daddr)

    # tcp header fields
    tcp_source = source_port  # source port
    tcp_dest = dest_port  # destination port
    tcp_seq = 2954607934
    tcp_ack_seq = 0
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    # tcp flags
    if mode == 'syn':
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
    elif mode == 'ack' or mode == 'win':
        tcp_fin = 0
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 1
        tcp_urg = 0
    elif mode == 'fin':
        tcp_fin = 1
        tcp_syn = 0
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0

    tcp_window = socket.htons(5840)  # maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window,
                      tcp_check, tcp_urg_ptr)

    user_data = ''

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header + user_data

    tcp_check = checksum(psh)
    # print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                      tcp_window) + pack(
        'H', tcp_check) + pack('!H', tcp_urg_ptr)

    # final full packet
    packet = ip_header + tcp_header + user_data

    return packet


def sniffer(mode):
    global global_source_port
    global ip_under_scan
    global running

    while running:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        packet = s.recvfrom(65565)

        # packet string from tuple
        packet = packet[0]

        ethernet_length = 14

        ethernet_header = packet[:ethernet_length]
        ethernet = unpack('!6s6sH', ethernet_header)
        ethernet_protocol = socket.ntohs(ethernet[2])

        # IP Protocol number = 8
        if ethernet_protocol == 8:
            # Parse IP packets:
            ip_header_packed = packet[ethernet_length:20 + ethernet_length]

            ip_header = unpack('!BBHHHBBH4s4s', ip_header_packed)

            version_IHL = ip_header[0]
            version = version_IHL >> 4
            IHL = version_IHL & 0xF

            ip_header_length = IHL * 4

            protocol = ip_header[6]
            s_address = socket.inet_ntoa(ip_header[8])
            d_address = socket.inet_ntoa(ip_header[9])

            # TCP protocol
            if protocol == 6 and s_address == ip_under_scan:
                start_point = ip_header_length + ethernet_length
                tcp_header_packed = packet[start_point:start_point + 20]

                tcp_header = unpack('!HHLLBBHHH', tcp_header_packed)

                source_port = tcp_header[0]
                dest_port = tcp_header[1]
                sequence = tcp_header[2]
                acknowledgement = tcp_header[3]
                dataOffset_reserved = tcp_header[4]
                tcp_header_length = dataOffset_reserved >> 4
                flags = tcp_header[5]
                win_size = tcp_header[6]
                checksum = tcp_header[7]

                if mode == 'syn':

                    if (flags & (1 << 1)) >= 1 and (flags & (1 << 4)) >= 1 and dest_port == global_source_port:
                        print(str(source_port))
                elif mode == 'ack':
                    if (flags & (1 << 2)) >= 1 and dest_port == global_source_port:
                        print(str(source_port))
                elif mode == 'fin':
                    if (flags & (1 << 2)) >= 1 and dest_port == global_source_port:
                        print(str(source_port))
                elif mode == 'win':
                    if (flags & (1 << 2)) >= 1 and dest_port == global_source_port:
                        if win_size > 0:
                            print(str(source_port) + ' open')
                        else:
                            print(str(source_port) + ' closed')


def send_packet(source_ip, dest_ip, global_source_port, j, mode):
    sender = create_socket()
    packet = create_packet(source_ip, dest_ip, global_source_port, j, mode)
    sender.sendto(packet, (dest_ip, 0))


def range_scan(source_ip, dest_ip, start_port, end_port, mode):
    print('scanning...')

    global global_source_port

    global running
    running = True

    t1 = threading.Thread(target=sniffer, args=(mode,))
    t1.start()

    threads = []
    for j in range(start_port, end_port):
        t = threading.Thread(target=send_packet, args=(source_ip, dest_ip, global_source_port, j, mode))
        threads.append(t)
        t.start()

    for j in range(end_port - start_port):
        threads[j].join()

    running = False
    time.sleep(5)
    t1.join()


def TCP_connect(ip, port_number):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(3)
    try:
        s.connect((ip, port_number))
        print(port_number)
    except:
        a=0

    s.close()


def connect_scan(dest_ip, start_port, end_port):
    print('scanning...')
    threads = []
    for j in range(start_port, end_port):
        t = threading.Thread(target=TCP_connect, args=(dest_ip, j))
        threads.append(t)
        t.start()

    for j in range(end_port - start_port):
        threads[j].join()


def run():
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.connect(('www.google.com', 0))
    source_ip = soc.getsockname()[0]
    soc.close()

    global global_source_port
    global ip_under_scan

    global_source_port = random.randrange(5000, 6000)

    target_device = raw_input('enter target device address > ')
    ip_under_scan = socket.gethostbyname(target_device)

    from_port = input('start scan from port > ')
    to_port = input('finish scan to port > ')

    print('scanning methods:')
    print('1: connect scan.')
    print('2: syn scan.')
    print('3: ack scan.')
    print('4: fin scan.')
    print('5: window scan.')

    method = input('start scan using method number > ')

    if method == 1:
        print('The following is the list of open ports:')
        connect_scan(ip_under_scan, 10, 200)
    elif method == 2:
        print('The following is the list of open ports:')
        range_scan(source_ip, ip_under_scan, from_port, to_port, 'syn')
    elif method == 3:
        print('The following is the list of unfiltered ports:')
        range_scan(source_ip, ip_under_scan, from_port, to_port, 'ack')
    elif method == 4:
        print('The following is the list of closed ports:')
        range_scan(source_ip, ip_under_scan, from_port, to_port, 'fin')
    elif method == 5:
        print('The following is the list of unfiltered ports:')
        range_scan(source_ip, ip_under_scan, from_port, to_port, 'win')
    else:
        print('invalid input')


# *************** main ***************

global_source_port = 0
ip_under_scan = 0
running = False

run()

# ************* end main *************
