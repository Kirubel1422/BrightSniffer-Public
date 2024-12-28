import os
import socket
import ipaddress
import struct
import sys
import time
import threading

SUBNET="172.16.41.0/24"
MESSAGE="Bright"

class IP:
    def __init__(self, buff=None):
        # Using little endian | big endian unpack the buffer
        header = struct.unpack('<BBHHHBBH4s4s', buff)

        # Extract version and HDR length from one byte and get two 4 bits each
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0XF

        # Extract type of service and total length
        self.tos = header[1]
        self.len = header[2]

        # Extract ID, fragment offset, time to live
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]

        # Extract protocol and header checksum
        self.protocol_num = header[6]
        self.sum = header[7]

        # Extract src IP and dest IP
        self.src = header[8]
        self.dst = header[9]

        # Convert to human readable IP 
        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        # Map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as E:
            print('%s No Protocol for %s' %(E, self.protocol_num))
            self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self, buff=None):
        # Header for ICMP
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        # Each ip in the subnet
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


class Scanner:
    def __init__(self, host):
        self.host = host

        if os.name == 'nt':
        # Capture all IP level protocols
            socket_protocol = socket.IPPROTO_IP
        else:
            # Capture ICMP | PING requests
            socket_protocol = socket.IPPROTO_ICMP

        # Create a socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        
        # Bind socket
        self.socket.bind((host, 0))

        # Include IP header
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, 1)
        
    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                # read a packet
                raw_buffer = self.socket.recvfrom(65535)[0]
                # Extract IP header
                ip_header = IP(raw_buffer[0: 20])
                # Check if it ICMP
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    # Begining of the ICMP
                    buffer = raw_buffer[offset: offset+8]
                    # Instance of ICMP header
                    icmp_header = ICMP(buffer)

                    # Class unreachable and port unreachable
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        # Check if the src ip is in the subnet
                        if ipaddress.ip_address(ip_header.src_addr) in ipaddress.IPv4Network(SUBNET):
                            # Check if the packet contains the magic word - message
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                # IP of target | responder to the sent UDP datagram
                                tgt = ipaddress.ip_address(ip_header.src_addr)

                                # Validate target before adding to hosts_up
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(tgt)
                                    print(f'Host up: {tgt}')

        except KeyboardInterrupt as E:
            # Turn off promiscous mode
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, 0)
            
            # List all the discovered hosts
            print('\nUser Interrupted')
            if hosts_up:
                print('All available hosts on %s' %SUBNET)
                for host in hosts_up:
                    print(f'{host}')
            
            sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        host = sys.argv[1]
        s = Scanner(host)
        t = threading.Thread(target=udp_sender)
        t.start()
        time.sleep(5)
        s.sniff()
    else:
        print('No host provided')
        sys.exit()
    