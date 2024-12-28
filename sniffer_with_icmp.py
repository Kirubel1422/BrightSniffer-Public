import os
import socket
import ipaddress
import struct
import sys

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
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host):
    if os.name == 'nt':
        # Capture all IP level protocols
        socket_protocol = socket.IPPROTO_IP
    else:
        # Capture ICMP | PING requests
        socket_protocol = socket.IPPROTO_ICMP
    
    # Create a raw socket
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))

    # Add a header to the socket - to include all meta data
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable Promscouis mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Continous reading a packet
    try:
        while True:
            # read a packet
            raw_buffer = sniffer.recvfrom(65535)[0]
            # create an IP header from the first 20 byte
            ip_header = IP(raw_buffer[0:20])
            # print ip addresses for ICMP
            if ip_header.protocol == "ICMP":
                print('Protocol %s: %s -> %s' %(ip_header.protocol, ip_header.src_addr, ip_header.dst_addr))
                print('Version: %s' %ip_header.ver)
                print('Header Length: %s' %ip_header.ihl)

                # Calculate where the ICMP packet starts
                offset = ip_header.ihl * 4
                buff = raw_buffer[offset: offset+8]
                ICMP_header = ICMP(buff)
                print('ICMP -> Type: %s Code: %s' %(ICMP_header.type, ICMP_header.code))

    except KeyboardInterrupt:
        if os.name == 'nt':
            # Disable promiscous mode on windows
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print('Exiting ...')
        sys.exit(1)

if __name__ == '__main__':
    host = sys.argv[1]
    sniff(host)
