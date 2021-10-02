from socket import *
from struct import *
import re
import time


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


class Pcap:
    def __init__(self, file_name, link_type=1):
        # file_name is either a text or byte string giving the name (and the path if the file isn't in the current working directory) of the file to be opened
        # 'wb' : the mode in which the file is opened. 'r' : reading - 'w' : writing (truncating the file if it already exists) - 'b' : binary mode - 't' : text mode
        self.pcap_file = open(file_name, 'wb')
        # magic_number = 4 bytes (d4 c3 b2 a1)
        # version_major = 2 bytes (02 00) , major version number -> *in our case 2.4. (little endian)
        # version_minor = 2 bytes (04 00) , minor version number
        # thiszone = 4 bytes (int) (00 00 00 00) , GMT to local correction , usually set to 0
        # sigfigs = 4 bytes (00 00 00 00) , accuracy of timestamps , usually set to 0
        # snaplen = 4 bytes (FF FF 00 00) , maximum length of the captured packets in bytes, here it's 65535 which is default value for tcpdump and wireshark
        # network = 4 bytes (01 00 00 00) , 0x1 which indicates that the link-layer protocol is Ethernet
        self.pcap_file.write(pack('@IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, rawdata):
        # ts_sec = 4 bytes (85 AD C7 50) , This is the number of seconds since the start of 1970, also known as Unix Epoch
        # ts_usec = 4 bytes (AC 97 05 00) , microseconds part of the time at which the packet was captured
        # incl_len = 4 bytes (E0 04 00 00) = 1248 , contains the size of the saved packet data in our file in bytes (following the header)
        # orig_len = 4 bytes (E0 04 00 00) , Both fields' value is same here, but these may have different values in cases where we set the maximum packet length (whose value is 65535 in the global header of our file) to a smaller size.
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        raw_data_length = len(rawdata)
        self.pcap_file.write(pack('@IIII', ts_sec, ts_usec, raw_data_length, raw_data_length))
        self.pcap_file.write(rawdata)

    def close(self):
        self.pcap_file.close()


if __name__ == '__main__':
    # create a AF_PACKET type raw socket (thats basically packet level)
    # define ETH_P_ALL    0x0003    Every packet
    s = socket(AF_PACKET, SOCK_RAW, ntohs(3))

    pcap_f = Pcap('pcap_ETH', 1)

    # infinite loop to receive packets
    while True:
        raw_data, addr = s.recvfrom(65565)

        pcap_f.write(raw_data)

        # parse ethernet header
        eth_length = 14
        eth_header_pack = raw_data[:eth_length]
        # Byte Order, Size, and Alignment : (!) network byte order is big-endian
        # A big-endian system stores the most significant byte of a word at the smallest memory address.
        # A little-endian system, in contrast, stores the least-significant byte at the smallest address.
        eth_h_unp = unpack('! 6s 6s H', eth_header_pack)
        dst_mac = eth_h_unp[0]
        src_mac = eth_h_unp[1]
        # EtherType, to indicate which protocol is encapsulated in the payload of the frame
        eth_protocol = eth_h_unp[2]
        print('\n\n\nEthernet Frame :'+'\n- Destination MAC: ' + eth_addr(str(dst_mac)) + ' - Source MAC: ' +
              eth_addr(str(src_mac)) + ' - EtherType: ' + hex(eth_protocol))

        # Parse ARP packets, ARP Protocol number = 0x0806
        if eth_protocol == 0x0806:
            # Parse ARP Packet
            arp_pack = raw_data[eth_length: eth_length+28]
            arp_unp = unpack('! H H B B H 6s 4s 6s 4s', arp_pack)

            HType = arp_unp[0]  # link protocol type. Example: Ethernet is 1.
            PType = arp_unp[1]  # the internetwork protocol for which the ARP request is intended -> EtherType

            HLen = arp_unp[2]  # Length (in octets) of hardware address.
            PLen = arp_unp[3]  # Length (in octets) of internetwork addresses.

            Oper = arp_unp[4]  # the operation that the sender is performing: 1 for request, 2 for reply.

            SHA = arp_unp[5]
            SPA = inet_ntoa(arp_unp[6])

            THA = arp_unp[7]
            TPA = inet_ntoa(arp_unp[8])
            print('\n\tARP Packet :' + '\n\t- Hardware Type: ' + str(HType) + ' - Protocol Type: ' + hex(PType) +
                  '\n\t- Hw Address Length: ' + str(HLen) + ' - Pr Address Length: ' + str(PLen) +
                  '\n\t- Request(1)/Reply(2): ' + str(Oper) + '\n\t- Sender Hw Address: ' + eth_addr(str(SHA)) +
                  ' - Sender Pr Address:' + str(SPA) + '\n\t- Target Hw Address: ' + eth_addr(str(THA)) +
                  ' - Target Pr Address:' + str(TPA))

        # Parse IPv4 packets, IPv4 Protocol number = 0x0800
        elif eth_protocol == 0x0800:
            # Parse IPv4 header
            # take first 20 characters for the ipv4 header
            ipv4_header_pack = raw_data[eth_length: eth_length+20]
            ipv4_h_unp = unpack('! B B H H H B B H 4s 4s', ipv4_header_pack)

            version_ihl = ipv4_h_unp[0]
            version = version_ihl >> 4  # four-bit version field. For IPv4, this is always equal to 4.
            ihl32 = version_ihl & 0xF  # 4 bits that specify the size of the IPv4 header (the number of 32-bit words in the header)
            ipv4_h_length = ihl32 * 4  # the size of the IPv4 header (in Bytes)
            header_offset_ip = ipv4_h_length + eth_length

            dscp = ipv4_h_unp[1]  # ToS

            total_ip_p_length = ipv4_h_unp[2]  # the entire packet size in bytes, including header and data. min=20 bytes (header without data), max=65,535 bytes.

            frag_id = ipv4_h_unp[3]  # uniquely identifying the group of fragments of a single IP datagram.
            frag_flag_offset = ipv4_h_unp[4]
            #     bit 0: Reserved; must be zero.
            #     bit 1: Don't Fragment (DF) -> If the DF flag is set, and fragmentation is required to route the packet, then the packet is dropped.
            #     bit 2: More Fragments (MF) -> For unfragmented packets, the MF flag is cleared. For fragmented packets, all fragments except the last have the MF flag set.
            frag_flag = bin(frag_flag_offset >> 13)
            frag_offset = frag_flag_offset & 0x1FFF  # the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram, it is measured in units of eight-byte blocks.

            ttl = ipv4_h_unp[5]

            trans_protocol = ipv4_h_unp[6]  # the protocol used in the data portion of the IP datagram.

            src_ip = inet_ntoa(ipv4_h_unp[8])
            dst_ip = inet_ntoa(ipv4_h_unp[9])

            print('\n\tIPv4 Datagram :' + '\n\t- Version: ' + str(version) + ' - IP Header Length(32-bit words): ' +
                  str(ihl32) + '\n\t- ToS: ' + str(dscp) + ' - Total Length: ' + str(total_ip_p_length) + '\n\t- Frag ID: ' +
                  str(frag_id) + ' - Frag Flag: ' + frag_flag + ' - Frag Offset: ' + str(frag_offset) + '\n\t- TTL: ' +
                  str(ttl) + ' - Transport Protocol: ' + str(trans_protocol) + '\n\t- Source IP Address: ' + str(src_ip)
                  + ' - Destination IP Address: ' + str(dst_ip))

            # Parse ICMP Packets, ICMP Protocol Number = 1
            if trans_protocol == 1:
                icmph_length = 4
                icmp_header_pack = raw_data[header_offset_ip: header_offset_ip+icmph_length]
                icmp_h_unp = unpack('! B B H', icmp_header_pack)

                icmp_type = icmp_h_unp[0]
                code = icmp_h_unp[1]
                checksum = icmp_h_unp[2]
                print('\n\t\tICMP Packet :' + '\n\t\t- Type: ' + str(icmp_type) + ' - Code: ' + str(code) +
                      ' - Checksum: ' + hex(checksum))
                # get data from the raw_data
                data = repr(raw_data[header_offset_ip+icmph_length:])  # canonical string representation of the object
                print('\t\tICMP Data : ' + str(data))


            # Parse UDP Packets, UDP Protocol Number = 17
            elif trans_protocol == 17:
                udp_h_length = 8
                header_offset_udp = header_offset_ip + udp_h_length

                udp_header_pack = raw_data[header_offset_ip: header_offset_udp]
                udp_h_unp = unpack('! H H H H', udp_header_pack)

                src_port = udp_h_unp[0]
                dst_port = udp_h_unp[1]
                length = udp_h_unp[2]
                checksum = udp_h_unp[3]

                print('\n\t\tUDP Datagram :' + '\n\t\t- Source Port: ' + str(src_port) + ' - Dest Port: ' +
                      str(dst_port) + '\n\t\t- Length: ' + str(length) + ' - Checksum: ' + hex(checksum))

                # get data from the raw_data
                data = raw_data[header_offset_udp:]


                # Parse DNS Messages, DNS Protocol Port Number = 53
                if (dst_port == 53) or (src_port == 53):
                    dns_h_length = 12
                    dns_header_p = data[: dns_h_length]
                    dns_h_unp = unpack('! H H H H H H', dns_header_p)

                    transactionID = dns_h_unp[0]

                    dns_flags = dns_h_unp[1]
                    query_or_reply = dns_flags >> 15
                    opcode = (dns_flags >> 11) & 0x000F
                    authoritative = (dns_flags >> 10) & 0x0001
                    truncated = (dns_flags >> 9) & 0x0001
                    recursion_desired = (dns_flags >> 8) & 0x0001
                    recursion_available = (dns_flags >> 7) & 0x0001
                    answer_authenticated = (dns_flags >> 6) & 0x0001
                    non_authenticated_data = (dns_flags >> 5) & 0x0001
                    reply_code = dns_flags & 0x000F

                    questions = dns_h_unp[2]
                    answer_RRs = dns_h_unp[3]
                    authority_RRs = dns_h_unp[4]
                    additional_RRs = dns_h_unp[5]

                    print('\n\t\t\tDNS Packet :' + '\n\t\t\t- Transaction ID: ' + str(transactionID) +
                          '\n\t\t\t- Flags: ' + '\n\t\t\t\t- Query or Reply: ' + str(query_or_reply) + ' - Opcode: ' +
                          hex(opcode) + ' - Authoritative: ' + str(authoritative) + '\n\t\t\t\t- Truncated: ' +
                          str(truncated) + ' - Recursion Desired: ' + str(recursion_desired) +
                          ' - Recursion Available: ' + str(recursion_available) + '\n\t\t\t\t- Answer Authenticated: ' +
                          str(answer_authenticated) + ' - non_authenticated_data: ' + str(non_authenticated_data) +
                          ' - Reply Code: ' + hex(reply_code) + '\n\t\t\t- num of questions: ' + str(questions) +
                          ' - num of answer RRs: ' + str(answer_RRs) + '\n\t\t\t- num of authority RRs: ' +
                          str(authority_RRs) + ' - num of additional RRs: ' + str(additional_RRs))

                    # get data from the raw_data
                    data = raw_data[header_offset_udp+dns_h_length:]
                    print('\t\t\t- DNS Data : ' + str(data))

                # some other UDP packets like DHCP
                else:
                    print('\n\t\t\t- Protocol other than DNS -> UDP Data Length = ' + str(len(data)) +
                          ' - UDP Data :' + repr(data))



            # Parse TCP Packets, TCP Protocol Number = 6
            elif trans_protocol == 6:
                tcp_header_pack = raw_data[header_offset_ip: header_offset_ip + 20]
                tcp_h_unp = unpack('! H H L L B B H H H', tcp_header_pack)

                src_port = tcp_h_unp[0]
                dst_port = tcp_h_unp[1]

                sequence_bytenum = tcp_h_unp[2]
                acknowledgement_bytenum = tcp_h_unp[3]

                dataoffset_reserved_ns = tcp_h_unp[4]
                # the size of the TCP header in 32-bit words. min=5 words(20 Bytes) , max=15 words(60 Bytes)
                tcph32_length = dataoffset_reserved_ns >> 4

                tcp_flags = tcp_h_unp[5]
                ns = dataoffset_reserved_ns & 0x01
                cwr = tcp_flags >> 7
                ece = (tcp_flags >> 6) & 0x01
                urg = (tcp_flags >> 5) & 0x01
                ack = (tcp_flags >> 4) & 0x01
                psh = (tcp_flags >> 3) & 0x01
                rst = (tcp_flags >> 2) & 0x01
                syn = (tcp_flags >> 1) & 0x01
                fin = tcp_flags & 0x01

                rwnd = tcp_h_unp[6]
                checksum = tcp_h_unp[7]
                urg_pointer = tcp_h_unp[8]

                print('\n\t\tTCP Segment :' + '\n\t\t- Source Port: ' + str(src_port) + ' - Dest Port: ' + str(dst_port)
                      + '\n\t\t- Sequence Number: ' + str(sequence_bytenum) + ' - Acknowledgement: ' +
                      str(acknowledgement_bytenum) + '\n\t\t- TCP header length(32-bit words): ' + str(tcph32_length) +
                      '\n\t\t- Flags:' + ' NS: ' + str(ns) + ' - CWR: ' + str(cwr) + ' - ECE: ' + str(ece) + ' - URG: '
                      + str(urg) + ' - ACK: ' + str(ack) + ' - PUSH: ' + str(psh) + ' - RST: ' + str(rst) + ' - SYN: ' +
                      str(syn) + ' - FIN: ' + str(fin) + '\n\t\t- rwnd: ' + str(rwnd) + ' - Checksum: ' + hex(checksum)
                      + ' - URG pointer: ' + str(urg_pointer))

                header_offset_tcp = header_offset_ip + tcph32_length * 4
                # get data from the raw_data
                data = raw_data[header_offset_tcp:]

                # Parse HTTP Request or Response Messages, HTTP Protocol Port Number = 80
                if (dst_port == 80) or (src_port == 80):
                    if len(data) > 6:
                        header_matchObj = re.search(rb'\r\n\r\n', data)

                        http_header_length = header_matchObj.end()
                        http_header_p = data[: http_header_length]

                        http_header_objects_p = re.findall(rb'(.+)\r\n', http_header_p)
                        print('\n\t\t\t- HTTP Header :')
                        for obj in http_header_objects_p:
                            print('\n\t\t\t\t- ' + str(obj))

                        http_body_p = data[http_header_length+1:]
                        print('\n\t\t\t- HTTP Body :' + str(http_body_p))
                    else:
                        print('\n\t\t\t- Protocol is HTTP but there is no TCP Data -> TCP Data Length = ' +
                              str(len(data)) + ' - TCP Data :' + repr(data))

                # some other TCP packets like Syn,FIN,HTTPS
                else:
                    print('\n\t\t\t- Protocol other than HTTP -> TCP Data Length = ' + str(len(data)) +
                          ' - TCP Data :' + repr(data))

            # some other IP packets like IGMP
            else:
                print('\n\t\t- Protocol other than TCP/UDP/ICMP')

        # some other EtherTypes like IPv6
        else:
            print('\n\tProtocol other than ARP/IPv4')
