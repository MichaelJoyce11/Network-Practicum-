import pcapy
from struct import unpack
from socket import inet_ntoa, ntohs
import socket
import csv
import datetime
import warnings

# Suppress DeprecationWarning for PY_SSIZE_T_CLEAN
warnings.filterwarnings("ignore", category = DeprecationWarning)

# Define protocol mapping
PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
}

def process_packet(header, data, csv_filename):
    eth_length = 14

    # Extract ethernet header
    eth_header = data[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # Parse IP packets only
    if eth_protocol == 8:
        # Parse IP header
        ip_header = data[eth_length:20+eth_length]
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        # Extract IP source and destination addresses
        src_ip = inet_ntoa(iph[8])
        dst_ip = inet_ntoa(iph[9])

        # Parse protocol
        protocol = PROTOCOL_MAP.get(iph[6], "Unknown")

        #Set appropriate header string to separate packet types
        if iph[6] == 6:
            csv_filename_prefix = "tcp_"
        elif iph[6] == 17:
            csv_filename_prefix = "udp_"
        elif iph[6] == 1:
            csv_filename_prefix = "icmp_"
        else:
            csv_filename_prefix = ""

        # Parse TCP packets
        if iph[6] == 6:
            tcp_header = data[iph_length+eth_length:iph_length+eth_length+20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            flags = {
                    "SYN": (tcph[5] & 0x02) != 0,
                    "ACK": (tcph[5] & 0x10) != 0,
                    "FIN": (tcph[5] & 0x01) != 0
                    }
            src_port = tcph[0]
            dst_port = tcph[1]
        else:
            flags = {}
            src_port = None
            dst_port = None

        # Calculate packet size
        packet_size = len(data)

        # Get current timestamp
        timestamp = datetime.datetime.now()

        # Write packet information to CSV file
        with open(csv_filename_prefix + csv_filename, mode = 'a', newline = '') as file:
            writer = csv.writer(file)
            row_data = [src_ip, src_port, dst_ip, dst_port, protocol, packet_size, timestamp] + list(flags.values())
            non_blank_data = [value for value in row_data if value != '']
            writer.writerow(non_blank_data)

        # Parse UDP packets
        if iph[6] == 17:
            udp_header = data[iph_length+eth_length:iph_length+eth_length+8]
            udph = unpack('!HHHH', udp_header)
            src_port = udph[0]
            dst_port = udph[1]

            # Write packet information to CSV file
            with open(csv_filename_prefix + csv_filename, mode = 'a', newline = '') as file:
                writer = csv.writer(file)
                row_data = ['', src_port, '', dst_port, 'UDP', '', ''] + [''] * len(flags)
                non_blank_data = [value for value in row_data if value != '']
                writer.writerow(non_blank_data)

        # Parse ICMP packets
        if iph[6] == 1:
            icmp_header = data[iph_length+eth_length:iph_length+eth_length+4]
            icmph = unpack('!BBH', icmp_header)
            icmp_type = icmph[0]

            # Write packet information to CSV file
            with open(csv_filename_prefix + csv_filename, mode = 'a', newline = '') as file:
                writer = csv.writer(file)
                row_data = ['', '', '', '', 'ICMP', '', ''] + [icmp_type] + [''] * (len(flags) - 1)
                non_blank_data = [value for value in row_data if value != '']
                writer.writerow(non_blank_data)

# Set the network interface to capture packets
interface = "eth0"

# Get the CSV file name from the user
csv_filename = input("Enter the CSV filename (ex. packet_info.csv): ")

 # Open the network interface in promiscuous mode
pcap = pcapy.open_live(interface, 65536, True, 100)

# Start capturing packets
pcap.loop(0, lambda header, data: process_packet(header, data, csv_filename))

