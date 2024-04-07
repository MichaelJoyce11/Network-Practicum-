import time
import os
import datetime
import subprocess
import socket
import pcapy
import pathlib  # Add this import if it's not already imported
from struct import unpack
import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier


PATH = f'{str(pathlib.path.Path(__file__).parent.absolute())}\\'
os.chdir(PATH)

if not os.path.exists(os.path.join(PATH, 'logs')):
    os.mkdir('logs')
LOG_TIME = time.asctime().replace(' ', '_').replace(':', '-')
logging.basicConfig(filename=os.path.join(PATH, 'logs', LOG_TIME + '-dbg.txt'), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info('Started logging file successfully')

# Get trained model file from user
modelName = input('Enter the name of the AI model file excluding the prefix (ex. svm_model.pkl)')

# Load trained model from .pkl file
with open(modelName, 'rb') as f:
    model = pickle.load(f)

# Get the IP of the victim computer
def get_ip_address():
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Connect to a remote server (doesn't send any data)
        sock.connect(("8.8.8.8", 80))

        # Get the local IP address connected to the socket
        ip_address = sock.getsockname()[0]
    except Exception as e:
        print("Error:", e)
        ip_address = None
    finally:
        # Close the socket
        sock.close()

    return ip_address

my_ip = get_ip_address()

# Function to extract features from a packet
def extract_features(packet):
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

        # Calculate packet size
        packet_size = len(data)

        # Get current timestamp
        timestamp = datetime.datetime.now()

        # Set Row Data
        row_data = None

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
        if iph [6] == 6:
            tcp_header = data[iph_length+eth_length:iph_length+eth_length+20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            flags = {
                "FIN": (tcph[5] & 0x01) != 0,
                "SYN": (tcph[5] & 0x02) != 0,
                "RST": (tcph[5] & 0x04) != 0,
                "PSH": (tcph[5] & 0x08) != 0,
                "ACK": (tcph[5] & 0x10) != 0,
                "URG": (tcph[5] & 0x20) != 0,
                "ECE": (tcph[5] & 0x40) != 0,
                "CWR": (tcph[5] & 0x80) != 0
            }
            src_port = tcph[0]
            dst_port = tcph[1]
            row_data = [src_ip, src_port, dst_ip, dst_port, protocol, packet_size, timestamp] + list(flags.values())
        # Parse UDP packets
        elif iph[6] == 17:
            udp_header = data[iph_length+eth_length:iph_length+eth_length+8]
            udph = unpack('!HHHH', udp_header)
            src_port = udph[0]
            dst_port = udph[1]
            row_data = [src_ip, src_port, dst_ip, dst_port, protocol, packet_size, timestamp]
        # Parse ICMP packets
        elif iph[6] == 1:
            icmp_header = data[iph_length+eth_length:iph_length+eth_length+4]
            icmph = unpack('!BBH', icmp_header)
            icmp_type = icmph[0]
            row_data = [src_ip, dst_ip, protocol, packet_size, timestamp, icmp_type]

        return np.array(row_data), protocol

# Function to predict packet type (attack or regular)
def predict_packet(packet_features, protocol):
    # Use the trained model to predict packet type
    prediction = model.predict(packet_features)
    src_ip = packet_features[0]
    
    # Assuming the classes are encoded as 0 for regular ping and 1 for attack
    if prediction == 1 and src_ip not my_ip:
        block_ip(src_ip, protocol)
    else:
        forward_ip(src_ip)



# Function to handle incoming packets
def handle_packet(header, data):
    features, protocol = extract_features(data)
    prediction = predict_packet([features], protocol)

# Function to block traffic from an IP address
def block_ip(ip_address, packet_type):
    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    subprocess.run(command)
    logging.warning('Blocked {packet_type} packet from {ip_address}: suspected DDOS traffic')

# Function to forward regular ping packets
def forward_packet(packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    try:
        # Send the packet to the destination address
        sock.sendto(packet, (destination_address, 0))
        print("Packet forwarded successfully.")
    except Exception as e:
        print("Error forwarding packet:", e)
    finally:
        # Close the socket
        sock.close()



# Set the network interface to capture packets
interface = "eth0"

# Open the network interface in promiscuous mode
pcap = pcapy.open_live(interface, 65536, True, 100)

# Start capturing packets
pcap.loop(0, lambda header, data: handle_packet(header, data))
