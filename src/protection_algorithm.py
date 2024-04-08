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
from joblib import load
from sklearn.ensemble import RandomForestClassifier
from struct import unpack
from socket import inet_ntoa, ntohs
from sklearn import svm
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
import warnings

# Ignore warning saying that for OneHotEncoder sparse_output will be changed in the future
warnings.filterwarnings("ignore", category=FutureWarning, message="`sparse` was renamed to `sparse_output`.*")

# Define protocol mapping
PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
}

if not os.path.exists('logs'):
    os.mkdir('logs')
LOG_TIME = time.asctime().replace(' ', '_').replace(':', '-')
logging.basicConfig(filename=os.path.join('logs', LOG_TIME + '-dbg.txt'), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info('Started logging file successfully')

# Get trained model file from user
modelName = input('Enter the name of the AI model file excluding the prefix (ex. svm_model.pkl): ')

# Load trained models from .pkl file
#with open('udp_' + modelName, 'rb') as file:
#    udp_model = load(file)

#with open('tcp_' + modelName, 'rb') as file:
#    tcp_model = load(file)

with open('icmp_' + modelName, 'rb') as file:
    icmp_model = load(file)

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

# Get the IP of the local computer
my_ip = get_ip_address()

# Function to extract features from a packet
def extract_features(data):
    eth_length = 14

    try:
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
                seconds = timestamp.second
                microseconds = timestamp.microsecond
        
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
                    packet_data = [src_ip, src_port, dst_ip, dst_port, protocol, packet_size, seconds, microseconds] + list(flags.values())
                # Parse UDP packets
                elif iph[6] == 17:
                    udp_header = data[iph_length+eth_length:iph_length+eth_length+8]
                    udph = unpack('!HHHH', udp_header)
                    src_port = udph[0]
                    dst_port = udph[1]
                    packet_data = [src_ip, src_port, dst_ip, dst_port, protocol, packet_size, seconds, microseconds]
                # Parse ICMP packets
                elif iph[6] == 1:
                    icmp_header = data[iph_length+eth_length:iph_length+eth_length+4]
                    icmph = unpack('!BBH', icmp_header)
                    icmp_type = icmph[0]
                    packet_data = [src_ip, dst_ip, protocol, packet_size, seconds, microseconds, icmp_type]
        
                return np.array(packet_data), protocol
    except:
        logging.warning(f'Error processing {protocol} packet: {e}')
        logging.warning(f'Packet details: {packet}')
        return np.array([]), "Unknown"

# Function to block traffic from an IP address
def block_ip(ip_address, protocol):
    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    subprocess.run(command)
    logging.warning('Blocked {protocol} packet from {ip_address}: suspected DDOS traffic')

# Function to forward regular ping packets
def forward_packet(packet, features, protocol):
    if protocol == 'UDP':
        destination_address = features[2]
        destination_port = features[3]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Send UDP packet
            sock.sentto(packet, (destination_address, destination_port))
        except Exception as e:
            print(f'Error sending packet over UDP: {e}')
        finally:
            sock.close()
    elif protocol == 'TCP':
        destination_address = features[2]
        destination_port = features[3]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Establish connection
            sock.connect((destination_address, destination_port))

            # Send TCP packet
            sock.send(packet)
        except Exception as e:
            print(f'Error sending packet over TCP: {e}')
        finally:
            sock.close()
    elif protocol == 'ICMP':
        destination_address = features[1]

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        try:
            # Send ICMP packet
            sock.sendto(packet, (destination_address, 0))
        except Exception as e:
            print(f'Error sending packet over ICMP: {e}')
        finally:
            sock.close()

# Get a single received packet
def receive_packet():
    # Create a raw socket to receive packets
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    try:
        # Receive a packet
        packet, _ = sock.recvfrom(65535)
        return packet
    except socket.error as e:
        print("Error receiving packet:", e)
    finally:
        # Close the socket
        sock.close()

encoder = OneHotEncoder(sparse_output=False)

udp_columns_to_encode = [0, 2]
tcp_columns_to_encode = [0, 2]
icmp_columns_to_encode = [0, 1]

while True:
        packet = receive_packet()
        features, protocol = extract_features(packet)

        try:
            if protocol == 'UDP':
                continue
                # Extract specific features and convert to appropriate type
                data = np.array([[features[0], features[1], features[2], features[3], features[5], features[6], features[7]]])

                # Create column transformer for encoding
                ct = ColumnTransformer(transformers=[('one_hot_encode', encoder, udp_columns_to_encode)], remainder='passthrough')

                # Apply OneHotEncoding
                data = ct.fit_transform(data)

                # Use trained model to predict packet type
                prediction = udp_model.predict(data)

            elif protocol == 'TCP':
                continue
                # Extract specific features and convert to appropriate type
                data = np.array([[features[0], features[1], features[2], features[3], features[5], features[6], features[7], features[8], features[9], features[10], features[11], features[12], features[13], features[14], features[15]]])

                # Create column transformer for encoding
                ct = ColumnTransformer(transformers=[('one_hot_encode', encoder, tcp_columns_to_encode)], remainder='passthrough')

                # Apply OneHotEncoding
                data = ct.fit_transform(data)

                # Use trained model to predict packet type
                prediction = tcp_model.predict(data)

            elif protocol == 'ICMP':
                # Extract specific features and convert to appropriate types
                data = np.array([[features[0], features[1], features[3], features[4], features[5], features[6]]])

                # Create column transformer for encoding
                ct = ColumnTransformer(transformers=[('one_hot_encode', encoder, icmp_columns_to_encode)], remainder='passthrough')

                # Apply OneHotEncoding
                data = ct.fit_transform(data)

                # Use the trained model to predict packet type
                prediction = icmp_model.predict(data)
        except Exception as e:
            logging.warning(f'Error processing {protocol} packet: {e}')
            logging.warning(f'Packet details: {packet}')
            continue

        src_ip = features[0]
        print(f'Prediction for protocol {protocol} is: {prediction}')
        # Assuming the classes are encoded as 0 for regular ping and 1 for attack
        if prediction == 1 and src_ip != my_ip:
                block_ip(src_ip, protocol)
        else:
                forward_packet(packet, features, protocol)
