import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Load trained model from .pkl file
with open('trained_model.pkl', 'rb') as f:
    model = pickle.load(f)

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

        return np.array(row_data)









# Function to predict packet type (attack or regular)
def predict_packet(packet_features):
    # Use the trained model to predict packet type
    # Return the prediction (0 for regular ping, 1 for attack)
    return model.predict(packet_features)

# Function to handle incoming packets
def handle_packet(packet):
    features = extract_features(packet)
    prediction = predict_packet([features])
    if prediction == 1:
        # Block or restrict traffic from the IP address if it's identified as an attacker
        block_ip(packet.source_ip)
    else:
        # Allow regular ping packets to pass through
        forward_packet(packet)

# Function to block traffic from an IP address
def block_ip(ip_address):
    # Implement IP blocking mechanism
    pass

# Function to forward regular ping packets
def forward_packet(packet):
    # Implement logic to forward the packet to its destination
    pass

# Main loop for monitoring incoming packets
while True:
    packet = receive_packet()  # Function to receive an incoming packet
    handle_packet(packet)
