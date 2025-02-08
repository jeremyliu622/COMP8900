import os
import time
import logging
import json
import ipaddress
from sklearn.tree import DecisionTreeClassifier
import numpy as np

# Setup logging
logging.basicConfig(
    filename="traffic_filter.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Whitelist and thresholds
WHITELIST = [ipaddress.IPv4Network("10.0.0.0/24")]
FREQUENT_CONNECTION_THRESHOLD = 100
ABNORMAL_PACKET_SIZE = 1500

# Machine learning model for advanced traffic analysis
decision_tree_model = DecisionTreeClassifier()
feature_set = [[100, 1000], [200, 2000], [50, 500]]  # Example training data
label_set = [0, 1, 0]  # Labels: 0 = benign, 1 = malicious
decision_tree_model.fit(feature_set, label_set)

# Tracking frequent connections
connection_counts = {}


def is_ip_whitelisted(ip):
    """Check if the IP is in the whitelist."""
    ip_obj = ipaddress.IPv4Address(ip)
    return any(ip_obj in network for network in WHITELIST)


def apply_firewall_rule(ip, action):
    """Apply dynamic firewall rules."""
    if action == "block":
        # Uncomment for real firewall rule application
        # os.system(f'sudo iptables -A INPUT -s {ip} -j DROP')
        logging.info(f"Firewall rule applied: Block traffic from {ip}")


def detect_frequent_connections(src_ip):
    """Detect potential DDoS based on connection counts."""
    if src_ip in connection_counts:
        connection_counts[src_ip] += 1
    else:
        connection_counts[src_ip] = 1

    if connection_counts[src_ip] > FREQUENT_CONNECTION_THRESHOLD:
        logging.info(f"Potential DDoS detected from {src_ip}")
        apply_firewall_rule(src_ip, "block")

    # Reset the dictionary if it grows too large
    if len(connection_counts) > 1000:
        connection_counts.clear()


def detect_abnormal_packet_size(src_ip, size):
    """Detect abnormally large packets."""
    if size > ABNORMAL_PACKET_SIZE:
        logging.info(f"Abnormally large packet detected from {src_ip}")
        apply_firewall_rule(src_ip, "block")


def analyze_packet_with_decision_tree(packet_info):
    """Use the decision tree to classify traffic."""
    src_ip = packet_info["src_ip"]
    dst_ip = packet_info["dst_ip"]
    size = packet_info["size"]

    # Extract features for classification
    features = np.array([[size]])
    prediction = decision_tree_model.predict(features)[0]

    if prediction == 1:  # Malicious traffic
        logging.info(f"Malicious traffic detected from {src_ip} to {dst_ip}")
        apply_firewall_rule(src_ip, "block")


def process_packet(packet_info):
    """
    Analyze the packet and apply appropriate rules.
    """
    src_ip = packet_info["src_ip"]
    size = packet_info["size"]

    if is_ip_whitelisted(src_ip):
        return

    detect_frequent_connections(src_ip)
    detect_abnormal_packet_size(src_ip, size)
    analyze_packet_with_decision_tree(packet_info)


def process_packets():
    """
    Read packets from the log file and process them.
    """
    log_file = "/logs/packets.log"
    print("Processing packets from log...")

    if not os.path.exists(log_file):
        print(f"No log file found at {log_file}. Exiting.")
        return

    with open(log_file, "r") as f:
        for line in f:
            try:
                packet_info = json.loads(line.strip())
                process_packet(packet_info)
            except json.JSONDecodeError:
                logging.error("Error decoding packet log entry.")


if __name__ == "__main__":
    while True:
        process_packets()
        time.sleep(1)  # Poll logs every second
