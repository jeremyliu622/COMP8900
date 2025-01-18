import argparse
from scapy.all import sniff, get_if_list
import logging
import os
from threading import Thread, Lock, Event

os.makedirs("/logs", exist_ok=True)

logging.basicConfig(
    filename='/logs/packets.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

log_lock = Lock()

stop_sniffing_event = Event()


def packet_callback(packet, args):
    """
    Callback function for processing captured packets.
    Logs packet details and their payloads based on filter arguments.
    """
    try:
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            protocol = packet.sprintf('%IP.proto%')
            # payload = bytes(packet['IP'].payload)

            # Apply filters
            if args.src_ip and src_ip != args.src_ip:
                return
            if args.dest_ip and dst_ip != args.dest_ip:
                return
            if args.ip and src_ip != args.ip and dst_ip != args.ip:
                return
            if args.protocol and protocol.lower() != args.protocol.lower():
                return

            if args.port and (
                (packet.haslayer('TCP') and packet['TCP'].sport != args.port and packet['TCP'].dport != args.port) or
                (packet.haslayer('UDP') and packet['UDP'].sport != args.port and packet['UDP'].dport != args.port)
            ):
                return

            # Thread-safe logging
            with log_lock:
                logging.info(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")
                print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")

    except Exception as e:
        with log_lock:
            logging.error(f"Error processing packet: {e}")


def start_sniffing(interface, args):
    """
    Function to start sniffing packets on a specific interface.
    Runs in a separate thread.
    """
    try:
        print(f"Starting packet capture on interface: {interface}")
        sniff(
            iface=interface,
            filter="ip",
            prn=lambda pkt: packet_callback(pkt, args),
            stop_filter=lambda _: stop_sniffing_event.is_set()
        )
    except PermissionError:
        print(f"Permission error: Please run as administrator/root for interface {interface}.")
    except Exception as e:
        with log_lock:
            logging.error(f"Error in sniffing thread for {interface}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded packet capture with filtering options.")
    parser.add_argument("--src_ip", type=str, help="Filter by source IP address", default=None)
    parser.add_argument("--dest_ip", type=str, help="Filter by destination IP address", default=None)
    parser.add_argument("--ip", type=str, help="Filter by IP address (matches source or destination)", default=None)
    parser.add_argument("--port", type=int, help="Filter by port number", default=None)
    parser.add_argument("--protocol", type=str, help="Filter by protocol (e.g., TCP, UDP, ICMP)", default=None)
    parser.add_argument("--interface", type=str, help="Specify a network interface to sniff on", default=None)
    args = parser.parse_args()

    interfaces = get_if_list()
    if args.interface:
        if args.interface not in interfaces:
            print(f"Error: Interface '{args.interface}' not found. Available interfaces: {interfaces}")
            return
        interfaces = [args.interface]

    print(f"Using interfaces: {interfaces}")

    threads = []
    for iface in interfaces:
        thread = Thread(target=start_sniffing, args=(iface, args), daemon=True)
        thread.start()
        threads.append(thread)

    try:
        print("Press Ctrl+C to stop packet capture and save the log.")
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        stop_sniffing_event.set()
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=5)  # Wait for threads to finish
        print("Packet capture stopped. Logs saved to /logs/packets.log.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
