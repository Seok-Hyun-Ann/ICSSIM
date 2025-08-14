#!/usr/bin/env python3
"""
PCAP Analyzer for Modbus/TCP, TCP, and MDNS Protocols
Extracts packet information and creates CSV files with analysis
"""

import os
import sys
import csv
import json
from datetime import datetime
from collections import defaultdict, Counter
import argparse

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy library is required. Install with: pip install scapy")
    sys.exit(1)

class ModbusTCPAnalyzer:
    """Modbus/TCP protocol analyzer"""
    
    def __init__(self):
        self.function_codes = {
            1: "Read Coils",
            2: "Read Discrete Inputs", 
            3: "Read Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Register",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers"
        }
        
    def parse_modbus_packet(self, packet):
        """Parse Modbus/TCP packet and extract relevant information"""
        try:
            if not packet.haslayer(TCP):
                return None
                
            tcp_layer = packet[TCP]
            payload = bytes(tcp_layer.payload)
            
            if len(payload) < 8:  # Minimum Modbus TCP header size
                return None
                
            # Modbus TCP Header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + Function Code (1)
            transaction_id = int.from_bytes(payload[0:2], 'big')
            protocol_id = int.from_bytes(payload[2:4], 'big')
            length = int.from_bytes(payload[4:6], 'big')
            unit_id = payload[6]
            
            if protocol_id != 0:  # Modbus protocol ID should be 0
                return None
                
            if len(payload) < 8:
                return None
                
            function_code = payload[7]
            
            modbus_data = {
                'transaction_id': transaction_id,
                'protocol_id': protocol_id,
                'length': length,
                'unit_id': unit_id,
                'function_code': function_code,
                'function_name': self.function_codes.get(function_code, f"Unknown ({function_code})"),
                'data_length': len(payload) - 8,
                'raw_data': payload[8:].hex() if len(payload) > 8 else ""
            }
            
            # Parse specific function code data
            if function_code == 3:  # Read Holding Registers
                if len(payload) >= 12:
                    start_addr = int.from_bytes(payload[8:10], 'big')
                    reg_count = int.from_bytes(payload[10:12], 'big')
                    modbus_data.update({
                        'start_address': start_addr,
                        'register_count': reg_count
                    })
            
            return modbus_data
            
        except Exception as e:
            print(f"Error parsing Modbus packet: {e}")
            return None

class PCAPAnalyzer:
    """Main PCAP analyzer class"""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.modbus_analyzer = ModbusTCPAnalyzer()
        self.modbus_transactions = {}
        self.stats = defaultdict(int)
        
    def load_pcap(self):
        """Load and parse PCAP file"""
        try:
            print(f"Loading PCAP file: {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
            return False
            
    def extract_packet_info(self, packet, packet_num):
        """Extract detailed information from a single packet"""
        info = {
            'packet_number': packet_num,
            'timestamp': float(packet.time),
            'datetime': datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
            'length': len(packet),
            'protocol': 'Unknown',
            'src_ip': '',
            'dst_ip': '',
            'src_port': '',
            'dst_port': '',
            'src_mac': '',
            'dst_mac': '',
            'tcp_flags': '',
            'tcp_seq': '',
            'tcp_ack': '',
            'tcp_window': '',
            'payload_size': 0,
            'payload_hex': '',
            'is_modbus': False,
            'modbus_info': ''
        }
        
        # Ethernet layer
        if packet.haslayer(Ether):
            eth = packet[Ether]
            info['src_mac'] = eth.src
            info['dst_mac'] = eth.dst
            
        # IP layer
        if packet.haslayer(IP):
            ip = packet[IP]
            info['src_ip'] = ip.src
            info['dst_ip'] = ip.dst
            info['protocol'] = ip.proto
            
        # TCP layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info['protocol'] = 'TCP'
            info['src_port'] = tcp.sport
            info['dst_port'] = tcp.dport
            info['tcp_flags'] = tcp.flags
            info['tcp_seq'] = tcp.seq
            info['tcp_ack'] = tcp.ack
            info['tcp_window'] = tcp.window
            
            # Check if it's Modbus/TCP (port 502)
            if tcp.sport == 502 or tcp.dport == 502:
                info['is_modbus'] = True
                modbus_data = self.modbus_analyzer.parse_modbus_packet(packet)
                if modbus_data:
                    info['modbus_info'] = json.dumps(modbus_data)
                    
            # Get payload
            if hasattr(tcp, 'payload') and tcp.payload:
                payload = bytes(tcp.payload)
                info['payload_size'] = len(payload)
                info['payload_hex'] = payload.hex()
                
        # UDP layer
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info['protocol'] = 'UDP'
            info['src_port'] = udp.sport
            info['dst_port'] = udp.dport
            
            # Check for MDNS (port 5353)
            if udp.sport == 5353 or udp.dport == 5353:
                info['protocol'] = 'MDNS'
                
            # Get payload
            if hasattr(udp, 'payload') and udp.payload:
                payload = bytes(udp.payload)
                info['payload_size'] = len(payload)
                info['payload_hex'] = payload.hex()
                
        return info
        
    def analyze_modbus_transactions(self):
        """Analyze Modbus query-response pairs"""
        transactions = []
        pending_queries = {}
        
        for i, packet in enumerate(self.packets):
            if not packet.haslayer(TCP):
                continue
                
            tcp = packet[TCP]
            if tcp.sport != 502 and tcp.dport != 502:
                continue
                
            modbus_data = self.modbus_analyzer.parse_modbus_packet(packet)
            if not modbus_data:
                continue
                
            transaction_id = modbus_data['transaction_id']
            is_query = tcp.dport == 502  # Query goes to server (port 502)
            
            packet_info = {
                'packet_number': i + 1,
                'timestamp': float(packet.time),
                'datetime': datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
                'src_ip': packet[IP].src if packet.haslayer(IP) else '',
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else '',
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'is_query': is_query,
                'modbus_data': modbus_data
            }
            
            if is_query:
                # Store query for matching with response
                pending_queries[transaction_id] = packet_info
            else:
                # This is a response, try to match with query
                if transaction_id in pending_queries:
                    query_info = pending_queries[transaction_id]
                    
                    # Calculate response time
                    response_time = packet_info['timestamp'] - query_info['timestamp']
                    
                    transaction = {
                        'transaction_id': transaction_id,
                        'query_packet': query_info['packet_number'],
                        'response_packet': packet_info['packet_number'],
                        'query_time': query_info['datetime'],
                        'response_time': packet_info['datetime'],
                        'response_time_ms': round(response_time * 1000, 3),
                        'client_ip': query_info['src_ip'],
                        'server_ip': query_info['dst_ip'],
                        'function_code': query_info['modbus_data']['function_code'],
                        'function_name': query_info['modbus_data']['function_name'],
                        'unit_id': query_info['modbus_data']['unit_id'],
                        'query_data': query_info['modbus_data'].get('raw_data', ''),
                        'response_data': packet_info['modbus_data'].get('raw_data', ''),
                        'query_length': query_info['modbus_data']['data_length'],
                        'response_length': packet_info['modbus_data']['data_length']
                    }
                    
                    # Add specific data for Read Holding Registers
                    if 'start_address' in query_info['modbus_data']:
                        transaction['start_address'] = query_info['modbus_data']['start_address']
                        transaction['register_count'] = query_info['modbus_data']['register_count']
                    
                    transactions.append(transaction)
                    del pending_queries[transaction_id]
                    
        return transactions
        
    def generate_network_analysis(self):
        """Generate comprehensive network behavior analysis"""
        analysis = {
            'summary': {},
            'protocols': {},
            'connections': {},
            'modbus_analysis': {},
            'temporal_analysis': {}
        }
        
        # Basic statistics
        total_packets = len(self.packets)
        total_size = sum(len(packet) for packet in self.packets)
        
        if total_packets > 0:
            duration = float(self.packets[-1].time) - float(self.packets[0].time)
            start_time = datetime.fromtimestamp(float(self.packets[0].time))
            end_time = datetime.fromtimestamp(float(self.packets[-1].time))
        else:
            duration = 0
            start_time = end_time = datetime.now()
            
        analysis['summary'] = {
            'total_packets': total_packets,
            'total_size_bytes': total_size,
            'duration_seconds': round(duration, 3),
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'average_packet_size': round(total_size / total_packets, 2) if total_packets > 0 else 0,
            'packets_per_second': round(total_packets / duration, 2) if duration > 0 else 0
        }
        
        # Protocol analysis
        protocol_count = Counter()
        port_count = Counter()
        ip_pairs = Counter()
        modbus_functions = Counter()
        
        for packet in self.packets:
            if packet.haslayer(TCP):
                protocol_count['TCP'] += 1
                tcp = packet[TCP]
                port_count[f"TCP:{tcp.sport}"] += 1
                port_count[f"TCP:{tcp.dport}"] += 1
                
                if tcp.sport == 502 or tcp.dport == 502:
                    protocol_count['Modbus/TCP'] += 1
                    
                if packet.haslayer(IP):
                    ip_pair = f"{packet[IP].src} -> {packet[IP].dst}"
                    ip_pairs[ip_pair] += 1
                    
            elif packet.haslayer(UDP):
                protocol_count['UDP'] += 1
                udp = packet[UDP]
                port_count[f"UDP:{udp.sport}"] += 1
                port_count[f"UDP:{udp.dport}"] += 1
                
                if udp.sport == 5353 or udp.dport == 5353:
                    protocol_count['MDNS'] += 1
                    
        analysis['protocols'] = dict(protocol_count.most_common())
        analysis['connections'] = {
            'top_ip_pairs': dict(ip_pairs.most_common(10)),
            'top_ports': dict(port_count.most_common(10))
        }
        
        return analysis
        
    def export_to_csv(self, output_dir="output"):
        """Export analysis results to CSV files"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # 1. Individual packet CSV
        packet_csv = os.path.join(output_dir, "network_packets.csv")
        with open(packet_csv, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'packet_number', 'timestamp', 'datetime', 'length', 'protocol',
                'src_ip', 'dst_ip', 'src_port', 'dst_port', 'src_mac', 'dst_mac',
                'tcp_flags', 'tcp_seq', 'tcp_ack', 'tcp_window',
                'payload_size', 'payload_hex', 'is_modbus', 'modbus_info'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for i, packet in enumerate(self.packets):
                packet_info = self.extract_packet_info(packet, i + 1)
                writer.writerow(packet_info)
                
        print(f"Individual packet data exported to: {packet_csv}")
        
        # 2. Modbus transaction CSV
        transactions = self.analyze_modbus_transactions()
        modbus_csv = os.path.join(output_dir, "modbus_transactions.csv")
        with open(modbus_csv, 'w', newline='', encoding='utf-8') as f:
            if transactions:
                fieldnames = [
                    'transaction_id', 'query_packet', 'response_packet',
                    'query_time', 'response_time', 'response_time_ms',
                    'client_ip', 'server_ip', 'function_code', 'function_name',
                    'unit_id', 'start_address', 'register_count',
                    'query_data', 'response_data', 'query_length', 'response_length'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for transaction in transactions:
                    writer.writerow(transaction)
                    
        print(f"Modbus transaction data exported to: {modbus_csv}")
        print(f"Found {len(transactions)} Modbus transactions")
        
        # 3. Network analysis report
        analysis = self.generate_network_analysis()
        analysis_file = os.path.join(output_dir, "network_analysis.json")
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
            
        # Also create a readable text report
        report_file = os.path.join(output_dir, "network_analysis_report.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("NETWORK BEHAVIOR ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("SUMMARY:\n")
            f.write("-" * 20 + "\n")
            for key, value in analysis['summary'].items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
            
            f.write("PROTOCOL DISTRIBUTION:\n")
            f.write("-" * 25 + "\n")
            for protocol, count in analysis['protocols'].items():
                percentage = (count / analysis['summary']['total_packets']) * 100
                f.write(f"{protocol}: {count} packets ({percentage:.1f}%)\n")
            f.write("\n")
            
            f.write("TOP IP CONNECTIONS:\n")
            f.write("-" * 20 + "\n")
            for connection, count in analysis['connections']['top_ip_pairs'].items():
                f.write(f"{connection}: {count} packets\n")
            f.write("\n")
            
            f.write("TOP PORTS:\n")
            f.write("-" * 10 + "\n")
            for port, count in analysis['connections']['top_ports'].items():
                f.write(f"{port}: {count} packets\n")
                
        print(f"Network analysis exported to: {analysis_file}")
        print(f"Human-readable report exported to: {report_file}")

def main():
    parser = argparse.ArgumentParser(description='Analyze PCAP files and export to CSV')
    parser.add_argument('pcap_file', help='Path to the PCAP file')
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: output)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap_file):
        print(f"Error: PCAP file '{args.pcap_file}' not found")
        sys.exit(1)
        
    analyzer = PCAPAnalyzer(args.pcap_file)
    
    if not analyzer.load_pcap():
        sys.exit(1)
        
    print("Analyzing packets and exporting to CSV...")
    analyzer.export_to_csv(args.output)
    print("Analysis complete!")

if __name__ == "__main__":
    main()