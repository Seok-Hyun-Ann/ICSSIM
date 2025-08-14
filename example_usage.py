#!/usr/bin/env python3
"""
Example usage of PCAP Analyzer
This script demonstrates how to use the pcap_analyzer.py tool
"""

import os
import sys
from pcap_analyzer import PCAPAnalyzer

def analyze_sample_pcap():
    """Example function to analyze a PCAP file"""
    
    # Example PCAP file path (replace with your actual file)
    pcap_file = "sample_network_capture.pcap"
    
    # Check if file exists
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file '{pcap_file}' not found")
        print("Please provide a valid PCAP file path")
        return False
    
    # Create analyzer instance
    print("Creating PCAP analyzer...")
    analyzer = PCAPAnalyzer(pcap_file)
    
    # Load the PCAP file
    if not analyzer.load_pcap():
        print("Failed to load PCAP file")
        return False
    
    # Export analysis to CSV files
    output_directory = "analysis_output"
    print(f"Exporting analysis to '{output_directory}' directory...")
    analyzer.export_to_csv(output_directory)
    
    print("Analysis complete!")
    print(f"\nGenerated files in '{output_directory}':")
    print("- network_packets.csv (개별 패킷 정보)")
    print("- modbus_transactions.csv (Modbus 트랜잭션 분석)")
    print("- network_analysis.json (네트워크 분석 데이터)")
    print("- network_analysis_report.txt (분석 리포트)")
    
    return True

def demonstrate_manual_analysis():
    """Demonstrate manual analysis of specific aspects"""
    
    pcap_file = "sample_network_capture.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"PCAP file '{pcap_file}' not found for manual analysis demo")
        return
    
    analyzer = PCAPAnalyzer(pcap_file)
    if not analyzer.load_pcap():
        return
    
    print("\n=== Manual Analysis Demo ===")
    
    # Analyze Modbus transactions specifically
    print("Analyzing Modbus transactions...")
    transactions = analyzer.analyze_modbus_transactions()
    
    if transactions:
        print(f"Found {len(transactions)} Modbus transactions:")
        for i, trans in enumerate(transactions[:5], 1):  # Show first 5
            print(f"  {i}. Transaction ID: {trans['transaction_id']}")
            print(f"     Function: {trans['function_name']}")
            print(f"     Response time: {trans['response_time_ms']} ms")
            print(f"     Client: {trans['client_ip']} -> Server: {trans['server_ip']}")
            print()
    else:
        print("No Modbus transactions found in the capture")
    
    # Generate network analysis
    print("Generating network behavior analysis...")
    analysis = analyzer.generate_network_analysis()
    
    print(f"Summary:")
    print(f"  Total packets: {analysis['summary']['total_packets']}")
    print(f"  Duration: {analysis['summary']['duration_seconds']} seconds")
    print(f"  Average packet size: {analysis['summary']['average_packet_size']} bytes")
    
    print(f"\nProtocol distribution:")
    for protocol, count in analysis['protocols'].items():
        percentage = (count / analysis['summary']['total_packets']) * 100
        print(f"  {protocol}: {count} packets ({percentage:.1f}%)")

if __name__ == "__main__":
    print("PCAP Analyzer Example Usage")
    print("=" * 40)
    
    # Method 1: Basic analysis
    print("\nMethod 1: Basic Analysis")
    print("-" * 25)
    
    if len(sys.argv) > 1:
        # Use provided PCAP file
        pcap_file = sys.argv[1]
        analyzer = PCAPAnalyzer(pcap_file)
        if analyzer.load_pcap():
            analyzer.export_to_csv("example_output")
    else:
        # Use default file
        analyze_sample_pcap()
    
    # Method 2: Manual analysis demonstration
    print("\nMethod 2: Manual Analysis")
    print("-" * 26)
    demonstrate_manual_analysis()
    
    print("\n사용법:")
    print("python example_usage.py [pcap_file_path]")
    print("\n예시:")
    print("python example_usage.py my_capture.pcap")