#!/usr/bin/env python3
"""
네트워크 모니터링 CLI 도구
TCPDUMP를 이용한 편리한 네트워크 패킷 분석
"""

import os
import sys
import time
import argparse
from datetime import datetime
from NetworkMonitor import network_monitor

class NetworkMonitorCLI:
    def __init__(self):
        self.monitor = network_monitor
        
    def interactive_mode(self):
        """대화형 모드"""
        print("\n" + "="*60)
        print("ICS Network Monitor - Interactive Mode")
        print("="*60)
        
        while True:
            self.show_menu()
            try:
                choice = input("\nYour choice: ").strip()
                
                if choice == '1':
                    self.start_capture_interactive()
                elif choice == '2':
                    self.stop_capture_interactive()
                elif choice == '3':
                    self.list_running_captures()
                elif choice == '4':
                    self.analyze_pcap_interactive()
                elif choice == '5':
                    self.show_predefined_filters()
                elif choice == '6':
                    self.quick_capture_menu()
                elif choice == '0':
                    self.cleanup_and_exit()
                else:
                    print("Invalid choice. Please try again.")
                    
            except (KeyboardInterrupt, EOFError):
                print("\nExiting...")
                self.cleanup_and_exit()
            except Exception as e:
                print(f"Error: {e}")
                
            input("\nPress Enter to continue...")
    
    def show_menu(self):
        """메인 메뉴 표시"""
        print("\n" + "-"*60)
        print("Network Monitor Menu:")
        print("1) Start packet capture")
        print("2) Stop packet capture")
        print("3) List running captures")
        print("4) Analyze PCAP file")
        print("5) Show predefined filters")
        print("6) Quick capture presets")
        print("0) Exit")
        print("-"*60)
    
    def start_capture_interactive(self):
        """대화형 캡처 시작"""
        print("\n--- Start Packet Capture ---")
        
        capture_name = input("Capture name: ").strip()
        if not capture_name:
            print("Capture name is required!")
            return
        
        print("\nAvailable interfaces:")
        print("- any (all interfaces)")
        print("- br_icsnet (ICS network bridge)")
        print("- eth0 (primary ethernet)")
        print("- lo (loopback)")
        
        interface = input("Interface [any]: ").strip() or 'any'
        
        print("\nFilter options:")
        filters = self.monitor.get_predefined_filters()
        for i, (name, filter_expr) in enumerate(filters.items(), 1):
            print(f"{i:2d}) {name}: {filter_expr}")
        
        filter_choice = input("\nSelect filter number or enter custom filter [empty for no filter]: ").strip()
        
        filter_expression = ""
        if filter_choice.isdigit():
            filter_idx = int(filter_choice) - 1
            filter_list = list(filters.items())
            if 0 <= filter_idx < len(filter_list):
                filter_name, filter_expression = filter_list[filter_idx]
                print(f"Selected filter: {filter_name} ({filter_expression})")
        elif filter_choice:
            filter_expression = filter_choice
        
        packet_count = input("Packet count limit [unlimited]: ").strip()
        packet_count = int(packet_count) if packet_count.isdigit() else None
        
        duration = input("Duration in seconds [unlimited]: ").strip()
        duration = int(duration) if duration.isdigit() else None
        
        real_time = input("Enable real-time analysis? (y/n) [n]: ").strip().lower() == 'y'
        
        print(f"\nStarting capture '{capture_name}'...")
        success = self.monitor.start_capture(
            capture_name=capture_name,
            interface=interface,
            filter_expression=filter_expression,
            packet_count=packet_count,
            duration=duration,
            real_time_analysis=real_time
        )
        
        if success:
            print(f"✓ Capture '{capture_name}' started successfully!")
        else:
            print(f"✗ Failed to start capture '{capture_name}'")
    
    def stop_capture_interactive(self):
        """대화형 캡처 중지"""
        print("\n--- Stop Packet Capture ---")
        
        running_captures = self.monitor.get_running_captures()
        if not running_captures:
            print("No running captures found.")
            return
        
        print("Running captures:")
        for i, (name, info) in enumerate(running_captures.items(), 1):
            print(f"{i}) {name} (started: {info['start_time']}, interface: {info['interface']})")
        
        choice = input("\nSelect capture number to stop or 'all' for all captures: ").strip()
        
        if choice.lower() == 'all':
            self.monitor.stop_all_captures()
            print("✓ All captures stopped!")
        elif choice.isdigit():
            capture_idx = int(choice) - 1
            capture_names = list(running_captures.keys())
            if 0 <= capture_idx < len(capture_names):
                capture_name = capture_names[capture_idx]
                if self.monitor.stop_capture(capture_name):
                    print(f"✓ Capture '{capture_name}' stopped!")
                else:
                    print(f"✗ Failed to stop capture '{capture_name}'")
            else:
                print("Invalid selection.")
        else:
            print("Invalid input.")
    
    def list_running_captures(self):
        """실행 중인 캡처 목록"""
        print("\n--- Running Captures ---")
        
        running_captures = self.monitor.get_running_captures()
        if not running_captures:
            print("No running captures.")
            return
        
        for name, info in running_captures.items():
            print(f"\nCapture: {name}")
            print(f"  Started: {info['start_time']}")
            print(f"  Interface: {info['interface']}")
            print(f"  Filter: {info['filter'] or 'None'}")
            print(f"  Output file: {info['output_file']}")
            if info['packet_count']:
                print(f"  Packet limit: {info['packet_count']}")
            if info['duration']:
                print(f"  Duration: {info['duration']} seconds")
    
    def analyze_pcap_interactive(self):
        """대화형 PCAP 분석"""
        print("\n--- Analyze PCAP File ---")
        
        pcap_file = input("PCAP file path: ").strip()
        if not pcap_file:
            print("PCAP file path is required!")
            return
        
        if not os.path.exists(pcap_file):
            print(f"File not found: {pcap_file}")
            return
        
        print("\nAnalysis types:")
        print("1) Basic analysis")
        print("2) Modbus protocol analysis")
        print("3) Security analysis")
        
        analysis_choice = input("Select analysis type [1]: ").strip() or '1'
        
        analysis_types = {'1': 'basic', '2': 'modbus', '3': 'security'}
        analysis_type = analysis_types.get(analysis_choice, 'basic')
        
        print(f"\nAnalyzing {pcap_file} with {analysis_type} analysis...")
        result = self.monitor.analyze_pcap_file(pcap_file, analysis_type)
        
        if result:
            print("\n--- Analysis Results ---")
            self.print_analysis_result(result)
            
            save_report = input("\nSave analysis report? (y/n) [y]: ").strip().lower() != 'n'
            if save_report:
                report_file = self.monitor.save_analysis_report(result)
                if report_file:
                    print(f"✓ Report saved to: {report_file}")
        else:
            print("✗ Analysis failed!")
    
    def print_analysis_result(self, result):
        """분석 결과 출력"""
        print(f"File: {result.get('file', 'N/A')}")
        print(f"Analysis type: {result.get('analysis_type', 'N/A')}")
        print(f"Timestamp: {result.get('timestamp', 'N/A')}")
        
        if result.get('analysis_type') == 'basic':
            print(f"Total packets: {result.get('total_packets', 0)}")
            protocols = result.get('protocols', {})
            if protocols:
                print("Protocols:")
                for protocol, count in protocols.items():
                    print(f"  {protocol}: {count}")
        
        elif result.get('analysis_type') == 'modbus':
            print(f"Modbus packets: {result.get('modbus_packets', 0)}")
            devices = result.get('devices', {})
            if devices:
                print("Devices:")
                for device, count in devices.items():
                    print(f"  {device}: {count} packets")
        
        elif result.get('analysis_type') == 'security':
            print(f"Scan attempts: {result.get('scan_attempts', 0)}")
            alerts = result.get('alerts', [])
            if alerts:
                print("Security alerts:")
                for alert in alerts:
                    print(f"  {alert['type']} ({alert['severity']}): {alert['description']}")
    
    def show_predefined_filters(self):
        """사전 정의된 필터 표시"""
        print("\n--- Predefined Filters ---")
        
        filters = self.monitor.get_predefined_filters()
        for name, filter_expr in filters.items():
            print(f"{name:20s}: {filter_expr}")
    
    def quick_capture_menu(self):
        """빠른 캡처 프리셋"""
        print("\n--- Quick Capture Presets ---")
        print("1) Monitor all Modbus traffic (30 seconds)")
        print("2) Monitor PLC1 traffic (60 seconds)")
        print("3) Monitor PLC2 traffic (60 seconds)")
        print("4) Monitor HMI traffic (60 seconds)")
        print("5) Monitor attacker traffic (60 seconds)")
        print("6) Security scan detection (300 seconds)")
        
        choice = input("\nSelect preset: ").strip()
        
        presets = {
            '1': ('modbus_monitor', 'any', 'port 502', 30),
            '2': ('plc1_monitor', 'any', 'host 192.168.0.11', 60),
            '3': ('plc2_monitor', 'any', 'host 192.168.0.12', 60),
            '4': ('hmi_monitor', 'any', 'host 192.168.0.21 or host 192.168.0.22', 60),
            '5': ('attacker_monitor', 'any', 'host 192.168.0.41 or host 192.168.0.42 or host 192.168.0.43', 60),
            '6': ('security_scan', 'any', 'tcp[tcpflags] & tcp-syn != 0', 300)
        }
        
        if choice in presets:
            name, interface, filter_expr, duration = presets[choice]
            timestamp = datetime.now().strftime('%H%M%S')
            capture_name = f"{name}_{timestamp}"
            
            print(f"Starting {name} capture for {duration} seconds...")
            success = self.monitor.start_capture(
                capture_name=capture_name,
                interface=interface,
                filter_expression=filter_expr,
                duration=duration,
                real_time_analysis=True
            )
            
            if success:
                print(f"✓ Quick capture '{capture_name}' started!")
                print(f"Will run for {duration} seconds...")
            else:
                print(f"✗ Failed to start quick capture")
        else:
            print("Invalid selection.")
    
    def cleanup_and_exit(self):
        """정리 후 종료"""
        print("\nStopping all running captures...")
        self.monitor.stop_all_captures()
        print("Goodbye!")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='ICS Network Monitor CLI')
    parser.add_argument('--interactive', '-i', action='store_true', 
                       help='Run in interactive mode')
    parser.add_argument('--capture', '-c', type=str, 
                       help='Start capture with given name')
    parser.add_argument('--interface', type=str, default='any',
                       help='Network interface to monitor')
    parser.add_argument('--filter', '-f', type=str, default='',
                       help='Packet filter expression')
    parser.add_argument('--duration', '-d', type=int,
                       help='Capture duration in seconds')
    parser.add_argument('--count', type=int,
                       help='Number of packets to capture')
    parser.add_argument('--analyze', '-a', type=str,
                       help='Analyze PCAP file')
    parser.add_argument('--analysis-type', type=str, default='basic',
                       choices=['basic', 'modbus', 'security'],
                       help='Type of analysis to perform')
    parser.add_argument('--list-captures', '-l', action='store_true',
                       help='List running captures')
    parser.add_argument('--stop', '-s', type=str,
                       help='Stop capture by name')
    parser.add_argument('--stop-all', action='store_true',
                       help='Stop all running captures')
    
    args = parser.parse_args()
    
    cli = NetworkMonitorCLI()
    
    try:
        if args.interactive:
            cli.interactive_mode()
        elif args.capture:
            success = network_monitor.start_capture(
                capture_name=args.capture,
                interface=args.interface,
                filter_expression=args.filter,
                packet_count=args.count,
                duration=args.duration,
                real_time_analysis=True
            )
            if success:
                print(f"✓ Capture '{args.capture}' started!")
            else:
                print(f"✗ Failed to start capture '{args.capture}'")
        elif args.analyze:
            result = network_monitor.analyze_pcap_file(args.analyze, args.analysis_type)
            if result:
                cli.print_analysis_result(result)
                network_monitor.save_analysis_report(result)
            else:
                print("✗ Analysis failed!")
        elif args.list_captures:
            cli.list_running_captures()
        elif args.stop:
            if network_monitor.stop_capture(args.stop):
                print(f"✓ Capture '{args.stop}' stopped!")
            else:
                print(f"✗ Failed to stop capture '{args.stop}'")
        elif args.stop_all:
            network_monitor.stop_all_captures()
            print("✓ All captures stopped!")
        else:
            print("No action specified. Use --help for usage information.")
            print("Use --interactive for interactive mode.")
    
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        cli.cleanup_and_exit()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()