#!/bin/bash

# ICS Network Monitor Script for Docker Environment
# 네트워크 패킷 분석을 위한 TCPDUMP 기반 모니터링 도구

echo "ICS Network Monitor"
echo "=================="

# 컨테이너 확인
echo "Checking running containers..."
docker-compose ps

echo ""
echo "Network Monitor Options:"
echo "1) Start interactive network monitor"
echo "2) Quick Modbus traffic capture (30s)"
echo "3) Monitor PLC communications"
echo "4) Security scan detection"
echo "5) Analyze existing PCAP file"
echo "6) Access HMI1 container for manual monitoring"
echo "7) Access HMI2 container for manual monitoring"
echo "0) Exit"

read -p "Select option: " choice

case $choice in
    1)
        echo "Starting interactive network monitor..."
        docker exec -it hmi1 python3 network_monitor_cli.py --interactive
        ;;
    2)
        echo "Starting Modbus traffic capture for 30 seconds..."
        docker exec -it hmi1 python3 network_monitor_cli.py --capture modbus_quick --filter "port 502" --duration 30
        ;;
    3)
        echo "PLC Communication Monitoring Options:"
        echo "a) Monitor PLC1 (192.168.0.11)"
        echo "b) Monitor PLC2 (192.168.0.12)"
        echo "c) Monitor both PLCs"
        read -p "Select PLC monitoring option: " plc_choice
        
        case $plc_choice in
            a)
                docker exec -it hmi1 python3 network_monitor_cli.py --capture plc1_monitor --filter "host 192.168.0.11" --duration 60
                ;;
            b)
                docker exec -it hmi1 python3 network_monitor_cli.py --capture plc2_monitor --filter "host 192.168.0.12" --duration 60
                ;;
            c)
                docker exec -it hmi1 python3 network_monitor_cli.py --capture plc_all_monitor --filter "host 192.168.0.11 or host 192.168.0.12" --duration 60
                ;;
            *)
                echo "Invalid option"
                ;;
        esac
        ;;
    4)
        echo "Starting security scan detection for 5 minutes..."
        docker exec -it hmi1 python3 network_monitor_cli.py --capture security_scan --filter "tcp[tcpflags] & tcp-syn != 0" --duration 300
        ;;
    5)
        echo "Enter PCAP file path (relative to container):"
        read -p "PCAP file: " pcap_file
        echo "Analysis type:"
        echo "1) Basic"
        echo "2) Modbus"
        echo "3) Security"
        read -p "Select analysis type: " analysis_type
        
        case $analysis_type in
            1) type="basic" ;;
            2) type="modbus" ;;
            3) type="security" ;;
            *) type="basic" ;;
        esac
        
        docker exec -it hmi1 python3 network_monitor_cli.py --analyze "$pcap_file" --analysis-type "$type"
        ;;
    6)
        echo "Accessing HMI1 container..."
        docker exec -it hmi1 bash
        ;;
    7)
        echo "Accessing HMI2 container..."
        docker exec -it hmi2 bash
        ;;
    0)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid option"
        ;;
esac

echo ""
echo "Network monitor operation completed."
echo "Check logs/network_monitor/ directory for capture files and analysis reports."