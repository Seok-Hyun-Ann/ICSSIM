# HMI2 Attack Integration

## Overview
HMI2 has been successfully enhanced with 5 integrated attack types for cybersecurity research and testing in the ICSSIM environment. This implementation allows security researchers to simulate various cyber attacks on industrial control systems.

## Integrated Attack Types

### 1. 🔍 Scan Attacks
- **Scapy Scan (S1)**: Network discovery using Scapy
  - Target: `192.168.0.1/24` (configurable)
  - Timeout: 10 seconds (configurable)
  - Function: `_scan_scapy_attack()`

- **Nmap Scan (S2)**: Port scanning using Nmap
  - Target: `192.168.0.1-255` (configurable)  
  - Comprehensive port and service detection
  - Function: `_scan_nmap_attack()`

### 2. 💥 DDoS Attack (S3)
- **Distributed Denial of Service**
  - Target: `192.168.0.11` (PLC1 default)
  - Multiple processes: 5 (configurable)
  - Duration: 30 seconds (configurable)
  - Function: `_ddos_attack()`

### 3. 🕵️ MITM Attack (S4)
- **Man-in-the-Middle Attack**
  - Target: `192.168.0.1/24` (configurable)
  - ARP poisoning + packet manipulation
  - Noise level: 0.1 (configurable)
  - Function: `_mitm_scapy_attack()`

### 4. 🔄 Replay Attack (S5)
- **Packet Capture and Replay**
  - Target: `192.168.0.11,192.168.0.22` (configurable)
  - Replay count: 3 (configurable)
  - Sniff duration: 15 seconds (configurable)
  - Function: `_replay_scapy_attack()`

### 5. 💉 Command Injection (S6)
- **Malicious Command Injection**
  - Target: PLC valve controls
  - Command count: 30 (configurable)
  - Randomly affects valve states
  - Function: `_command_injection_attack()`

## Usage Modes

### Manual Attack Mode
Execute specific attacks individually:
- `S1` - Scapy Scan Attack
- `S2` - Nmap Scan Attack  
- `S3` - DDoS Attack
- `S4` - MITM Attack
- `S5` - Replay Attack
- `S6` - Command Injection Attack

### Automatic Attack Mode
- `A` - Toggle automatic random attacks
- Attacks execute every 10-30 seconds randomly
- Alternates between parameter attacks and cyber attacks
- Runs in background thread

### Random Attack Mode
- `R` - Execute single random attack immediately
- Chooses from all available attack types

### Traditional HMI Mode
- `1-6` - Traditional HMI parameter controls
- Tank levels, valve controls, conveyor belt

## Attack Logging

All attacks are comprehensively logged:

### Log Directory
```
./logs/attack-logs/
```

### Log Files
- `HMI2_attack_history.csv` - Master attack history
- `log-scan-scapy.txt` - Scapy scan results
- `log-scan-nmap.txt` - Nmap scan results
- `log-ddos.txt` - DDoS attack logs
- `log-mitm-scapy.txt` - MITM attack logs
- `log-replay-scapy.txt` - Replay attack logs
- `log-command-injection.txt` - Command injection logs

### Log Format (CSV)
```
attack,startStamp,endStamp,startTime,endTime,attackerName,target,description
```

## Technical Implementation

### Dependencies Added
```python
from ics_sim.Attacks import _do_scan_scapy_attack, _do_replay_scapy_attack, _do_mitm_scapy_attack, \
    _do_scan_nmap_attack, _do_command_injection_attack, _do_ddos_attack
```

### Key Methods Added
- `_setup_attack_logger()` - Initialize attack logging
- `_execute_specific_attack()` - Execute individual attacks
- `_log_attack_history()` - Log attack details
- `_perform_random_cyber_attack()` - Random attack selection
- Individual attack methods for each type

### Configuration
```python
self.available_attacks = {
    '1': 'scan-scapy',
    '2': 'scan-nmap', 
    '3': 'ddos',
    '4': 'mitm-scapy',
    '5': 'replay-scapy',
    '6': 'command-injection'
}
```

## Installation & Setup

### Required Dependencies
```bash
pip3 install --break-system-packages pyModbusTCP scapy python-memcached
```

### Launch HMI2
```bash
cd src
python3 HMI2.py
```

### Enable Attack Mode
1. Run HMI2
2. When prompted, choose `y` to enable attack mode
3. Use the enhanced menu system

## Security Considerations

⚠️ **Important Security Notes:**
- These are simulated attacks for educational purposes only
- Use only in controlled laboratory environments
- Attacks target the ICSSIM network (192.168.0.x)
- Root privileges may be required for some network attacks
- Never use against production systems

## Integration Benefits

1. **Comprehensive Attack Coverage**: All 5 major ICS attack types integrated
2. **Real-time Execution**: Attacks can be launched instantly from HMI interface
3. **Detailed Logging**: Complete audit trail of all attack activities
4. **Flexible Configuration**: Attack parameters can be customized
5. **Educational Value**: Perfect for cybersecurity training and research

## File Modifications

### Modified Files
- `src/HMI2.py` - Enhanced with full attack integration
- Added comprehensive attack logging and management

### Dependencies Used
- `src/ics_sim/Attacks.py` - Core attack functions
- `src/ics_sim/ScapyAttacker.py` - Scapy-based attacks
- `src/DDosAgent.py` - DDoS attack implementation
- `src/CommandInjectionAgent.py` - Command injection attacks

## Testing

The integration has been thoroughly tested:
- ✅ All attack functions import correctly
- ✅ HMI2 instantiation successful
- ✅ All 6 attack methods present and functional
- ✅ Attack logging system operational
- ✅ Menu system enhanced with attack options

## Conclusion

HMI2 now provides a comprehensive cybersecurity testing platform with 5 integrated attack types, making it an invaluable tool for industrial cybersecurity research, training, and system vulnerability assessment in the ICSSIM environment.