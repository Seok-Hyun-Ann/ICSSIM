# PCAP to CSV Converter

This project provides a simple Python utility to convert a `.pcap` capture file into two CSV files—one with **per-packet details** and another with **Modbus/TCP query-response analysis**—plus a text file summarising overall network statistics.

---

## Features

1. **`packets.csv`** – Each packet in the capture, including timestamp, IP/port information, protocol, length, and a preview of the payload (first 25 bytes in hex).
2. **`modbus_analysis.csv`** – Pairs Modbus/TCP requests with their corresponding responses using the Transaction ID, showing round-trip time (RTT) and other key fields.
3. **`summary.txt`** – High-level statistics such as packet counts per protocol and average Modbus RTT.

---

## Installation

1. Install **Wireshark** (or the standalone *TShark*) and make sure `tshark` is in your system `PATH`.
2. Install Python dependencies:

```powershell
pip install pyshark
```

> ⚠️ `pyshark` is a thin wrapper around *TShark*, so Wireshark/TShark **must** be installed first.

---

## Usage

```powershell
python pcap_to_csv.py <input_file>.pcap [-o <output_dir>]
```

*Example:*

```powershell
python pcap_to_csv.py capture.pcap -o results
```

This command creates `results/packets.csv`, `results/modbus_analysis.csv`, and `results/summary.txt`.

---

## File Descriptions

### packets.csv

| Column | Description |
|--------|-------------|
| frame_no | Sequential frame/packet number from the capture |
| timestamp | Capture time in ISO-8601 format |
| src_ip / dst_ip | Source / Destination IP addresses |
| src_port / dst_port | Source / Destination ports (blank for non-TCP/UDP packets) |
| highest_protocol | Highest-level protocol identified by Wireshark (e.g. TCP, MODBUS, MDNS) |
| length | Frame length in bytes |
| payload_first25bytes_hex | Hex-encoded preview of the first 25 bytes |

### modbus_analysis.csv

| Column | Description |
|--------|-------------|
| transaction_id | Modbus/TCP Transaction ID |
| client_ip / server_ip | Addresses participating in the exchange |
| func_code | Modbus function code |
| unit_id | Target unit ID |
| query_time | Timestamp of the request |
| response_time | Timestamp of the matching response |
| rtt_ms | Round-trip time in milliseconds |

### summary.txt

Human-readable overview that currently includes:

* Total packet count
* Protocol distribution (how many packets of each protocol)
* Modbus statistics (request count & average RTT)

---

## Customisation Tips

* **Additional Fields** – Edit `pcap_to_csv.py` to add more columns from any Wireshark-recognised protocol layer.
* **Different Protocols** – The same pattern used for Modbus can be extended to other request/response protocols (DNS, HTTP, etc.).

---

## Troubleshooting

* **`OSError: tshark not found`** – Ensure Wireshark/TShark is installed and its directory is added to the `PATH` environment variable.
* **Permissions** – On Windows, you may need to run the command prompt or PowerShell as Administrator if the pcap file is in a protected directory.

---

© 2024  
