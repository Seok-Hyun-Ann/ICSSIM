# PCAP CSV/Analysis Utility

This utility converts a `.pcap`/`.pcapng` into:

- Per-packet CSV (`per_packet.csv`) with headers, addresses, ports, flags, payload hex, and common protocol fields (TCP/UDP/DNS/mDNS/Modbus/TCP)
- Modbus/TCP query-response correlation CSV (`modbus_correlated.csv`) using Transaction Identifier and TCP stream
- A concise markdown analysis report (`analysis.md`) with protocol breakdown, top talkers, Modbus statistics, and mDNS services

It relies on Wireshark's `tshark` for decoding.

## Requirements

- Wireshark (includes `tshark`)
- Python 3.8+

On Windows, `tshark` is usually at:

- `C:\\Program Files\\Wireshark\\tshark.exe`
- `C:\\Program Files (x86)\\Wireshark\\tshark.exe`

## Install

No installation needed. Optional: create a virtual environment.

```powershell
py -3 -m venv .venv
. .venv\Scripts\Activate.ps1
```

## Usage

```powershell
# Basic (tshark on PATH)
python pcap_to_csv.py --pcap C:\path\to\file.pcapng --out C:\path\to\outdir

# Explicit tshark path
python pcap_to_csv.py --pcap C:\path\to\file.pcap --out C:\path\to\outdir --tshark "C:\Program Files\Wireshark\tshark.exe"
```

Outputs inside the `--out` directory:

- `per_packet.csv`
- `modbus_correlated.csv`
- `analysis.md`

## Notes

- mDNS is detected as DNS over UDP port 5353. Relevant query names, PTR/SRV targets are exported when present.
- Modbus request/response direction is inferred by port 502 (client -> server for requests). If your capture is reversed (non-standard port), the CSV will still include fields but correlation may be partial.
- The script works with both `.pcap` and `.pcapng` files.
- Very large pcaps will take time; ensure enough RAM/disk space.