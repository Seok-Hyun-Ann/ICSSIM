import argparse
import csv
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Tuple, Optional, List

try:
    import pyshark
except ImportError as exc:
    raise SystemExit("PyShark is required. Install with `pip install pyshark` and be sure Wireshark/tshark is installed and in PATH.") from exc


###################################################################################################
# Utility helpers                                                                                 #
###################################################################################################

def safe_get(layer, attr: str, default: str = "") -> str:
    """Return the attribute value from a pyshark layer if present, else default."""
    return getattr(layer, attr, default) if layer else default


def write_csv(path: str, header: List[str], rows: List[List[str]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)

###################################################################################################
# Modbus/TCP correlation logic                                                                    #
###################################################################################################

class ModbusConversationTracker:
    """Track Modbus/TCP request-response pairs using transaction identifiers."""

    def __init__(self):
        # key -> query info dict
        self._pending: Dict[Tuple[str, str, str], Dict] = {}
        self._completed_rows: List[List[str]] = []

    @staticmethod
    def _build_key(src_port: str, dst_port: str, trans_id: str) -> Tuple[str, str, str]:
        return src_port, dst_port, trans_id

    def handle_packet(self, pkt):
        if "MODBUS" not in pkt:  # fast check
            return

        modbus_layer = pkt["MODBUS"]
        tcp_layer = pkt.get("TCP")
        if tcp_layer is None:
            return  # Not TCP? skip

        trans_id = safe_get(modbus_layer, "transaction_id")
        func_code = safe_get(modbus_layer, "func_code")
        unit_id = safe_get(modbus_layer, "unit_id")
        # Ports as str
        src_port = safe_get(tcp_layer, "srcport")
        dst_port = safe_get(tcp_layer, "dstport")

        timestamp = pkt.sniff_time  # datetime object
        timestamp_str = timestamp.isoformat(" ")

        # Heuristic: destination port 502 -> query, source port 502 -> response
        if dst_port == "502":  # Query
            key = self._build_key(src_port, dst_port, trans_id)
            self._pending[key] = {
                "trans_id": trans_id,
                "client_port": src_port,
                "server_port": dst_port,
                "func_code": func_code,
                "unit_id": unit_id,
                "query_time": timestamp,
                "query_time_str": timestamp_str,
                "client_ip": safe_get(pkt.ip, "src"),
                "server_ip": safe_get(pkt.ip, "dst"),
            }
        elif src_port == "502":  # Response
            # Query key should have client_port = dst_port (their src port)
            key = self._build_key(dst_port, src_port, trans_id)
            query = self._pending.pop(key, None)
            if query:
                delta = (timestamp - query["query_time"]).total_seconds() * 1000  # ms
                row = [
                    trans_id,
                    query["client_ip"],
                    query["server_ip"],
                    query["func_code"],
                    query["unit_id"],
                    query["query_time_str"],
                    timestamp_str,
                    f"{delta:.3f}",
                ]
                self._completed_rows.append(row)

    def get_rows(self) -> List[List[str]]:
        return self._completed_rows

###################################################################################################
# Main processing                                                                                 #
###################################################################################################

def process_pcap(pcap_path: str, out_dir: str):
    per_packet_rows: List[List[str]] = []
    modbus_tracker = ModbusConversationTracker()
    protocol_counter: Counter = Counter()

    capture = pyshark.FileCapture(
        pcap_path,
        include_raw=True,  # needed for payload
        keep_packets=False,  # streaming to reduce memory
    )

    for pkt in capture:
        try:
            frame_no = safe_get(pkt.frame_info, "number")
            timestamp = pkt.sniff_time.isoformat(" ")
            length = safe_get(pkt.frame_info, "len")
            highest_layer = pkt.highest_layer
            protocol_counter[highest_layer] += 1

            ip_layer = pkt.get("IP")
            src_ip, dst_ip = "", ""
            if ip_layer:
                src_ip = safe_get(ip_layer, "src")
                dst_ip = safe_get(ip_layer, "dst")

            transport = pkt.get("TCP") or pkt.get("UDP")
            src_port = dst_port = ""
            if transport:
                src_port = safe_get(transport, "srcport")
                dst_port = safe_get(transport, "dstport")

            payload = safe_get(pkt, "raw_packet" if hasattr(pkt, "raw_packet") else "")
            # Write basic row; payload may be long, so store first 50 bytes as hex
            payload_hex = ""
            if hasattr(pkt, "get_raw_packet"):  # pyshark 0.6+
                payload_hex = pkt.get_raw_packet()[:25].hex()

            per_packet_rows.append([
                frame_no,
                timestamp,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                highest_layer,
                length,
                payload_hex,
            ])

            # Modbus tracking
            if "MODBUS" in pkt:
                modbus_tracker.handle_packet(pkt)
        except Exception as exc:
            # graceful skip of problematic packet
            print(f"[WARN] Failed to process packet: {exc}")
            continue

    # Write per-packet CSV
    per_packet_header = [
        "frame_no",
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "highest_protocol",
        "length",
        "payload_first25bytes_hex",
    ]
    write_csv(os.path.join(out_dir, "packets.csv"), per_packet_header, per_packet_rows)

    # Write Modbus analysis CSV
    modbus_header = [
        "transaction_id",
        "client_ip",
        "server_ip",
        "func_code",
        "unit_id",
        "query_time",
        "response_time",
        "rtt_ms",
    ]
    write_csv(os.path.join(out_dir, "modbus_analysis.csv"), modbus_header, modbus_tracker.get_rows())

    # Write summary
    total_packets = sum(protocol_counter.values())
    summary_lines = [
        f"Input file: {pcap_path}",
        f"Total packets: {total_packets}",
        "Protocol distribution:",
    ]
    for proto, cnt in protocol_counter.most_common():
        summary_lines.append(f"  {proto}: {cnt}")

    if modbus_tracker.get_rows():
        rtt_values = [float(r[-1]) for r in modbus_tracker.get_rows()]
        avg_rtt = sum(rtt_values) / len(rtt_values)
        summary_lines.extend([
            "\nModbus/TCP statistics:",
            f"  Requests: {len(rtt_values)}",
            f"  Average RTT (ms): {avg_rtt:.3f}",
        ])
    summary_path = os.path.join(out_dir, "summary.txt")
    os.makedirs(out_dir, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as sf:
        sf.write("\n".join(summary_lines))

    print("Processing complete.")
    print(f"Generated files:\n - {os.path.abspath(os.path.join(out_dir, 'packets.csv'))}\n - {os.path.abspath(os.path.join(out_dir, 'modbus_analysis.csv'))}\n - {os.path.abspath(summary_path)}")

###################################################################################################
# CLI                                                                                             #
###################################################################################################


def main():
    parser = argparse.ArgumentParser(description="PCAP to CSV converter with Modbus analysis")
    parser.add_argument("input", help="Path to input pcap file")
    parser.add_argument("-o", "--out", default="output", help="Output directory (default: ./output)")
    args = parser.parse_args()

    pcap_path = os.path.abspath(args.input)
    out_dir = os.path.abspath(args.out)

    if not os.path.isfile(pcap_path):
        parser.error(f"Input file not found: {pcap_path}")

    process_pcap(pcap_path, out_dir)


if __name__ == "__main__":
    main()