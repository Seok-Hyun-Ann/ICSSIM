#!/usr/bin/env python3

import argparse
import csv
import os
import sys
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# PyShark is lazily imported inside parse_pcap() so --help works without dependencies


def safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return default


def get_layer(packet: Any, *layer_names: str) -> Optional[Any]:
    for name in layer_names:
        try:
            if hasattr(packet, name):
                return getattr(packet, name)
        except Exception:
            continue
    # Walk generic layers for case-insensitive matches
    try:
        for lyr in packet.layers:
            lname = safe_getattr(lyr, 'layer_name', '').lower()
            if lname in [n.lower() for n in layer_names]:
                return lyr
    except Exception:
        pass
    return None


def get_field_values(layer: Any, candidates: List[str]) -> Optional[str]:
    if layer is None:
        return None
    for cand in candidates:
        # Direct attribute
        val = safe_getattr(layer, cand)
        if val is not None:
            try:
                return str(val)
            except Exception:
                return None
        # PyShark internal field map
        try:
            fields = getattr(layer, '_all_fields', None)
            if fields and cand in fields:
                v = fields[cand]
                return str(v.show)
        except Exception:
            pass
    return None


def write_utf8_bom_csv(path: str, header: List[str]) -> csv.DictWriter:
    f = open(path, 'w', encoding='utf-8-sig', newline='')
    writer = csv.DictWriter(f, fieldnames=header)
    writer.writeheader()
    # Attach the file object so we can close later
    writer._file = f  # type: ignore[attr-defined]
    return writer


def close_writer(writer: csv.DictWriter) -> None:
    f = getattr(writer, '_file', None)
    if f:
        try:
            f.close()
        except Exception:
            pass


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Parse PCAP to CSV (packets + Modbus conversations) and analysis report.')
    p.add_argument('--pcap', required=True, help='Path to .pcap or .pcapng file')
    p.add_argument('--out', required=True, help='Output directory for CSV/analysis files')
    p.add_argument('--only-modbus', action='store_true', help='Only export Modbus/TCP conversations; skip packets.csv')
    p.add_argument('--display-filter', default=None, help='Optional Wireshark display filter (e.g., "tcp || udp")')
    p.add_argument('--max-packets', type=int, default=None, help='Optional limit for packets to process (for testing)')
    return p


PacketRow = Dict[str, Any]
ConversationKey = Tuple[str, str, str, str, str]  # src_ip, src_port, dst_ip, dst_port, trans_id


def packet_row_header() -> List[str]:
    return [
        'frame_no', 'time_epoch', 'time', 'time_delta', 'highest_layer', 'protocols',
        'src_mac', 'dst_mac', 'eth_type',
        'ip_version', 'src_ip', 'dst_ip', 'ip_id', 'ip_ttl', 'ip_flags', 'l4_proto',
        'src_port', 'dst_port', 'tcp_seq', 'tcp_ack', 'tcp_flags', 'tcp_len', 'tcp_window', 'udp_length',
        'app_protocol',
        'dns_id', 'dns_qr', 'dns_qname', 'dns_qtype', 'dns_rcode',
        'mdns_service',
        'modbus_tid', 'modbus_proto_id', 'modbus_len', 'modbus_uid', 'modbus_func',
        'modbus_reference', 'modbus_word_count', 'modbus_byte_count', 'modbus_exception',
        'payload_len'
    ]


def conversation_row_header() -> List[str]:
    return [
        'req_frame', 'resp_frame', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'unit_id', 'func_code',
        'transaction_id', 'reference', 'word_count', 'byte_count', 'values', 'exception', 'rtt_ms'
    ]


class Stats:
    def __init__(self) -> None:
        self.total_packets = 0
        self.l4_counter: Counter[str] = Counter()
        self.highest_counter: Counter[str] = Counter()
        self.ip_talkers: Counter[str] = Counter()
        self.ip_pairs: Counter[str] = Counter()
        self.modbus_func_counter: Counter[str] = Counter()
        self.modbus_rtts: List[float] = []
        self.modbus_exceptions = 0
        self.mdns_queries = 0
        self.mdns_responses = 0
        self.mdns_services: Counter[str] = Counter()

    def add_packet(self, pkt: Any) -> None:
        self.total_packets += 1
        highest = safe_getattr(pkt, 'highest_layer', '') or ''
        self.highest_counter[highest] += 1
        try:
            ip = get_layer(pkt, 'ip', 'ipv6')
            if ip is not None:
                src = get_field_values(ip, ['src', 'addr', 'src_host']) or ''
                dst = get_field_values(ip, ['dst', 'addr', 'dst_host']) or ''
                if src:
                    self.ip_talkers[src] += 1
                if src and dst:
                    self.ip_pairs[f"{src} -> {dst}"] += 1
        except Exception:
            pass

    def add_l4(self, proto: str) -> None:
        if proto:
            self.l4_counter[proto] += 1

    def add_modbus_func(self, func_code: Optional[str]) -> None:
        if func_code:
            self.modbus_func_counter[func_code] += 1

    def add_modbus_rtt(self, rtt_ms: float) -> None:
        self.modbus_rtts.append(rtt_ms)

    def add_modbus_exception(self) -> None:
        self.modbus_exceptions += 1

    def add_mdns(self, qr: Optional[str], service: Optional[str]) -> None:
        if qr == '0' or qr == 'query':
            self.mdns_queries += 1
        elif qr == '1' or qr == 'response':
            self.mdns_responses += 1
        if service:
            self.mdns_services[service] += 1

    def to_markdown(self) -> str:
        lines: List[str] = []
        lines.append(f"**Total packets**: {self.total_packets}")
        if self.l4_counter:
            lines.append("\n**L4 protocol counts**:")
            for proto, cnt in self.l4_counter.most_common():
                lines.append(f"- {proto}: {cnt}")
        if self.highest_counter:
            lines.append("\n**Highest layer counts**:")
            for name, cnt in self.highest_counter.most_common():
                lines.append(f"- {name}: {cnt}")
        if self.ip_talkers:
            lines.append("\n**Top IP talkers**:")
            for ip, cnt in self.ip_talkers.most_common(10):
                lines.append(f"- {ip}: {cnt}")
        if self.ip_pairs:
            lines.append("\n**Top IP pairs**:")
            for pair, cnt in self.ip_pairs.most_common(10):
                lines.append(f"- {pair}: {cnt}")
        if self.modbus_func_counter:
            lines.append("\n**Modbus function codes**:")
            for fcode, cnt in self.modbus_func_counter.most_common():
                lines.append(f"- {fcode}: {cnt}")
        if self.modbus_rtts:
            rtts = self.modbus_rtts
            lines.append("\n**Modbus RTT (ms)**:")
            lines.append(f"- count: {len(rtts)}")
            lines.append(f"- min/avg/median/max: {min(rtts):.3f} / {statistics.mean(rtts):.3f} / {statistics.median(rtts):.3f} / {max(rtts):.3f}")
            lines.append(f"- exceptions: {self.modbus_exceptions}")
        if self.mdns_queries or self.mdns_responses:
            lines.append("\n**mDNS activity**:")
            lines.append(f"- queries: {self.mdns_queries}")
            lines.append(f"- responses: {self.mdns_responses}")
            if self.mdns_services:
                lines.append("- common services:")
                for svc, cnt in self.mdns_services.most_common(10):
                    lines.append(f"  - {svc}: {cnt}")
        return "\n".join(lines) + "\n"


def extract_dns_fields(pkt: Any) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    dns = get_layer(pkt, 'dns', 'mdns')
    if not dns:
        return None, None, None, None, None, None
    dns_id = get_field_values(dns, ['id'])
    qr = get_field_values(dns, ['flags_response', 'qr'])
    qname = get_field_values(dns, ['qry_name', 'qry_name_utf8', 'qname', 'ptr_domain_name'])
    qtype = get_field_values(dns, ['qry_type', 'qtype'])
    rcode = get_field_values(dns, ['flags_rcode', 'rcode'])
    # mDNS service extraction (PTR names usually hold service)
    service = None
    try:
        if qname and (qname.endswith('.local') or '._' in qname):
            service = qname
    except Exception:
        pass
    return dns_id, qr, qname, qtype, rcode, service


def extract_modbus_fields(pkt: Any) -> Dict[str, Optional[str]]:
    modbus = get_layer(pkt, 'modbus', 'mbtcp')
    if not modbus:
        return {k: None for k in [
            'tid', 'proto_id', 'length', 'unit_id', 'func_code', 'reference', 'word_cnt', 'byte_cnt', 'exception', 'values'
        ]}
    # Try multiple candidate field names for robustness
    fields = {
        'tid': get_field_values(modbus, ['trans_id', 'transaction_id', 'modbus_trans_id', 'transid', 'transaction_identifier']),
        'proto_id': get_field_values(modbus, ['proto_id', 'protocol_id']),
        'length': get_field_values(modbus, ['len', 'length']),
        'unit_id': get_field_values(modbus, ['unit_id', 'uid', 'unit_identifier']),
        'func_code': get_field_values(modbus, ['func_code', 'function_code']),
        'reference': get_field_values(modbus, ['reference_num', 'reference', 'start_addr', 'reference_number']),
        'word_cnt': get_field_values(modbus, ['word_cnt', 'word_count']),
        'byte_cnt': get_field_values(modbus, ['byte_cnt', 'byte_count']),
        'exception': get_field_values(modbus, ['exception_code', 'exception']),
        'values': None,
    }
    # Try to collect register values; different dissectors expose differently
    try:
        values = []
        all_fields = getattr(modbus, '_all_fields', {}) or {}
        for key, f in all_fields.items():  # type: ignore[assignment]
            if key.endswith('regval') or key.endswith('register_value') or key.endswith('registers'):
                try:
                    show = f.show
                    if isinstance(show, list):
                        values.extend([str(x) for x in show])
                    else:
                        values.append(str(show))
                except Exception:
                    continue
        if not values:
            # Last resort: 'data' may contain concatenated values
            dv = get_field_values(modbus, ['data'])
            if dv:
                values.append(dv)
        if values:
            fields['values'] = ';'.join(values)
    except Exception:
        pass
    return fields


def parse_pcap(pcap_path: str, out_dir: str, only_modbus: bool = False, display_filter: Optional[str] = None, max_packets: Optional[int] = None) -> None:
    os.makedirs(out_dir, exist_ok=True)

    # Writers
    packets_writer: Optional[csv.DictWriter] = None
    if not only_modbus:
        packets_writer = write_utf8_bom_csv(os.path.join(out_dir, 'packets.csv'), packet_row_header())

    conversations_writer = write_utf8_bom_csv(os.path.join(out_dir, 'modbus_conversations.csv'), conversation_row_header())

    stats = Stats()

    # Outstanding Modbus requests keyed by 5-tuple + TID
    pending: Dict[ConversationKey, Dict[str, Any]] = {}

    # Lazy import here to allow --help to run without pyshark/tshark installed
    try:
        import pyshark  # type: ignore
    except Exception as exc:
        print("PyShark/TShark is required to parse pcap. Install Wireshark (with TShark) and run 'pip install -r requirements.txt'.", file=sys.stderr)
        raise

    capture = pyshark.FileCapture(
        input_file=pcap_path,
        display_filter=display_filter,
        keep_packets=False,
        use_json=True,
        include_raw=False,
    )

    processed = 0
    try:
        for pkt in capture:
            processed += 1
            if max_packets is not None and processed > max_packets:
                break

            stats.add_packet(pkt)

            frame = get_layer(pkt, 'frame')
            frame_no = get_field_values(frame, ['number']) if frame else None
            time_epoch = get_field_values(frame, ['time_epoch']) if frame else None
            time_delta = get_field_values(frame, ['time_delta']) if frame else None
            protocols = get_field_values(frame, ['protocols']) if frame else None
            sniff_time = safe_getattr(pkt, 'sniff_time', None)
            time_str = sniff_time.isoformat() if sniff_time else None

            eth = get_layer(pkt, 'eth')
            src_mac = get_field_values(eth, ['src']) if eth else None
            dst_mac = get_field_values(eth, ['dst']) if eth else None
            eth_type = get_field_values(eth, ['type']) if eth else None

            ip = get_layer(pkt, 'ip', 'ipv6')
            ip_version = '4' if get_layer(pkt, 'ip') else ('6' if get_layer(pkt, 'ipv6') else None)
            src_ip = get_field_values(ip, ['src', 'addr']) if ip else None
            dst_ip = get_field_values(ip, ['dst', 'addr']) if ip else None
            ip_id = get_field_values(ip, ['id']) if ip else None
            ip_ttl = get_field_values(ip, ['ttl', 'hop_limit']) if ip else None
            ip_flags = get_field_values(ip, ['flags']) if ip else None

            tcp = get_layer(pkt, 'tcp')
            udp = get_layer(pkt, 'udp')
            l4_proto = 'TCP' if tcp else ('UDP' if udp else None)
            stats.add_l4(l4_proto or '')

            src_port = dst_port = None
            tcp_seq = tcp_ack = tcp_flags = tcp_len = tcp_window = None
            udp_length = None

            if tcp:
                src_port = get_field_values(tcp, ['srcport', 'src_port'])
                dst_port = get_field_values(tcp, ['dstport', 'dst_port'])
                tcp_seq = get_field_values(tcp, ['seq', 'seq_raw'])
                tcp_ack = get_field_values(tcp, ['ack', 'ack_raw'])
                tcp_flags = get_field_values(tcp, ['flags', 'flags_str'])
                tcp_len = get_field_values(tcp, ['len'])
                tcp_window = get_field_values(tcp, ['window_size', 'window_size_value'])
            elif udp:
                src_port = get_field_values(udp, ['srcport', 'src_port'])
                dst_port = get_field_values(udp, ['dstport', 'dst_port'])
                udp_length = get_field_values(udp, ['length', 'len'])

            highest_layer = safe_getattr(pkt, 'highest_layer', None)
            app_protocol = highest_layer

            # DNS/mDNS fields
            dns_id, dns_qr, dns_qname, dns_qtype, dns_rcode, mdns_service = extract_dns_fields(pkt)
            if dns_qr or mdns_service:
                stats.add_mdns(dns_qr, mdns_service)

            # Modbus fields
            modbus_fields = extract_modbus_fields(pkt)
            if modbus_fields.get('func_code'):
                stats.add_modbus_func(modbus_fields['func_code'])

            # Build packet row if requested
            if packets_writer:
                row: PacketRow = {
                    'frame_no': frame_no,
                    'time_epoch': time_epoch,
                    'time': time_str,
                    'time_delta': time_delta,
                    'highest_layer': highest_layer,
                    'protocols': protocols,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'eth_type': eth_type,
                    'ip_version': ip_version,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'ip_id': ip_id,
                    'ip_ttl': ip_ttl,
                    'ip_flags': ip_flags,
                    'l4_proto': l4_proto,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'tcp_seq': tcp_seq,
                    'tcp_ack': tcp_ack,
                    'tcp_flags': tcp_flags,
                    'tcp_len': tcp_len,
                    'tcp_window': tcp_window,
                    'udp_length': udp_length,
                    'app_protocol': app_protocol,
                    'dns_id': dns_id,
                    'dns_qr': dns_qr,
                    'dns_qname': dns_qname,
                    'dns_qtype': dns_qtype,
                    'dns_rcode': dns_rcode,
                    'mdns_service': mdns_service,
                    'modbus_tid': modbus_fields['tid'],
                    'modbus_proto_id': modbus_fields['proto_id'],
                    'modbus_len': modbus_fields['length'],
                    'modbus_uid': modbus_fields['unit_id'],
                    'modbus_func': modbus_fields['func_code'],
                    'modbus_reference': modbus_fields['reference'],
                    'modbus_word_count': modbus_fields['word_cnt'],
                    'modbus_byte_count': modbus_fields['byte_cnt'],
                    'modbus_exception': modbus_fields['exception'],
                    'payload_len': get_field_values(tcp or udp or frame, ['len', 'pdu_size', 'cap_len']),
                }
                try:
                    packets_writer.writerow(row)
                except Exception:
                    pass

            # Handle Modbus conversations: match request->response using TID and 5-tuple
            if modbus_fields.get('tid') and ip and (tcp or udp):
                # Determine if this is a request or response by func_code and exception; fallback to TCP flags
                func_code = modbus_fields.get('func_code')
                unit_id = modbus_fields.get('unit_id')
                tid = modbus_fields.get('tid')
                reference = modbus_fields.get('reference')
                word_cnt = modbus_fields.get('word_cnt')
                byte_cnt = modbus_fields.get('byte_cnt')
                exception = modbus_fields.get('exception')
                values = modbus_fields.get('values')

                src_ip_k = get_field_values(ip, ['src', 'addr'])
                dst_ip_k = get_field_values(ip, ['dst', 'addr'])
                l4_src = src_port
                l4_dst = dst_port

                key_req: ConversationKey = (src_ip_k or '', l4_src or '', dst_ip_k or '', l4_dst or '', tid or '')
                key_resp: ConversationKey = (dst_ip_k or '', l4_dst or '', src_ip_k or '', l4_src or '', tid or '')

                # Heuristic: if pending has key_resp, this is likely the response to that request
                if key_resp in pending:
                    req = pending.pop(key_resp)
                    t0 = req.get('time_epoch')
                    t1 = float(time_epoch) if time_epoch else None
                    rtt_ms = None
                    if t0 is not None and t1 is not None:
                        try:
                            rtt_ms = max((t1 - float(t0)) * 1000.0, 0.0)
                        except Exception:
                            rtt_ms = None
                    if rtt_ms is not None:
                        stats.add_modbus_rtt(rtt_ms)
                    if exception:
                        stats.add_modbus_exception()

                    conv_row = {
                        'req_frame': req.get('frame_no'),
                        'resp_frame': frame_no,
                        'src_ip': req.get('src_ip'),
                        'src_port': req.get('src_port'),
                        'dst_ip': req.get('dst_ip'),
                        'dst_port': req.get('dst_port'),
                        'unit_id': unit_id or req.get('unit_id'),
                        'func_code': func_code or req.get('func_code'),
                        'transaction_id': tid,
                        'reference': req.get('reference') or reference,
                        'word_count': req.get('word_cnt') or word_cnt,
                        'byte_count': byte_cnt,
                        'values': values,
                        'exception': exception,
                        'rtt_ms': f"{rtt_ms:.3f}" if rtt_ms is not None else None,
                    }
                    try:
                        conversations_writer.writerow(conv_row)
                    except Exception:
                        pass
                else:
                    # Store as potential request
                    pending[key_req] = {
                        'frame_no': frame_no,
                        'time_epoch': time_epoch,
                        'src_ip': src_ip_k,
                        'src_port': l4_src,
                        'dst_ip': dst_ip_k,
                        'dst_port': l4_dst,
                        'unit_id': unit_id,
                        'func_code': func_code,
                        'reference': reference,
                        'word_cnt': word_cnt,
                    }

    finally:
        try:
            capture.close()
        except Exception:
            pass

        # Close writers
        if packets_writer:
            close_writer(packets_writer)
        close_writer(conversations_writer)

        # Analysis file
        analysis_path = os.path.join(out_dir, 'analysis.md')
        with open(analysis_path, 'w', encoding='utf-8') as f:
            f.write(stats.to_markdown())


def main() -> None:
    args = build_arg_parser().parse_args()
    if not os.path.isfile(args.pcap):
        print(f"PCAP not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)
    parse_pcap(
        pcap_path=args.pcap,
        out_dir=args.out,
        only_modbus=args.only_modbus,
        display_filter=args.display_filter,
        max_packets=args.max_packets,
    )
    print("Done. Files written to:", args.out)


if __name__ == '__main__':
    main()