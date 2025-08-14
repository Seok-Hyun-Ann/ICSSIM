#!/usr/bin/env python3

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def find_tshark(custom_path: Optional[str] = None) -> Optional[str]:
	"""Locate tshark executable across platforms.

	Returns absolute path or None if not found.
	"""
	candidates: List[str] = []
	if custom_path:
		candidates.append(custom_path)
	# PATH lookup first
	path_exec = shutil.which("tshark")
	if path_exec:
		candidates.append(path_exec)
	# Common Windows install paths
	win_candidates = [
		"C:/Program Files/Wireshark/tshark.exe",
		"C:/Program Files (x86)/Wireshark/tshark.exe",
	]
	candidates.extend(win_candidates)
	# Common Linux locations
	linux_candidates = [
		"/usr/bin/tshark",
		"/usr/local/bin/tshark",
	]
	candidates.extend(linux_candidates)

	for cand in candidates:
		if cand and os.path.exists(cand):
			return os.path.abspath(cand)
	return None


def run_tshark_json(tshark_path: str, pcap_path: str) -> List[Dict[str, Any]]:
	"""Run tshark and obtain full JSON dissection for all packets."""
	cmd = [tshark_path, "-r", pcap_path, "-T", "json"]
	try:
		result = subprocess.run(
			cmd, capture_output=True, text=True, check=True
		)
		text = result.stdout
		# Some tshark builds may emit multiple JSON arrays back-to-back.
		# Normalize by wrapping if needed.
		text = text.strip()
		if not text:
			raise RuntimeError("tshark produced no JSON output.")
		# tshark -T json returns either a JSON array or a sequence of arrays.
		if text.startswith("["):
			try:
				return json.loads(text)
			except json.JSONDecodeError:
				# Attempt to split concatenated arrays
				packets: List[Dict[str, Any]] = []
				for chunk in text.split("\n\n"):
					chunk = chunk.strip()
					if not chunk:
						continue
					if not chunk.startswith("["):
						continue
					try:
						arr = json.loads(chunk)
						packets.extend(arr)
					except json.JSONDecodeError:
						continue
				return packets
		else:
			# Unexpected format
			raise RuntimeError("Unexpected tshark JSON format")
	except subprocess.CalledProcessError as e:
		stderr = e.stderr or ""
		raise RuntimeError(f"tshark failed: {stderr}")


# -------- JSON helpers --------

def _first_value(value: Any) -> Optional[str]:
	"""Return a representative string value from tshark JSON field contents."""
	if value is None:
		return None
	if isinstance(value, list):
		if not value:
			return None
		# Prefer 'show' or 'showname' dicts if present
		v0 = value[0]
		if isinstance(v0, dict):
			for key in ("show", "showname", "val", "value"):
				if key in v0:
					return str(v0[key])
			return str(v0)
		return str(v0)
	if isinstance(value, dict):
		for key in ("show", "showname", "val", "value"):
			if key in value:
				return str(value[key])
		return json.dumps(value, ensure_ascii=False)
	return str(value)


def _find_field(layer: Dict[str, Any], *name_parts: str) -> Optional[str]:
	"""Fuzzy-find a field in a layer by matching all name_parts (case-insensitive).

	This accommodates tshark JSON key variations like 'frame.time_epoch' vs 'frame_time_epoch'.
	"""
	parts = [p.lower() for p in name_parts]
	for key, val in layer.items():
		key_l = key.lower()
		if all(p in key_l for p in parts):
			return _first_value(val)
	return None


def _get_layer(layers: Dict[str, Any], *candidates: str) -> Optional[Dict[str, Any]]:
	for cand in candidates:
		layer = layers.get(cand)
		if layer is not None:
			return layer
	return None


# -------- Extraction for per-packet CSV --------

def extract_packet_row(pkt: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
	"""Extract a rich set of fields for a single packet.

	Returns (row, indices) where 'indices' contains items used for session/analysis.
	"""
	layers: Dict[str, Any] = pkt.get("_source", {}).get("layers", {})
	row: Dict[str, Any] = {}
	indices: Dict[str, Any] = {}

	frame = _get_layer(layers, "frame") or {}
	eth = _get_layer(layers, "eth") or {}
	ip4 = _get_layer(layers, "ip") or {}
	ip6 = _get_layer(layers, "ipv6") or {}
	tcp = _get_layer(layers, "tcp") or {}
	udp = _get_layer(layers, "udp") or {}
	modbus = _get_layer(layers, "modbus") or {}
	dns = _get_layer(layers, "dns") or {}
	data_layer = _get_layer(layers, "data") or {}

	# Frame basics
	row["frame_number"] = _find_field(frame, "frame", "number") or _find_field(frame, "number")
	row["time_epoch"] = _find_field(frame, "time", "epoch")
	row["time"] = _find_field(frame, "time")
	row["frame_len"] = _find_field(frame, "len")
	row["protocols"] = _find_field(frame, "protocols")

	# L2/L3
	row["eth_src"] = _find_field(eth, "src")
	row["eth_dst"] = _find_field(eth, "dst")
	row["ip_src"] = _find_field(ip4, "src") or _find_field(ip6, "src")
	row["ip_dst"] = _find_field(ip4, "dst") or _find_field(ip6, "dst")
	row["ip_proto"] = _find_field(ip4, "proto") or _find_field(ip6, "nxt")

	# L4 TCP/UDP
	row["tcp_stream"] = _find_field(tcp, "stream")
	row["tcp_srcport"] = _find_field(tcp, "srcport")
	row["tcp_dstport"] = _find_field(tcp, "dstport")
	row["tcp_seq"] = _find_field(tcp, "seq")
	row["tcp_ack"] = _find_field(tcp, "ack")
	row["tcp_len"] = _find_field(tcp, "len")
	row["tcp_flags"] = _find_field(tcp, "flags")
	row["udp_srcport"] = _find_field(udp, "srcport")
	row["udp_dstport"] = _find_field(udp, "dstport")
	row["udp_len"] = _find_field(udp, "length") or _find_field(udp, "len")

	# Application - Modbus
	row["modbus_trans_id"] = _find_field(modbus, "trans", "id")
	row["modbus_unit_id"] = _find_field(modbus, "unit", "id")
	row["modbus_func_code"] = _find_field(modbus, "func", "code")
	row["modbus_reference_num"] = _find_field(modbus, "reference", "num")
	row["modbus_word_cnt"] = _find_field(modbus, "word", "cnt")
	row["modbus_byte_count"] = _find_field(modbus, "byte", "count")
	row["modbus_exception_code"] = _find_field(modbus, "exception", "code")

	# DNS/mDNS (mDNS is DNS over UDP 5353)
	row["dns_is_response"] = _find_field(dns, "flags", "response")
	row["dns_qry_name"] = _find_field(dns, "qry", "name")
	row["dns_qry_type"] = _find_field(dns, "qry", "type")
	row["dns_resp_name"] = _find_field(dns, "resp", "name") or _find_field(dns, "rrname")
	row["dns_resp_type"] = _find_field(dns, "resp", "type") or _find_field(dns, "rrtype")
	row["dns_ptr"] = _find_field(dns, "ptr")
	row["dns_srv_target"] = _find_field(dns, "srv", "target")

	# Payload (hex)
	row["payload_hex"] = _find_field(data_layer, "data", "data") or _find_field(modbus, "payload")

	# Indices for sessioning / analysis
	indices["is_modbus"] = (modbus != {})
	indices["tcp_stream"] = row.get("tcp_stream")
	indices["modbus_trans_id"] = row.get("modbus_trans_id")
	indices["time_epoch"] = float(row["time_epoch"]) if row.get("time_epoch") else None
	indices["src_ip"] = row.get("ip_src")
	indices["dst_ip"] = row.get("ip_dst")
	indices["src_port"] = row.get("tcp_srcport") or row.get("udp_srcport")
	indices["dst_port"] = row.get("tcp_dstport") or row.get("udp_dstport")
	indices["frame_number"] = int(row["frame_number"]) if row.get("frame_number") else None
	indices["is_tcp"] = bool(tcp)
	indices["is_udp"] = bool(udp)

	# Additional hints
	indices["is_modbus_request"] = None
	if indices["is_modbus"]:
		# Heuristic: request if destination is port 502; response if source is 502
		dst_is_502 = (row.get("tcp_dstport") == "502") or (row.get("udp_dstport") == "502")
		src_is_502 = (row.get("tcp_srcport") == "502") or (row.get("udp_srcport") == "502")
		if dst_is_502 and not src_is_502:
			indices["is_modbus_request"] = True
		elif src_is_502 and not dst_is_502:
			indices["is_modbus_request"] = False

	return row, indices


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
	"""Write rows with dynamic headers. Missing values are written blank."""
	# Compute union of keys
	all_keys: List[str] = []
	seen = set()
	for row in rows:
		for k in row.keys():
			if k not in seen:
				seen.add(k)
				all_keys.append(k)
	with open(path, "w", newline="", encoding="utf-8") as f:
		writer = csv.DictWriter(f, fieldnames=all_keys)
		writer.writeheader()
		for row in rows:
			writer.writerow({k: row.get(k, "") for k in all_keys})


# -------- Modbus correlation --------

def correlate_modbus(packets: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> List[Dict[str, Any]]:
	"""Build Modbus/TCP request-response pairs using trans_id and tcp stream."""
	out_rows: List[Dict[str, Any]] = []
	open_reqs: Dict[Tuple[str, str], Dict[str, Any]] = {}

	for row, idx in packets:
		if not idx.get("is_modbus"):
			continue
		trans_id = idx.get("modbus_trans_id") or row.get("modbus_trans_id")
		stream = idx.get("tcp_stream") or "-1"
		key_req = (str(stream), str(trans_id))

		if idx.get("is_modbus_request") is True:
			open_reqs[key_req] = {
				"row": row,
				"idx": idx,
			}
		elif idx.get("is_modbus_request") is False:
			# response: match to open request
			if key_req in open_reqs:
				req = open_reqs.pop(key_req)
				r = {}
				# Connection identifiers
				r["tcp_stream"] = stream
				r["trans_id"] = trans_id
				r["client_ip"] = req["idx"].get("src_ip")
				r["client_port"] = req["idx"].get("src_port")
				r["server_ip"] = idx.get("src_ip")
				r["server_port"] = idx.get("src_port")
				# Frames and times
				r["request_frame"] = req["idx"].get("frame_number")
				r["response_frame"] = idx.get("frame_number")
				r["request_time_epoch"] = req["idx"].get("time_epoch")
				r["response_time_epoch"] = idx.get("time_epoch")
				try:
					if req["idx"].get("time_epoch") is not None and idx.get("time_epoch") is not None:
						delta = float(idx["time_epoch"]) - float(req["idx"]["time_epoch"])
						r["rtt_ms"] = round(delta * 1000.0, 3)
					else:
						r["rtt_ms"] = ""
				except Exception:
					r["rtt_ms"] = ""
				# Modbus request fields
				r["unit_id"] = req["row"].get("modbus_unit_id") or row.get("modbus_unit_id")
				r["function_code"] = req["row"].get("modbus_func_code") or row.get("modbus_func_code")
				r["reference_number"] = req["row"].get("modbus_reference_num")
				r["word_count"] = req["row"].get("modbus_word_cnt")
				# Response fields
				r["byte_count"] = row.get("modbus_byte_count")
				r["exception_code"] = row.get("modbus_exception_code")
				# Collect all modbus layer values that look like register values
				register_values: List[str] = []
				# Find in response JSON layer directly for flexibility
				layers = pkt_layers_by_frame.get(idx.get("frame_number"), {})
				mod_layer = layers.get("modbus") or {}
				for k, v in mod_layer.items():
					kl = k.lower()
					if ("reg" in kl or "register" in kl) and ("val" in kl or "uint" in kl or "value" in kl):
						val = _first_value(v)
						if val is not None:
							register_values.append(val)
				r["register_values"] = ";".join(register_values) if register_values else ""
				out_rows.append(r)
			else:
				# unmatched response; emit a row with minimal info
				r = {
					"tcp_stream": stream,
					"trans_id": trans_id,
					"request_frame": "",
					"response_frame": idx.get("frame_number"),
					"rtt_ms": "",
					"function_code": row.get("modbus_func_code"),
					"unit_id": row.get("modbus_unit_id"),
					"exception_code": row.get("modbus_exception_code"),
				}
				out_rows.append(r)
	# Emit any dangling requests (no response)
	for key, req in open_reqs.items():
		r = {
			"tcp_stream": key[0],
			"trans_id": key[1],
			"request_frame": req["idx"].get("frame_number"),
			"response_frame": "",
			"rtt_ms": "",
			"function_code": req["row"].get("modbus_func_code"),
			"unit_id": req["row"].get("modbus_unit_id"),
			"reference_number": req["row"].get("modbus_reference_num"),
			"word_count": req["row"].get("modbus_word_cnt"),
		}
		out_rows.append(r)
	return out_rows


# Store of packet layers by frame_number for later modbus value mining
pkt_layers_by_frame: Dict[int, Dict[str, Dict[str, Any]]] = {}


def build_analysis_report(
	per_packet_rows: List[Dict[str, Any]],
	modbus_rows: List[Dict[str, Any]],
	outfile: str,
	pcap_path: str,
) -> None:
	"""Write a concise markdown report with network-wide insights."""
	# Protocol frequency
	proto_counter: Counter[str] = Counter()
	bytes_total = 0
	for r in per_packet_rows:
		protos = (r.get("protocols") or "").split(":")
		for p in protos:
			p = p.strip()
			if p:
				proto_counter[p] += 1
		try:
			bytes_total += int(r.get("frame_len") or 0)
		except Exception:
			pass

	# Top talkers by bytes
	bytes_by_pair: Counter[Tuple[str, str]] = Counter()
	for r in per_packet_rows:
		src = r.get("ip_src") or "?"
		dst = r.get("ip_dst") or "?"
		try:
			l = int(r.get("frame_len") or 0)
		except Exception:
			l = 0
		bytes_by_pair[(src, dst)] += l

	# Modbus stats
	func_counter: Counter[str] = Counter()
	exceptions = 0
	for m in modbus_rows:
		fc = str(m.get("function_code") or "?")
		func_counter[fc] += 1
		if m.get("exception_code"):
			exceptions += 1
	avg_rtt = None
	valid_rtts: List[float] = []
	for m in modbus_rows:
		try:
			rtt = float(m.get("rtt_ms"))
			valid_rtts.append(rtt)
		except Exception:
			pass
	if valid_rtts:
		avg_rtt = sum(valid_rtts) / len(valid_rtts)

	# mDNS services
	mdns_services: Counter[str] = Counter()
	for r in per_packet_rows:
		if r.get("udp_dstport") == "5353" or r.get("udp_srcport") == "5353":
			service = r.get("dns_qry_name") or r.get("dns_ptr") or r.get("dns_srv_target")
			if service:
				mdns_services[service] += 1

	# Write markdown
	with open(outfile, "w", encoding="utf-8") as f:
		f.write(f"# PCAP Analysis\n\n")
		f.write(f"- Source file: `{os.path.abspath(pcap_path)}`\n")
		f.write(f"- Packets: {len(per_packet_rows)}\n")
		f.write(f"- Total bytes: {bytes_total}\n\n")

		f.write("## Protocol breakdown (by packet count)\n\n")
		for proto, cnt in proto_counter.most_common():
			f.write(f"- {proto}: {cnt}\n")
		f.write("\n")

		f.write("## Top talkers (bytes)\n\n")
		for (src, dst), b in bytes_by_pair.most_common(15):
			f.write(f"- {src} -> {dst}: {b} bytes\n")
		f.write("\n")

		f.write("## Modbus/TCP summary\n\n")
		f.write(f"- Transactions (matched or open): {len(modbus_rows)}\n")
		if func_counter:
			f.write("- Function codes:\n")
			for fc, c in func_counter.most_common():
				f.write(f"  - FC {fc}: {c}\n")
		if avg_rtt is not None:
			f.write(f"- Average Modbus RTT: {avg_rtt:.3f} ms\n")
		f.write(f"- Modbus exceptions: {exceptions}\n\n")

		if mdns_services:
			f.write("## mDNS services observed\n\n")
			for svc, c in mdns_services.most_common(15):
				f.write(f"- {svc}: {c}\n")


# -------- CLI --------

def main() -> int:
	parser = argparse.ArgumentParser(
		description=(
			"Convert a .pcap/.pcapng into: per-packet CSV, Modbus/TCP correlation CSV, and a markdown analysis report. "
			"Requires Wireshark's tshark to be installed."
		)
	)
	parser.add_argument("--pcap", required=True, help="Path to input pcap/pcapng file")
	parser.add_argument("--out", required=True, help="Output directory for CSV and report")
	parser.add_argument("--tshark", default=None, help="Optional path to tshark executable")
	args = parser.parse_args()

	pcap_path = os.path.abspath(args.pcap)
	out_dir = os.path.abspath(args.out)
	os.makedirs(out_dir, exist_ok=True)

	tshark_path = find_tshark(args.tshark)
	if not tshark_path:
		print(
			"ERROR: tshark not found. Please install Wireshark (which includes tshark) and ensure 'tshark' is on PATH, "
			"or provide --tshark with the full path to tshark.",
			file=sys.stderr,
		)
		return 2

	print(f"Using tshark: {tshark_path}")
	print("Reading pcap and decoding via tshark... (this may take a while for large files)")
	packets_json = run_tshark_json(tshark_path, pcap_path)

	per_packet_rows: List[Dict[str, Any]] = []
	indexed_packets: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []

	# Build global index of layers by frame number for later mining
	global pkt_layers_by_frame
	pkt_layers_by_frame = {}

	for pkt in packets_json:
		layers = pkt.get("_source", {}).get("layers", {})
		# Store raw layers index for modbus register mining
		# We only keep a shallow copy of layer dicts
		frame_layer = layers.get("frame", {})
		frame_no_s = _find_field(frame_layer, "number") or _find_field(frame_layer, "frame", "number") or "0"
		try:
			frame_no = int(frame_no_s)
		except Exception:
			frame_no = 0
		pkt_layers_by_frame[frame_no] = {k: v for k, v in layers.items()}

		row, idx = extract_packet_row(pkt)
		per_packet_rows.append(row)
		indexed_packets.append((row, idx))

	# Outputs
	per_packet_csv = os.path.join(out_dir, "per_packet.csv")
	modbus_csv = os.path.join(out_dir, "modbus_correlated.csv")
	report_md = os.path.join(out_dir, "analysis.md")

	print(f"Writing per-packet CSV: {per_packet_csv}")
	write_csv(per_packet_csv, per_packet_rows)

	print("Correlating Modbus request/response pairs...")
	modbus_rows = correlate_modbus(indexed_packets)
	print(f"Writing Modbus CSV: {modbus_csv}")
	write_csv(modbus_csv, modbus_rows)

	print(f"Writing analysis report: {report_md}")
	build_analysis_report(per_packet_rows, modbus_rows, report_md, pcap_path)

	print("Done.")
	return 0


if __name__ == "__main__":
	sys.exit(main())