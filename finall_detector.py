#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_addr, conf
from collections import deque, Counter
from datetime import datetime, timezone
import argparse
import csv
import os
import time
import ipaddress

# ---------------------------
# Utility: interface handling
# ---------------------------

# Return a list of non-loopback network interfaces that appear up
def list_up_ifaces():
    try:
        ifaces = []
        for _, v in conf.ifaces.items():
            # Try to get a readable interface name; fall back to str(v)
            name = getattr(v, 'name', None) or str(v)
            if not name:
                continue
            lname = name.lower()
            # Skip loopback interfaces (lo, lo0, etc.)
            if lname == "lo" or lname.startswith("lo"):
                continue
            ifaces.append(name)
        # Deduplicate while preserving order
        seen, uniq = set(), []
        for x in ifaces:
            if x not in seen:
                uniq.append(x); seen.add(x)
        return uniq or []
    except Exception:
        # On any error, return an empty list
        return []

# Resolve the user-provided interface argument into an iface spec
# Accepts: 'any', 'auto', comma-separated list, or a single interface name
def resolve_interfaces(arg_iface):
    if not arg_iface:
        arg_iface = "auto"
    val = arg_iface.strip().lower()
    if val == "any":
        # Linux special: capture on all interfaces
        return "any"
    if val == "auto":
        # Auto: return all up interfaces
        ifaces = list_up_ifaces()
        return ifaces if ifaces else None
    if "," in arg_iface:
        # Comma-separated list -> list of names
        return [x.strip() for x in arg_iface.split(",") if x.strip()]
    # Single interface name -> return as-is
    return arg_iface

# Check whether an IP string is a broadcast, multicast, loopback, unspecified or reserved
def is_broadcast_or_multicast(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_reserved or ip == ipaddress.ip_address("255.255.255.255")
    except Exception:
        return False

# ---------------------------
# DDoS Detector
# ---------------------------

class DDoSDetector:
    """
    Logs CSV with:
      ts_start, ts_end, src_ip, dst_ip, attack_type, pkt_count, byte_count, rate_pps, rate_bps
    Uses top (src,dst) pair instead of independent top src/top dst to avoid showing the same IP twice.
    """
    def __init__(self, interfaces, threshold=50, log_file="ddos_attacks.csv", window_seconds=1.0,
                 exclude_self=True, ignore_broadcast=True):
        # Save config
        self.interfaces = interfaces
        self.threshold = int(threshold)
        self.log_file = log_file
        self.window_seconds = float(window_seconds)
        self.exclude_self = bool(exclude_self)
        self.ignore_broadcast = bool(ignore_broadcast)

        # Circular window of recent packets: store tuples (t, size, src, dst, syn, udp, icmp)
        self.win = deque()
        self.total_pkts = 0
        self.total_bytes = 0

        # Ensure CSV has header if file doesn't exist
        self._init_csv()

        # Collect our detector IPs to optionally exclude them from top-pair detection
        self.self_ips = set()
        self.detector_ips = {}
        try:
            if isinstance(interfaces, list):
                for itf in interfaces:
                    try:
                        ip = get_if_addr(itf)
                    except Exception:
                        ip = None
                    self.detector_ips[itf] = ip or "unknown"
                    if ip:
                        self.self_ips.add(ip)
            elif isinstance(interfaces, str):
                try:
                    ip = get_if_addr(interfaces)
                except Exception:
                    ip = None
                self.detector_ips[interfaces] = ip or "unknown"
                if ip:
                    self.self_ips.add(ip)
        except Exception:
            # If anything fails while discovering local IPs, continue without them
            pass

        # Print startup banner with configuration info
        self._banner()

    # ---------------------------
    # CSV
    # ---------------------------

    # Create CSV file with header if needed
    def _init_csv(self):
        need_header = not os.path.exists(self.log_file)
        with open(self.log_file, "a", newline="") as f:
            w = csv.writer(f)
            if need_header:
                w.writerow([
                    "ts_start", "ts_end", "src_ip", "dst_ip",
                    "attack_type", "pkt_count", "byte_count",
                    "rate_pps", "rate_bps"
                ])

    # Helper to append an alert row to CSV
    def _write_csv_row(self, ts_start, ts_end, src_ip, dst_ip, attack_type,
                       pkt_count, byte_count, rate_pps, rate_bps):
        with open(self.log_file, "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                ts_start, ts_end, src_ip, dst_ip, attack_type,
                int(pkt_count), int(byte_count), f"{rate_pps:.3f}", f"{rate_bps:.3f}"
            ])

    # ---------------------------
    # Output formatting
    # ---------------------------

    # Print a formatted banner with config details
    def _banner(self):
        print("┌" + "─" * 70 + "┐")
        print("│{:^70}│".format("DDoS Detector – Scapy"))
        print("├" + "─" * 70 + "┤")
        if isinstance(self.interfaces, list):
            if_desc = ", ".join(self.interfaces) if self.interfaces else "(none)"
        else:
            if_desc = self.interfaces
        print("│ Interfaces : {:57}│".format(if_desc))
        for itf, ip in (self.detector_ips or {}).items():
            line = f"{itf} → {ip}"
            print("│ Detector IP: {:57}│".format(line[:57]))
        print("│ Threshold  : {:57}│".format(f"{self.threshold} packets/sec"))
        print("│ Options    : {:57}│".format(f"exclude_self={self.exclude_self}, ignore_broadcast={self.ignore_broadcast}"))
        print("│ Log file   : {:57}│".format(self.log_file))
        print("└" + "─" * 70 + "┘\n")

    # Nicely print an alert to stdout including type and top pair
    def _pretty_alert(self, attack_type, pkt_count, byte_count, rate_pps, rate_bps,
                      pair, ts_start, ts_end, syn, udp, icmp):
        src, dst = pair if pair else ("-", "-")
        print("\n" + "═" * 72)
        print(f"🚨  {attack_type.upper()}  |  {pkt_count} pkts  |  {byte_count} bytes")
        print(f"    Window: {ts_start} → {ts_end}  |  Rate: {rate_pps:.1f} pps, {rate_bps:.1f} bps")
        print(f"    Top Pair: {src}  →  {dst}")
        print(f"    Types  : SYN={syn}  UDP={udp}  ICMP={icmp}")
        print("═" * 72)

    # ---------------------------
    # Heuristics
    # ---------------------------

    # Decide an attack label based on protocol counts and other stats
    @staticmethod
    def _detect_type(counts_syn, counts_udp, counts_icmp, avg_len, uniq_src, uniq_dst):
        total = counts_syn + counts_udp + counts_icmp
        if total <= 0:
            return "High Traffic"
        syn_ratio = counts_syn / total
        udp_ratio = counts_udp / total
        icmp_ratio = counts_icmp / total
        if syn_ratio > 0.7:
            return "SYN Flood"
        if udp_ratio > 0.6:
            return "UDP Flood"
        if icmp_ratio > 0.5:
            return "POD Attack" if avg_len > 1000 else "ICMP Flood"
        if uniq_src > 100:
            return "Distributed DDoS"
        return "High Traffic"

    # ---------------------------
    # Packet processing
    # ---------------------------

    # Remove old packets outside the sliding window (based on timestamp)
    def _trim_window(self, now):
        cutoff = now - self.window_seconds
        while self.win and self.win[0][0] < cutoff:
            self.win.popleft()

    # Called for each captured packet
    def _on_packet(self, pkt):
        now = time.time()
        # Skip non-IP packets quickly
        if IP not in pkt:
            return

        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        size = int(len(pkt))

        # Protocol/type flags: check for SYN bit, UDP presence, or ICMP
        syn = 1 if (TCP in pkt and pkt[TCP].flags & 0x02) else 0
        udp = 1 if UDP in pkt else 0
        icmp = 1 if ICMP in pkt else 0

        # Push a tuple representing this packet into the sliding window
        self.win.append((now, size, src, dst, syn, udp, icmp))
        self.total_pkts += 1
        self.total_bytes += size

        # Trim old packets and compute stats for the current window
        self._trim_window(now)
        pkt_count = len(self.win)
        # If count does not exceed threshold, do nothing further
        if pkt_count <= self.threshold:
            return

        ts_start_epoch = self.win[0][0]
        ts_end_epoch   = self.win[-1][0]
        dur = max(ts_end_epoch - ts_start_epoch, 1e-3)

        byte_count = sum(x[1] for x in self.win)
        rate_pps   = pkt_count / dur
        rate_bps   = (byte_count * 8) / dur

        syn_count  = sum(x[4] for x in self.win)
        udp_count  = sum(x[5] for x in self.win)
        icmp_count = sum(x[6] for x in self.win)

        avg_len    = byte_count / pkt_count

        # Build top (src,dst) pairs with filters to avoid “same IP” artifact
        pairs = []
        for (_, _, s, d, *_rest) in self.win:
            # Optionally skip broadcast/multicast addresses
            if self.ignore_broadcast and (is_broadcast_or_multicast(s) or is_broadcast_or_multicast(d)):
                continue
            # Optionally skip packets involving the detector's own IPs
            if self.exclude_self and (s in self.self_ips or d in self.self_ips):
                continue
            # Skip trivial packets where src==dst
            if s == d:
                continue
            pairs.append((s, d))

        # Count frequency of each (src,dst) pair and pick the top one
        pair_counts = Counter(pairs)
        top_pair = pair_counts.most_common(1)[0][0] if pair_counts else None

        # Fallback if filtering removed everything: compute top pair without filters except src!=dst
        if not top_pair:
            # at least avoid src==dst
            pairs2 = [(x[2], x[3]) for x in self.win if x[2] != x[3]]
            pair_counts2 = Counter(pairs2)
            top_pair = pair_counts2.most_common(1)[0][0] if pair_counts2 else None

        # Use heuristic to decide attack_type label
        attack_type = self._detect_type(
            syn_count, udp_count, icmp_count, avg_len,
            uniq_src=len(set(x[2] for x in self.win)),
            uniq_dst=len(set(x[3] for x in self.win))
        )

        # Convert epoch timestamps to UTC-formatted strings
        ts_start = datetime.fromtimestamp(ts_start_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        ts_end   = datetime.fromtimestamp(ts_end_epoch,   tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        src_ip, dst_ip = (top_pair if top_pair else ("", ""))

        # Write one row per alert window (top pair) to CSV
        self._write_csv_row(
            ts_start=ts_start,
            ts_end=ts_end,
            src_ip=src_ip,
            dst_ip=dst_ip,
            attack_type=attack_type,
            pkt_count=pkt_count,
            byte_count=byte_count,
            rate_pps=rate_pps,
            rate_bps=rate_bps
        )

        # Also print a pretty alert to the console
        self._pretty_alert(
            attack_type=attack_type,
            pkt_count=pkt_count,
            byte_count=byte_count,
            rate_pps=rate_pps,
            rate_bps=rate_bps,
            pair=(src_ip, dst_ip),
            ts_start=ts_start,
            ts_end=ts_end,
            syn=syn_count,
            udp=udp_count,
            icmp=icmp_count
        )

        # keep a small tail to reduce spam but allow rapid re-triggers
        keep_from = time.time() - min(0.1, self.window_seconds * 0.2)
        while self.win and self.win[0][0] < keep_from:
            self.win.popleft()

    # ---------------------------
    # Run
    # ---------------------------

    # Start the packet capture loop
    def start(self):
        print("Starting capture… (Ctrl+C to stop)\n")
        try:
            sniff(
                iface=self.interfaces,     # string, list, or "any"
                prn=self._on_packet,
                store=False,
                filter="ip"                # ignore non-IP noise
            )
        except KeyboardInterrupt:
            # Graceful shutdown on Ctrl+C
            pass
        except Exception as e:
            print(f"❌ Sniffer error: {e}")
        finally:
            # When stopped, print totals and CSV location
            print("\n" + "-" * 72)
            print(f"Stopped. Total packets: {self.total_pkts}  |  Total bytes: {self.total_bytes}")
            print(f"CSV log: {os.path.abspath(self.log_file)}")
            print("-" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="DDoS detector with multi-interface support and robust src/dst pair selection"
    )
    parser.add_argument("-i","--interface", default="auto",
                        help="Interface name, comma-separated list, 'auto' (all up), or 'any' (Linux). Default: auto")
    parser.add_argument("-t","--threshold", type=int, default=50,
                        help="Trigger threshold (packets/sec window). Default: 50")
    parser.add_argument("-l","--logfile", default="ddos_attacks.csv",
                        help="CSV file path for logs. Default: ddos_attacks.csv")
    parser.add_argument("-w","--window", type=float, default=1.0,
                        help="Window length in seconds. Default: 1.0")
    parser.add_argument("--exclude-self", action="store_true", default=True,
                        help="Exclude detector’s own IPs from top-pair selection (default on).")
    parser.add_argument("--include-self", dest="exclude_self", action="store_false",
                        help="Include detector’s own IPs in top-pair selection.")
    parser.add_argument("--ignore-broadcast", action="store_true", default=True,
                        help="Ignore broadcast/multicast when picking top pair (default on).")
    parser.add_argument("--no-ignore-broadcast", dest="ignore_broadcast", action="store_false",
                        help="Do not ignore broadcast/multicast.")
    args = parser.parse_args()

    interfaces = resolve_interfaces(args.interface)
    if not interfaces:
        print("❌ No usable interfaces found. Try -i <iface> or -i any")
        return

    det = DDoSDetector(
        interfaces=interfaces,
        threshold=args.threshold,
        log_file=args.logfile,
        window_seconds=args.window,
        exclude_self=args.exclude_self,
        ignore_broadcast=args.ignore_broadcast
        )
    det.start()

if __name__ == "__main__":
    main()

