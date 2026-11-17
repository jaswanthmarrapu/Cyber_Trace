from pathlib import Path
from typing import List, Dict

def parse_pcap_summary(pcap_path: str | Path, max_packets: int = 250) -> Dict[str, any]:
    """Inspect packet capture files using Scapy with safe exception handling."""
    path = Path(pcap_path)
    flows = []
    protocols_count = {}
    ip_endpoints = set()

    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS
        packets = rdpcap(str(path), count=max_packets)

        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = "Other"
                sport = None
                dport = None

                ip_endpoints.add(src)
                ip_endpoints.add(dst)

                if TCP in pkt:
                    proto = "TCP"
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                elif UDP in pkt:
                    proto = "UDP"
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    if DNS in pkt:
                        proto = "DNS"

                protocols_count[proto] = protocols_count.get(proto, 0) + 1

                flows.append({
                    "timestamp": float(pkt.time),
                    "source_ip": src,
                    "destination_ip": dst,
                    "source_port": sport,
                    "destination_port": dport,
                    "protocol": proto,
                    "length": len(pkt)
                })

        return {
            "total_packets_parsed": len(flows),
            "unique_ips": list(ip_endpoints),
            "protocols_distribution": protocols_count,
            "flows": flows[:50]
        }
    except Exception as e:
        return {
            "total_packets_parsed": 0,
            "error": f"PCAP parsing notice: {str(e)}",
            "unique_ips": [],
            "protocols_distribution": {},
            "flows": []
        }

