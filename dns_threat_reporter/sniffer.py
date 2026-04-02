"""
DNS Sniffer - Captures DNS packets on UDP port 53 using Scapy.
"""

from scapy.all import sniff, DNS, DNSQR, IP, UDP
from typing import Callable, Optional


class DNSSniffer:
    """Captures live DNS traffic on UDP port 53."""

    BPF_FILTER = "udp port 53"

    def __init__(self, interface: Optional[str] = None):
        """
        Args:
            interface: Network interface to sniff on (e.g., 'en0', 'eth0').
                       None = sniff on all interfaces.
        """
        self.interface = interface
        self._running = False

    def start(self, packet_callback: Callable):
        """
        Start sniffing DNS packets. Blocks until stopped.

        Args:
            packet_callback: Function called for each captured DNS packet.
        """
        self._running = True
        iface_label = self.interface if self.interface else "all interfaces"
        print(f"[Sniffer] Listening for DNS traffic on {iface_label}...")


        sniff(
            filter=self.BPF_FILTER,                     # BPF filter for performance
            iface=self.interface,                       # interface to listen on
            prn=packet_callback,                        # callback for each packet
            store=False,                                # don't store packets in memory
            stop_filter=lambda _: not self._running,    # stop when _running is False 
        )

    def stop(self):
        """Stop the sniffer."""
        self._running = False
        print("[Sniffer] Stopped.")

    @staticmethod
    def is_dns_query(packet) -> bool:
        """Check if a packet is a DNS query (not a response)."""
        return (
            packet.haslayer(DNS)
            and packet.haslayer(DNSQR)
            and packet[DNS].qr == 0  # 0 = query, 1 = response
        )

    @staticmethod
    def get_source_ip(packet) -> str:
        """Extract source IP from packet."""
        if packet.haslayer(IP):
            return packet[IP].src
        return "unknown"
