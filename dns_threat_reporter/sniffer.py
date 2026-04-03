"""
DNS Sniffer - Captures DNS packets on UDP port 53 using Scapy.

This module is responsible for the first stage of the pipeline:
capturing raw packets off the network interface and forwarding them
to the next stage (parser) via a callback function.

Only DNS query packets (qr == 0) are relevant to the pipeline.
DNS responses (qr == 1) are ignored because we care about what
domains devices are *asking* for, not what answers they receive.

Requires root/administrator privileges to capture raw packets.
"""

from scapy.all import sniff, DNS, DNSQR, IP, UDP
from typing import Callable, Optional


class DNSSniffer:
    """
    Captures live DNS traffic on UDP port 53.

    Uses Scapy's sniff() with a BPF (Berkeley Packet Filter) to efficiently
    capture only UDP port 53 traffic at the kernel level, discarding all
    other traffic before it reaches Python.

    Usage:
        sniffer = DNSSniffer(interface="en0")
        sniffer.start(callback_fn)  # blocks until stop() is called
    """

    # BPF filter string passed directly to libpcap — filters at kernel level
    # so unrelated packets never even reach Python.
    BPF_FILTER = "udp port 53"

    def __init__(self, interface: Optional[str] = None):
        """
        Args:
            interface: Network interface to sniff on (e.g., 'en0', 'eth0').
                       Pass None to sniff on all available interfaces.
        """
        self.interface = interface
        self._running = False

    def start(self, packet_callback: Callable):
        """
        Start sniffing DNS packets. Blocks until stop() is called.

        Each captured packet is passed to packet_callback on the same thread.
        The callback should be fast; heavy processing should be deferred.

        Args:
            packet_callback: Called once per captured packet with the raw
                             Scapy packet as its only argument.
        """
        self._running = True
        iface_label = self.interface if self.interface else "all interfaces"
        print(f"[Sniffer] Listening for DNS traffic on {iface_label}...")

        sniff(
            filter=self.BPF_FILTER,                     # BPF filter — applied at kernel level for performance
            iface=self.interface,                       # None = all interfaces
            prn=packet_callback,                        # called once per matching packet
            store=False,                                # don't accumulate packets in RAM
            stop_filter=lambda _: not self._running,    # return True to stop the loop
        )

    def stop(self):
        """
        Signal the sniffer to stop after the next packet arrives.

        Because Scapy's sniff() is blocking, the stop is checked via
        stop_filter on every packet. On quiet networks there may be a
        short delay before the loop exits.
        """
        self._running = False
        print("[Sniffer] Stopped.")

    @staticmethod
    def is_dns_query(packet) -> bool:
        """
        Return True if the packet is a DNS query (not a response).

        DNS packets have a QR flag: 0 = query, 1 = response.
        We only care about queries — what domains are being looked up.
        """
        return (
            packet.haslayer(DNS)
            and packet.haslayer(DNSQR)
            and packet[DNS].qr == 0  # 0 = query, 1 = response
        )

    @staticmethod
    def get_source_ip(packet) -> str:
        """Extract the source IP address from an IP-layer packet."""
        if packet.haslayer(IP):
            return packet[IP].src
        return "unknown"
