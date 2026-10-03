"""Packet capture module for TriStation protocol monitoring."""

from scapy.all import sniff, UDP
from datetime import datetime


class PacketCapture:
    def __init__(self, interface, port=1502, callback=None):
        self.interface = interface
        self.port = port
        self.callback = callback
        self.packet_count = 0

    def _packet_handler(self, pkt):
        if UDP in pkt and (pkt[UDP].dport == self.port or pkt[UDP].sport == self.port):
            self.packet_count += 1
            if self.callback:
                self.callback(pkt, self.packet_count)

    def start(self):
        bpf = f"udp port {self.port}"
        sniff(
            iface=self.interface,
            filter=bpf,
            prn=self._packet_handler,
            store=0
        )
