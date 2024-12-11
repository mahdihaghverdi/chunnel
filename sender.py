import logging
import os
import string
import time
import threading

from scapy.all import IP, send, sniff

logging.basicConfig(
    level=logging.INFO,
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
)

logger = logging.getLogger(__file__)

b_ip = os.environ["B_IP"]
a_ip = os.environ["A_IP"]


def send_packet(payload):
    logger.info(f'<Packet: {payload!r}> is sent.')
    packet = IP(src=a_ip, dst=b_ip) / IP(src=b_ip, dst=a_ip) / payload
    send(packet)


def send_p():
    with open('Dockerfile') as f:
        for line in f:
            send_packet(line)
            time.sleep(1)

    send_packet('CH: EXIT')


def packet_callback(packet):
    inner = packet[IP].payload
    logger.info(f"SENDER. <Packet: {inner.load.decode()!r}>")


def stop_filter(packet):
    if IP in packet and packet[IP].src == b_ip:
        payload = packet[IP].payload.load.decode()
        if payload.startswith("CH: "):
            if payload[4:] == 'EXIT':
                return True
    return False


def packet_filter(packet):
    return (
        IP in packet
        and packet[IP].src == b_ip
        and packet[IP].dst == a_ip
    )

threading.Thread(
    target=lambda: sniff(
        iface='',
        lfilter=packet_filter,
        stop_filter=stop_filter,
        prn=packet_callback
    )
).start()
threading.Thread(target=send_p).start()
