from scapy.all import IP, TCP, UDP, ICMP, send
import time

TARGET = '127.0.0.1'


def simulate_normal_traffic():
    packets = []
    for port in [80, 443, 22, 8080]:
        packets.append(IP(dst=TARGET) / TCP(dport=port, flags='S'))
    for port in [53, 67, 123]:
        packets.append(IP(dst=TARGET) / UDP(dport=port))
    packets.append(IP(dst=TARGET) / ICMP())
    send(packets, verbose=False)
    print('Normal traffic sent.')


def simulate_port_scan():
    packets = [IP(dst=TARGET) / TCP(dport=port, flags='S') for port in range(20, 41)]
    send(packets, verbose=False)
    print('Port scan traffic sent.')


def simulate_http_anomaly():
    encoded_payload = 'A' * 1200
    packet = IP(dst=TARGET) / TCP(dport=80, flags='PA') / (f'POST / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(encoded_payload)}\r\n\r\n{encoded_payload}')
    send(packet, verbose=False)
    print('Suspicious HTTP payload sent.')


def simulate_traffic_burst():
    """Simulate DoS-like traffic burst: many packets to port 80 in short time"""
    packets = []
    for i in range(100):
        packets.append(IP(dst=TARGET) / TCP(dport=80, flags='S'))
    send(packets, verbose=False)
    print('Traffic burst (DoS-like) sent.')


if __name__ == '__main__':
    simulate_normal_traffic()
    simulate_port_scan()
    simulate_http_anomaly()
    simulate_traffic_burst()
    print('Traffic simulation complete.')
