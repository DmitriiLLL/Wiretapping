import argparse
import time
import threading
import os
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from email.mime.text import MIMEText

class NetworkMonitor:
    def __init__(self, interface: str, bpf_filter: str = None, summary_interval: int = 10, log_file: str = None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.summary_interval = summary_interval
        self.log_file = log_file
        self.packet_count = 0
        self.ip_counter = Counter()
        self.protocol_counter = Counter()
        self.lock = threading.Lock()
        self.running = False

    def _log(self, message: str):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{timestamp}] {message}"
        print(line)
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(line + '\n')

    def packet_handler(self, packet):
        if IP not in packet:
            return
        src = packet[IP].src
        proto = 'OTHER'
        if TCP in packet:
            proto = 'TCP'
        elif UDP in packet:
            proto = 'UDP'
        elif ICMP in packet:
            proto = 'ICMP'
        with self.lock:
            self.packet_count += 1
            self.ip_counter[src] += 1
            self.protocol_counter[proto] += 1
        self._log(f"Packet #{self.packet_count}: {src} -> {packet[IP].dst} ({proto})")

    def summary_loop(self):
        while self.running:
            time.sleep(self.summary_interval)
            with self.lock:
                total = self.packet_count
                top_ips = self.ip_counter.most_common(5)
                proto_stats = dict(self.protocol_counter)
            self._log("--- Summary ---")
            self._log(f"Total packets: {total}")
            self._log(f"Top 5 source IPs: {top_ips}")
            self._log(f"Protocol counts: {proto_stats}")
            self._log("----------------")

    def start(self):
        self.running = True
        if self.summary_interval > 0:
            t = threading.Thread(target=self.summary_loop, daemon=True)
            t.start()
        sniff(iface=self.interface, prn=self.packet_handler, filter=self.bpf_filter, store=False)

    def stop(self):
        self.running = False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Network Activity Monitor')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-f', '--filter', help='BPF filter string (e.g. "tcp or icmp")')
    parser.add_argument('-s', '--summary-interval', type=int, default=10, help='Seconds between summary prints')
    parser.add_argument('-l', '--log-file', help='Optional log file path')
    parser.add_argument('-L', '--list-interfaces', action='store_true', help='List available network interfaces and exit')
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:", get_if_list())
        exit(0)

    if not args.interface:
        print("Ошибка: не указан интерфейс для прослушивания трафика.")
        print("Чтобы увидеть список доступных интерфейсов, выполните:")
        print("    python network_monitor.py -L")
        print("Для запуска мониторинга используйте:")
        print("    python network_monitor.py -i <interface> [-f <filter>] [-s <interval>] [-l <log_file>")
        exit(1)

    monitor = NetworkMonitor(
        interface=args.interface,
        bpf_filter=args.filter,
        summary_interval=args.summary_interval,
        log_file=args.log_file
    )
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
        print("\nMonitoring stopped by user.")