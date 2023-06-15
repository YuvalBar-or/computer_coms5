
from scapy.all import IP,  UDP, ICMP, send

class Spoofer:
    def __init__(self, protocol, fake_senders_ip, fake_senders_port, dest_ip, dest_port):
        self.protocol = protocol
        self.fake_ip = fake_senders_ip
        self.fake_port = fake_senders_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    def run(self):
        if self.protocol == 'ICMP':
            self.icmp_spoofer(self.fake_ip,self.dest_ip)
        elif self.protocol == 'UDP':
            self.udp_spoofer(self.fake_ip, self.fake_port, self.dest_ip, self.dest_port)
        
    def icmp_spoofer(self,source_ip, dest_ip):
        packet = IP(src=source_ip, dst=dest_ip) / ICMP()
        send(packet)

    def udp_spoofer(self,source_ip, source_port, dest_ip, dest_port):
        packet = IP(src=source_ip, dst=dest_ip) / UDP(sport=source_port, dport=dest_port)
        send(packet)

if "__main__" == __name__:
    print("started")
    spoof = Spoofer("ICMP", "192.168.127.128", 123467, "8.8.8.8", 80)
    spoof.run()

