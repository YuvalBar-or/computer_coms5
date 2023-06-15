from scapy.all import sniff, TCP, UDP, ICMP, IP
import datetime

DEFAULT_SERVER_PORT = 9999  # The default port for the server
DEFAULT_PROXY_PORT = 9998  # The default port for the proxy
DEFAULT_HOST = "127.0.0.1"
ID_1 = 332307073
ID_2 = 214329633

class PacketSniffer:
    def __init__(self):
        self.file_name = "passwordSniffer.txt"
        self.server_port = DEFAULT_SERVER_PORT
        self.proxy_port = DEFAULT_PROXY_PORT
        self.protocol = 0
        self.host = DEFAULT_HOST
    #setters for othe parts of assigment
    def setSP(self, numS):
        self.server_port = numS
    def setPP(self, numP):
        self.proxy_port = numP
    def setFN(self, str):
        self.file_name = str
        
    def sniff_packets(self):
        #scapy sniff function
        sniff(filter="tcp", prn=self.process_packet)

    def process_packet(self, packet):
        parsed_data = {}

        if TCP in packet:
            self.protocol = 1
            parsed_data = self.parse_tcp_packet(packet)
            
        elif UDP in packet:
            self.protocol = 1
            parsed_data = self.parse_udp_packet(packet)
        
        elif ICMP in packet:
            self.protocol = 1 # and (packet[ICMP].sport in [self.server_port, self.proxy_port] or packet[ICMP].dport in [self.server_port, self.proxy_port]):
            parsed_data = self.parse_icmp_packet(packet)
        
        elif IGMP in packet:
            self.protocol = 1
            parsed_data = self.parse_igmp_packet(packet)
        else:
            self.protocol = 1
            parsed_data = self.parse_raw_packet(packet)

        if parsed_data and self.protocol == 1:
            self.save_packet_data(parsed_data)

    def parse_tcp_packet(self, packet):
        parsed_data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "source_port": packet[TCP].sport,
            "dest_port": packet[TCP].dport,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_length": len(packet),
            "cache_flag": packet[TCP].flags.C,
            "steps_flag": packet[TCP].flags.S,
            "type_flag": packet[TCP].flags.F,
            "status_code": packet[TCP].flags.A,
            "cache_control": packet[TCP].flags.P,
            "data": packet[TCP].payload
        }
        return parsed_data

    def parse_udp_packet(self, packet):
        parsed_data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "source_port": packet[UDP].sport,
            "dest_port": packet[UDP].dport,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_length": len(packet),
            "cache_flag": "",
            "steps_flag": "",
            "type_flag": "",
            "status_code": "",
            "cache_control": "",
            "data": packet[UDP].payload.hex()
        }
        return parsed_data

    def parse_icmp_packet(self, packet):
        parsed_data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "source_port": "",
            "dest_port": "",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_length": len(packet),
            "cache_flag": "",
            "steps_flag": "",
            "type_flag": "",
            "status_code": "",
            "cache_control": "",
            "data": packet[ICMP].payload.hex()
        }
        return parsed_data

    def parse_igmp_packet(self, packet):
        parsed_data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "source_port": "",
            "dest_port": "",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_length": len(packet),
            "cache_flag": "",
            "steps_flag": "",
            "type_flag": "",
            "status_code": "",
            "cache_control": "",
            "data": packet[IGMP].payload.hex()
        }
        return parsed_data

    def parse_raw_packet(self, packet):
        parsed_data = {
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "source_port": "",
            "dest_port": "",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_length": len(packet),
            "cache_flag": "",
            "steps_flag": "",
            "type_flag": "",
            "status_code": "",
            "cache_control": "",
            "data": packet.payload.hex()
        }
        return parsed_data

    def save_packet_data(self, parsed_data):
        with open(self.file_name, "a") as file:
            file.write(str(parsed_data) + "\n")

if __name__ == "__main__":
    print("Started")

    sniffer = PacketSniffer()
    sniffer.sniff_packets()
    print("Finished")
