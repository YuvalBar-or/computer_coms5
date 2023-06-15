from scapy.all import IP, ICMP, sr1

class Traceroute:
    def __init__(self, destination):
        self.destination = destination

    def send_packet(self, ttl):
        packet = IP(dst=self.destination, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=False, timeout=5)
        if reply is not None:
            return reply.src
        #else:
            #return ""

    def run(self):
        ttl = 1
        while True:
            router_ip = self.send_packet(ttl)
            if router_ip == "*":
                print(f"{ttl}: *")
            else:
                print(f"{ttl}: {router_ip}")

            if router_ip == self.destination:
                break

            ttl += 1

if __name__ == "__main__":
    destination = '1.1.1.1'
    traceroute = Traceroute(destination)
    traceroute.run()






