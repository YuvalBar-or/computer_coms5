from sniffer import PacketSniffer
if __name__ == "__main__":
    s = PacketSniffer("icmp")
    serverP = input("Enter the server port")
    proxyP = input("Enter the proxy port")
    s.setSP(serverP) # set to port here
    s.setPP(proxyP) # set to port here
    s.setFN("sniffer_snooper.txt")
    s.sniff_packets()