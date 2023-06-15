from sniffer import PacketSniffer

if __name__ == "__main__":
    s_talnet = PacketSniffer("talnet")
    s_talnet.setFN("telnet_passwords.txt")
    s_talnet.sniff_packets()