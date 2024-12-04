from scapy.all import ARP, Ether, srp

def get_mac_addresses(target_ip):
    # Create an ARP request packet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)

    # Extract IP and MAC addresses
    devices = []
    for response in result:
        sent = response
        received = response
        print(received.show())  # Print the structure of received
        if ARP in received and received[ARP].op == 2:  # is-at (response)
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    target_ip = "192.168.1.0/24"  # Adjust this to match your network
    devices = get_mac_addresses(target_ip)

    # Limit to 5 devices
    devices = devices[:5]

    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

if __name__ == "__main__":
    main()
