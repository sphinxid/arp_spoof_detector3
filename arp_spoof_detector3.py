import pcapy
import struct
import threading

# Konstanta untuk ARP
ETHERTYPE_ARP = 0x0806
ARP_REPLY = 2

macs = {}
lock = threading.Lock()

def tampilkan_tabel_mac():
    """Menampilkan tabel alamat MAC saat ini ke layar."""
    global macs
    lock.acquire()
    print("\nTabel Alamat MAC saat ini:")
    for ip, mac in macs.items():
        print(f"{ip} -> {mac}")
    print("\n")
    lock.release()

    # Set timer untuk menampilkan tabel setiap 10 detik
    threading.Timer(10, tampilkan_tabel_mac).start()

def deteksi_arp_poisoning(interface):
    capture = pcapy.open_live(interface, 65536, 1, 0)
    global macs

    while True:
        try:
            (header, packet) = capture.next()
            ethertype = struct.unpack('!H', packet[12:14])[0]

            if ethertype == ETHERTYPE_ARP:
                arp_header = packet[14:42]

                _, _, _, _, opcode = struct.unpack('!HHBBH', arp_header[:8])

                if opcode == ARP_REPLY:
                    sender_mac = struct.unpack('!6B', arp_header[8:14])
                    sender_ip = struct.unpack('!4B', arp_header[14:18])

                    sender_mac_str = ':'.join('{:02x}'.format(b) for b in sender_mac)
                    sender_ip_str = '.'.join(str(b) for b in sender_ip)

                    lock.acquire()
                    if sender_ip_str in macs:
                        if macs[sender_ip_str] != sender_mac_str:
                            print(f"[+] Terdeteksi ARP poisoning dari IP: {sender_ip_str}. MAC seharusnya: {macs[sender_ip_str]}, tapi dideteksi MAC: {sender_mac_str}")
                    else:
                        macs[sender_ip_str] = sender_mac_str
                    lock.release()

        except KeyboardInterrupt:
            tampilkan_tabel_mac()
            print("[-] Deteksi dihentikan")
            break

if __name__ == "__main__":
    interfaces = pcapy.findalldevs()
    print("Interface yang tersedia: ", interfaces)
    interface = input("Masukkan nama interface (contoh: en0): ")

    # Mulai timer pertama kali untuk menampilkan tabel MAC
    tampilkan_tabel_mac()

    # Mulai deteksi ARP poisoning
    deteksi_arp_poisoning(interface)
