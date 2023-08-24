import pcapy
import struct
import threading
import netifaces
import socket
from ipaddress import IPv4Network

# Konstanta untuk ARP
ETHERTYPE_ARP = 0x0806
ARP_REPLY = 2

macs = {}
lock = threading.Lock()

def tampilkan_tabel_mac():
    # Menampilkan tabel alamat MAC yang dikenal ke layar.
    global macs
    lock.acquire()
    print("\nDaftar Alamat MAC saat ini:")
    for ip, mac in macs.items():
        print(f"{ip} -> {mac}")
    print("\n")
    lock.release()

    # Atur timer untuk menampilkan tabel setiap 10 detik
    threading.Timer(10, tampilkan_tabel_mac).start()

def get_local_ip(interface):
    # Dapatkan alamat IP lokal dari interface yang diberikan.
    addr = netifaces.ifaddresses(interface)
    return addr[netifaces.AF_INET][0]['addr']

def mac_to_bytes(mac_str):
    # Konversi string alamat MAC menjadi bytes.
    return bytes.fromhex(mac_str.replace(':', ''))

def arp_scan(interface):
    # Kirim ARP request ke setiap IP di subnet untuk mendeteksi alamat MAC lebih cepat.
    # Dapatkan IP dan netmask dari interface
    addr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
    ip_addr = addr['addr']
    netmask = addr['netmask']

    # Hitung rentang IP di subnet
    subnet = IPv4Network(f"{ip_addr}/{netmask}", strict=False)

    # Cetak netmask
    print(f"[+] Netmask: {netmask}")

    # Cetak informasi subnet
    print(f"[+] Subnet: {subnet}")

    # Dapatkan alamat MAC lokal
    local_mac = mac_to_bytes(netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'])

    # Kirim ARP request
    pcap = pcapy.open_live(interface, 65536, 1, 0)

    # Dapatkan IP lokal
    local_ip = get_local_ip(interface)

    for ip in subnet.hosts():
        packet = create_arp_request_packet(local_mac, str(ip), local_ip)
        pcap.sendpacket(packet)

    print("[+] Mengirimkan ARP request untuk pemindaian subnet.")

def jadwalkan_arp_scan(interface):
    # Jalankan arp_scan dan atur jadwal pemindaian berikutnya.
    arp_scan(interface)

    # Mengatur timer untuk memanggil fungsi ini lagi setelah 60 detik
    threading.Timer(60, jadwalkan_arp_scan, args=[interface]).start()

def create_arp_request_packet(source_mac, target_ip, local_ip):
    """Buat paket ARP request untuk IP target."""
    # Asumsi untuk alamat MAC yang akan diterima oleh semua komputer di jaringan
    broadcast_mac = b'\xff\xff\xff\xff\xff\xff'  # ff:ff:ff:ff:ff:ff dalam format byte

    # Membuat header Ethernet: Ini seperti bagian alamat dari surat fisik
    eth_header = struct.pack("!6s6s2s", broadcast_mac, source_mac, b'\x08\x06')  # Format paket Ethernet

    # Membuat header ARP: Ini seperti isi surat yang memberi tahu apa yang kita ingin tahu
    htype = b'\x00\x01'  # Tipe hardware (Ethernet)
    ptype = b'\x08\x00'  # Tipe protokol (IP)
    hlen = b'\x06'       # Panjang alamat hardware (MAC)
    plen = b'\x04'       # Panjang alamat protokol (IP)
    operation = b'\x00\x01'  # Operasi (permintaan ARP)
    sha = source_mac     # Alamat MAC pengirim
    spa = socket.inet_aton(local_ip)  # Alamat IP pengirim
    tha = b'\x00\x00\x00\x00\x00\x00'  # Alamat MAC target, yang belum kita ketahui
    tpa = socket.inet_aton(target_ip)  # Alamat IP target

    # Menggabungkan semua informasi di atas untuk membuat header ARP
    arp_header = struct.pack("!2s2s1s1s2s6s4s6s4s", htype, ptype, hlen, plen, operation, sha, spa, tha, tpa)

    # Menggabungkan header Ethernet dan ARP untuk membuat paket ARP lengkap
    return eth_header + arp_header

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
    print("Daftar Interface yang tersedia: ", interfaces)
    interface = input("Masukkan nama interface (misalnya: en0): ")

    # Mulai ARP scan untuk mendeteksi alamat MAC lebih cepat
    jadwalkan_arp_scan(interface)

    # Mulai timer pertama kali untuk menampilkan daftar MAC
    tampilkan_tabel_mac()

    # Mulai deteksi ARP poisoning
    deteksi_arp_poisoning(interface)
