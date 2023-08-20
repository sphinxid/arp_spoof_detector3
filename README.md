# arp_spoof_detector3
arp_spoof_detector3.py - Python 3 arp spoof/poisoning detector that updates the table list every 10 seconds.

## Dependencies
You will need pcapy-ng and Python 3.

## Usage

```
sudo python3 arp_spoof_detector3.py
```

Then you will see an input prompt:

```
Interface yang tersedia:  ['en0', 'awdl0', 'llw0', 'utun0', 'utun1', 'utun2', 'lo0', 'anpi2', 'anpi0', 'anpi1', 'en4', 'en5', 'en6', 'en1', 'en2', 'en3', 'ap1', 'bridge0', 'gif0', 'stf0', 'en7']
Masukkan nama interface (contoh: en0): en0
```

Then the output will be something like this:

```
Tabel Alamat MAC saat ini:
192.168.50.138 -> f4:d4:88:8d:a9:a0
192.168.50.1 -> a0:36:bc:6e:c8:d8



Tabel Alamat MAC saat ini:
192.168.50.138 -> f4:d4:88:8d:a9:a0
192.168.50.1 -> a0:36:bc:6e:c8:d8
192.168.50.2 -> 10:6f:d9:c3:2a:97
192.168.50.8 -> d0:55:09:cd:09:96
192.168.50.25 -> a4:d9:90:79:a1:01
192.168.50.117 -> 04:4b:ed:b6:75:cd
192.168.50.134 -> 10:62:e5:3e:69:7d
192.168.50.197 -> 60:32:b1:57:bc:dc
192.168.50.56 -> b4:b0:24:0d:10:c0
192.168.50.119 -> 5a:fc:d8:6f:c4:16
192.168.50.201 -> 28:c1:3c:ef:c7:e2
```

Example output if there is a mac poisoning attack:

```

[+] Terdeteksi ARP poisoning dari IP: 192.168.50.1. MAC seharusnya: a0:36:bc:6e:c8:d8, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.91. MAC seharusnya: d0:88:0c:77:2f:0a, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.1. MAC seharusnya: a0:36:bc:6e:c8:d8, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.91. MAC seharusnya: d0:88:0c:77:2f:0a, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.1. MAC seharusnya: a0:36:bc:6e:c8:d8, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.91. MAC seharusnya: d0:88:0c:77:2f:0a, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.1. MAC seharusnya: a0:36:bc:6e:c8:d8, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.91. MAC seharusnya: d0:88:0c:77:2f:0a, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.1. MAC seharusnya: a0:36:bc:6e:c8:d8, tapi dideteksi MAC: f4:d4:88:8d:a9:a0
[+] Terdeteksi ARP poisoning dari IP: 192.168.50.91. MAC seharusnya: d0:88:0c:77:2f:0a, tapi dideteksi MAC: f4:d4:88:8d:a9:a0

```

The attack is generated using [arpspoof3](https://github.com/sphinxid/arpspoof3)
```
sudo python3.11 arpspoof3.py -i en0 -t 192.168.50.91 -g 192.168.50.1
```

To exit you can use Ctrl+C
