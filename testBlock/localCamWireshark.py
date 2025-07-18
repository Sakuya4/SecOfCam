import subprocess
import os
import socket
import pyshark
import collections
from ipwhois import IPWhois

def getLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def isPrivateIP(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("10.122.") or
        ip.startswith("10.122.6.") or
        (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31)
    )

def capture_network_traffic_tshark(output_path="./trafficCapture", capture_file_name="result", capture_duration=60, interface=1):
    print(f"capture network traffic on interface {interface} for {capture_duration} seconds...")
    if not os.path.exists(output_path):
        print(f"create output directory: {output_path}")
        os.makedirs(output_path)
    pcapng_file_path = os.path.join(output_path, f"{capture_file_name}.pcapng")
    if os.path.exists(pcapng_file_path):
        os.remove(pcapng_file_path)
        print(f"remove old pcapng file: {pcapng_file_path}")

    print(f"start tshark capture to {pcapng_file_path} ...")
    print("open web Cam and start capture")

    tsharkPath = r"C:\Program Files\Wireshark\tshark.exe"
    tsharkCli = [
        tsharkPath,
        "-i", str(interface),
        "-a", f"duration:{capture_duration}",
        "-w", pcapng_file_path
    ]
    subprocess.run(tsharkCli)
    print(f"capture done! pcapng file is saved at {pcapng_file_path}")

    localIP = getLocalIP()
    print(f"local IP: {localIP}\n")
    print("any private IP: ", isPrivateIP(localIP))
    
    print("analyzing internet flow...")
    cap = pyshark.FileCapture(pcapng_file_path, display_filter=f"ip.src=={localIP}")
    externalIPs = set()
    external_packet_count = 0
    ip_counter = collections.Counter()

    for pkt in cap:
        try:
            dst_ip = pkt.ip.dst
            if not isPrivateIP(dst_ip):
                print(f"local IP: {localIP} -> {dst_ip}")
                externalIPs.add(dst_ip)
                external_packet_count += 1
                ip_counter[dst_ip] += 1
        except AttributeError:
            continue
    cap.close()

    if not externalIPs:
        print("no external IP found.")
    else:
        print("external IP:")
        for ip in externalIPs:
            print(ip)
        print(f"\nfound {len(externalIPs)} different external IPs.")
        print(f"total packets to external IPs: {external_packet_count}")
        print("\npacket count for each external IP (with whois):")
        for ip, count in ip_counter.most_common():
            try:
                whois = IPWhois(ip).lookup_rdap()
                org = whois.get('network', {}).get('name', 'N/A')
                country = whois.get('network', {}).get('country', 'N/A')
                print(f"{ip}: {count} packets | Org: {org} | Country: {country}")
            except Exception as e:
                print(f"{ip}: {count} packets | Whois query failed: {e}")

if __name__ == "__main__":
    capture_network_traffic_tshark(capture_duration=60, interface=6)
