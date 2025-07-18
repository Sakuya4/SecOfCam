import pyshark
import collections
from ipwhois import IPWhois

def isPrivateIP(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31)
    )

# web cam IP addr def
camera_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
# web cam IP addr def done

def analyze_camera_traffic(pcapng_file_path):
    cap = pyshark.FileCapture(pcapng_file_path, display_filter="ip")
    ip_counter = collections.Counter()
    for pkt in cap:
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            if src_ip in camera_ips and not isPrivateIP(dst_ip):
                ip_counter[(src_ip, dst_ip)] += 1
        except AttributeError:
            continue
    cap.close()

    print("\nweb cam traffic (with whois):")
    for (src_ip, dst_ip), count in ip_counter.most_common():
        try:
            whois = IPWhois(dst_ip).lookup_rdap()
            org = whois.get('network', {}).get('name', 'N/A')
            country = whois.get('network', {}).get('country', 'N/A')
            print(f"{src_ip} -> {dst_ip}: {count} packets | Org: {org} | Country: {country}")
        except Exception as e:
            print(f"{src_ip} -> {dst_ip}: {count} packets | Whois query failed: {e}")

if __name__ == "__main__":
    # set the path of pcapng file
    analyze_camera_traffic("./trafficCapture/resultOfMain.pcapng")
