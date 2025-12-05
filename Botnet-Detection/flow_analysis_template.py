import pandas as pd
from scapy.all import rdpcap

def extract_flow_features(pcap_file):
    """
    Extracts basic flow features from a PCAP file.
    """
    packets = rdpcap(pcap_file)
    flows = {}
    
    for pkt in packets:
        if pkt.haslayer('IP'):
            src = pkt['IP'].src
            dst = pkt['IP'].dst
            proto = pkt['IP'].proto
            length = len(pkt)
            
            flow_id = (src, dst, proto)
            
            if flow_id not in flows:
                flows[flow_id] = {'packet_count': 0, 'total_bytes': 0}
            
            flows[flow_id]['packet_count'] += 1
            flows[flow_id]['total_bytes'] += length
            
    return pd.DataFrame.from_dict(flows, orient='index')

if __name__ == "__main__":
    df = extract_flow_features("capture.pcap")
    print(df.head())
