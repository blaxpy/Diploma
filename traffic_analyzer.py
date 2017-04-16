import socket
import pickle
from scapy.all import *


def save_obj(obj, name):
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def load_obj(name):
    with open(name + '.pkl', 'rb') as f:
        return pickle.load(f)


def inspect_packet(p):
    if p.name == 'Ethernet' and p.payload.name == 'Raw':
        return ether_types[p.type], {}
    elif p.name == 'IP' and p.payload.name == 'Raw':
        return ip_protos[p.proto].upper(), {}
    # elif p.payload and p.name in ('IP', 'IPv6') and p.payload.name in ('TCP', 'UDP'):
    elif p.payload and p.name in ('TCP', 'UDP'):
        try:
            proto_name = socket.getservbyport(p.getfieldval('dport'))
            return p.name, {'al_protocol': proto_name}
        except socket.error:
            if p.payload and p.payload.name == 'Raw':
                return p.name, {'al_protocol': 'data'}
            elif p.payload:
                # Return for example DNS, because scapy understands DNS layer
                return p.name, {'al_protocol': p.payload.name.lower()}
    elif p.payload and (p.payload.name == 'Raw' or p.payload.name == 'Padding'):
        return p.name, {}
    elif not p.payload:
        return p.name, {}
    else:
        return inspect_packet(p.payload)


# There wasn't a complete list of ether_types in scapy so I had to find it online
ether_types = load_obj('ether_types')

ip_protos = load_obj('ip_protos')

packet_dump = rdpcap('dump.pcap')
# packet_dump = rdpcap('mpls-basic.pcap')
# packet_dump = rdpcap('conference.pcap')

# Display protocols summary
# print(repr(packet_dump))

proto_dict = {}

for packet in packet_dump:
    inspection_result = inspect_packet(packet)
    temp_pdict = {'length': len(packet)}

    # Check if the received dict is not empty
    if inspection_result[1]:
        temp_pdict.update(inspection_result[1])

    try:
        if inspection_result[0] in proto_dict:
            proto_dict[inspection_result[0]].update({packet.time: temp_pdict})
        else:
            proto_dict[inspection_result[0]] = {packet.time: temp_pdict}
    except TypeError:
        print(repr(packet))
        print(inspection_result)

for proto, val in proto_dict.items():
    print(proto, len(val.items()), val.items())

# tcp_services_ports_and_names = {item[1]: item[0] for item in dict(TCP_SERVICES).items()}
# print(tcp_services_ports_and_names.items())
# udp_services_ports_and_names = {item[1]: item[0] for item in dict(UDP_SERVICES).items()}
# print(udp_services_ports_and_names.items())

