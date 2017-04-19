import socket
import pickle
from datetime import datetime
from scapy.all import *


def save_obj(obj, name):
    """Saves object with pickle in binary mode"""
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def load_obj(name):
    """Loads object with pickle by reading binary file"""
    with open(name + '.pkl', 'rb') as f:
        return pickle.load(f)


def inspect_packet(p):
    """Performs recursive packet inspection by analyzing each layers payloads"""

    # Matches L2 VPN packets like MPLS
    if p.name == 'Ethernet' and p.payload.name == 'Raw':
        return ether_types[p.type], {}
    # Matches packets with unparsable transport layer protocols like EIGRP
    elif p.name == 'IP' and p.payload.name == 'Raw':
        return ip_protos[p.proto].upper(), {}
    # Matches all TCP and UDP packets
    elif p.payload and p.name in ('IP', 'IPv6') and p.payload.name in ('TCP', 'UDP'):
        # Define data variable for TCP or UDP payload to reduce clutter
        if p.payload.payload:
            data = p.payload.payload
        else:
            data = None

        try:
            # Check if we have unparsable data above transport layer like HTTPS in case of TCP
            if data and data.name == 'Raw':
                try:
                    proto_name = socket.getservbyport(p.payload.dport)
                except socket.error:
                    proto_name = socket.getservbyport(p.payload.sport)
                return p.name, p.payload.name, {'al_protocol': proto_name}
            else:
                # Raise exception to proceed with inspection
                raise socket.error
        except socket.error:
            if data and data.name == 'Raw':
                # If destination or source port does not match well known service consider it raw data
                return p.name, p.payload.name, {'al_protocol': 'data'}
            elif data:
                # Return parsable layer above transport layer like DNS, because scapy understands DNS layer
                return p.name, p.payload.name, {'al_protocol': p.payload.payload.name.lower()}
            else:
                # Return transport layer protocol without payload
                return p.name, p.payload.name, {}
    # Matches packets with special payload like ARP packets with padding
    elif p.payload and (p.payload.name == 'Raw' or p.payload.name == 'Padding'):
        return p.name, {}
    # Matches packets without payload like ARP
    elif not p.payload:
        return p.name, {}
    # Continues recursive inspection
    else:
        return inspect_packet(p.payload)

start_time = datetime.now()

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

    proto = inspection_result[:-1]
    inspection_pdict = inspection_result[-1]

    # print(repr(packet))
    # print(inspection_result)
    # print('')

    pdict = {'length': len(packet)}

    # Check if the received dict is not empty
    if inspection_pdict:
        pdict.update(inspection_pdict)

    if len(proto) == 2:
        # Divide proto to internet and transport layer protocols
        i_proto, t_proto = proto
        if i_proto in proto_dict:
            if t_proto in proto_dict[i_proto]:
                proto_dict[i_proto][t_proto].update({packet.time: pdict})
            else:
                proto_dict[i_proto].update({t_proto: {packet.time: pdict}})
        else:
            proto_dict[i_proto] = {t_proto: {packet.time: pdict}}
    else:
        if proto in proto_dict:
            proto_dict[proto].update({packet.time: pdict})
        else:
            proto_dict[proto] = {packet.time: pdict}

for proto, val in proto_dict.items():
    if isinstance(val.values()[0], dict) and isinstance(val.values()[0].keys()[0], float):
        print(proto)
        for item, item_val in val.items():
            # print('\t' + repr((item, len(item_val.items()), item_val.items())))
            print('\t' + repr((item, len(item_val.items()))))
    else:
        # print(proto, len(val.items()), val.items())
        print(proto, len(val.items()))
    print('')

end_time = datetime.now()
elapsed_time = end_time - start_time
print('Elapsed time: ' + str(elapsed_time))


