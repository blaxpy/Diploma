from __future__ import division
import socket
import json
import pickle
import pygal
from datetime import datetime
from collections import OrderedDict
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
        return ether_types[p.type].upper()
    # Matches packets with unparsable transport layer protocols like EIGRP
    elif p.name == 'IP' and p.payload.name == 'Raw':
        return ip_protos[p.proto].upper()
    # Matches all TCP and UDP packets
    elif p.payload and p.name in ('IP', 'IPv6'):
        if p.payload.name in ('TCP', 'UDP'):
            # Define data variable for TCP or UDP payload to reduce clutter
            if p.payload.payload:
                data = p.payload.payload
            else:
                data = None

            try:
                # Check if we have unparsable data above transport layer like HTTPS in case of TCP
                if data and data.name in ('Raw', 'Padding'):
                    try:
                        al_proto_name = socket.getservbyport(p.payload.sport)
                    except socket.error:
                        al_proto_name = socket.getservbyport(p.payload.dport)
                    return p.name, p.payload.name, al_proto_name
                else:
                    # Raise exception to proceed with inspection
                    raise socket.error
            except socket.error:
                if data and data.name == 'Raw':
                    # If destination or source port does not match well known service consider it raw data
                    return p.name, p.payload.name, 'data'
                elif data:
                    # Return parsable layer above transport layer like DNS, because scapy understands DNS layer
                    return p.name, p.payload.name, p.payload.payload.name.lower()
                else:
                    # Return transport layer protocol without payload
                    return p.name, p.payload.name, 'no payload'
        else:
            # Return other transport protocols like ICMP
            return p.name, p.payload.name
    # Matches packets with special payload like ARP packets with padding
    elif p.payload and (p.payload.name == 'Raw' or p.payload.name == 'Padding'):
        return p.name
    # Matches packets without payload like ARP
    elif not p.payload:
        return p.name
    # Continues recursive inspection
    else:
        return inspect_packet(p.payload)


def x_labels_factory(x_interval):
    """Factory function which returns lambda function, that returns x_labels with passed interval"""
    counter = {'c': 0}

    def func(d):
        """Returns formatted string for multiples of interval"""
        if counter['c'] == 0 or counter['c'] % x_interval == 0:
            counter['c'] += 1
            return d.strftime('%H:%M:%S')
        else:
            counter['c'] += 1
            return ''

    return lambda d: func(d)


def values_factory(x_interval):
    counter = {'c': 0}

    def func(speed, dtime):
        if counter['c'] == 0 or counter['c'] % x_interval == 0:
            counter['c'] += 1
            return speed
        else:
            counter['c'] += 1
            return {'value': speed, 'label': datetime.fromtimestamp(dtime).strftime('%Mm %Ss')}

    return lambda speed, dtime: func(speed, dtime)


start_time = datetime.now()

# There wasn't a complete list of ether_types in scapy so I had to find it online
ether_types = load_obj('ether_types')

ip_protos = load_obj('ip_protos')

# with io.open('ether.json', 'wb') as f:
#     json.dump(ether_types, codecs.getwriter('utf-8')(f), ensure_ascii=False)
#
# with open('ether.json', 'rb') as f:
#     ether_json = json.load(f)
#     print(ether_json)
#     exit()

packet_dump = rdpcap('dump.pcap')
# packet_dump = rdpcap('new_dump.pcap')
# packet_dump = rdpcap('mpls-basic.pcap')
# packet_dump = rdpcap('conference.pcap')

# Display protocols summary
# print(repr(packet_dump))

proto_dict = {}
packet_time_size = OrderedDict()

for packet in packet_dump:
    packet_size = len(packet)
    packet_time_size[packet.time] = packet_size

    inspection_result = inspect_packet(packet)

    print(repr(packet))
    print(inspection_result)
    print('')

    # UDP or TCP transport layers
    if not isinstance(inspection_result, str):
        if len(inspection_result) == 3:
            # Divide proto to internet and transport layer protocols
            i_proto, t_proto, al_proto = inspection_result
            if i_proto in proto_dict:
                if t_proto in proto_dict[i_proto]:
                    if al_proto in proto_dict[i_proto][t_proto]:
                        proto_dict[i_proto][t_proto][al_proto].update({packet.time: packet_size})
                    else:
                        proto_dict[i_proto][t_proto].update({al_proto: {packet.time: packet_size}})
                else:
                    proto_dict[i_proto].update({t_proto: {al_proto: {packet.time: packet_size}}})
            else:
                proto_dict[i_proto] = {t_proto: {al_proto: {packet.time: packet_size}}}
        # Other transport layers
        elif len(inspection_result) == 2:
            i_proto, t_proto = inspection_result
            if i_proto in proto_dict:
                if t_proto in proto_dict[i_proto]:
                    proto_dict[i_proto][t_proto].update({packet.time: packet_size})
                else:
                    proto_dict[i_proto][t_proto] = {packet.time: packet_size}
            else:
                proto_dict[i_proto] = {t_proto: {packet.time: packet_size}}
    # All other protocols
    else:
        proto = inspection_result
        if proto in proto_dict:
            proto_dict[proto].update({packet.time: packet_size})
        else:
            proto_dict[proto] = {packet.time: packet_size}

# for proto, val in proto_dict.items():
#     if isinstance(val.values()[0], dict) and isinstance(val.values()[0].keys()[0], float):
#         print(proto)
#         for item, item_val in val.items():
#             # print('\t' + repr((item, len(item_val.items()), item_val.items())))
#             print('\t' + repr((item, len(item_val.items()))))
#     else:
#         # print(proto, len(val.items()), val.items())
#         print(proto, len(val.items()))
#     print('')

end_time = datetime.now()
elapsed_time = end_time - start_time
print('Elapsed time: ' + str(elapsed_time))

# for proto in proto_dict:
#     print(proto, proto_dict[proto])

time_period = packet_time_size.keys()[-1] - packet_time_size.keys()[0]
# print(time_period)

# interval = time_period / 20
interval = 1

packet_interval_time_size = OrderedDict()
for pos in range(1, int(time_period)):
    interval_speed = 0

    left_border = packet_time_size.keys()[0] + interval * (pos - 1)
    right_border = packet_time_size.keys()[0] + interval * pos

    interval_middle_time = packet_time_size.keys()[0] + interval * (pos + 0.5)

    for ptime in packet_time_size:
        if left_border <= ptime <= right_border:
            interval_speed += packet_time_size[ptime] * 8 / 1024 / interval

    packet_interval_time_size[interval_middle_time] = interval_speed

# print(packet_interval_time_size)
# print(sum(packet_interval_time_size.values()), sum(packet_time_size.values()))

# Create visualizations of gathered statistics
pie_chart = pygal.Pie()
pie_chart.title = 'Network traffic protocol distribution'

pie_chart_tcp_udp = pygal.Pie()
pie_chart_tcp_udp.title = 'TCP and UDP application protocols'

if 'IP' in proto_dict and 'IPv6' in proto_dict:
    ip_ipv6_tags = True
else:
    ip_ipv6_tags = False

for proto, sub_proto in proto_dict.items():
    # Check if the proto's sub_proto is a dictionary of packets
    if isinstance(sub_proto.keys()[0], float):
        quantity = len(sub_proto)
    # Parse proto's sub_proto
    else:
        quantity = []
        for item in sub_proto:
            if item in ('UDP', 'TCP'):
                s_quantity = []
                count = 0
                for s_p in sub_proto[item]:
                    count += len(sub_proto[item][s_p])
                    s_quantity.append({'value': len(sub_proto[item][s_p]), 'label': s_p})
                if ip_ipv6_tags:
                    pie_chart_tcp_udp.add(proto + ': ' + item, s_quantity)
                else:
                    pie_chart_tcp_udp.add(item, s_quantity)
                quantity.append({'value': count, 'label': item})
            else:
                quantity.append({'value': len(sub_proto[item].values()), 'label': item})
    pie_chart.add(proto, quantity)

pie_chart.render_to_file('protocols.svg')
pie_chart_tcp_udp.render_to_file('tcp_and_udp.svg')

# Create config for traffic speed and time chart
my_config = pygal.Config()
my_config.title = 'Traffic IO graph'
my_config.show_legend = False
my_config.x_title = 'Time hh:mm:ss'
my_config.y_title = 'Speed in kbit/s'
my_config.x_label_rotation = 30
# my_config.interpolate = 'cubic'
my_config.interpolate = 'hermite'
my_config.interpolation_parameters = {'type': 'kochanek_bartels', 'b': -1, 'c': 1, 't': 1}
# my_config.interpolation_parameters = {'type': 'cardinal', 'c': .75}
my_config.show_y_guides = True
# my_config.show_x_guides = True
my_config.width = 1000

speed_time_chart = pygal.Line(my_config)

# Define value interval for abscissa
x_int = len(packet_interval_time_size) // 6

get_x_label = x_labels_factory(x_int)
speed_time_chart.x_labels = map(get_x_label, map(datetime.fromtimestamp, packet_interval_time_size.keys()))

get_interval_value = values_factory(x_int)
interval_values = [get_interval_value(s, t) for t, s in packet_interval_time_size.items()]

speed_time_chart.add("", interval_values)
speed_time_chart.render_to_file('time_chart.svg')
