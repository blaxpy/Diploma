# -*- coding: utf-8 -*-
from __future__ import division
import socket
import pickle
import pygal
from datetime import datetime
from collections import defaultdict, OrderedDict
from random import randint
from scapy.all import *


def save_obj(obj, name):
    """Saves object with pickle in binary mode"""
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def load_obj(name):
    """Loads object with pickle by reading binary file"""
    with open(name + '.pkl', 'rb') as f:
        return pickle.load(f)


def render_chart(chart, name):
    """Saves chart in svg and png formats"""
    chart.render_to_png(filename='%s.png' % name)
    chart.render_to_file(filename='%s.svg' % name)


def inspect_packet(p):
    """Performs recursive packet inspection by analyzing each layers payloads"""

    # Matches L2 VPN packets like MPLS
    if p.name == 'Ethernet' and p.payload.name == 'Raw':
        return ether_types[p.type].upper()
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
                if data and data.name == 'Raw':
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
        # Matches packets with unparsable transport layer protocols like EIGRP
        elif p.payload.name == 'Raw':
            return p.name, ip_protos[p.proto].upper()
        else:
            # Return other transport protocols like ICMP
            return p.name, p.payload.name
    # Matches packets with special payload like ARP packets with padding
    elif p.payload and (p.payload.name == 'Raw' or p.payload.name == 'Padding'):
        return p.__class__.__name__
    # Matches packets without payload like ARP
    elif not p.payload:
        return p.name
    # Continues recursive inspection
    else:
        return inspect_packet(p.payload)


def get_rand_color():
    rgb = [randint(0, 255) for x in range(3)]
    return 'rgba({0}, {1}, {2}, 1)'.format(*rgb)


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


# Record script's start time
start_time = datetime.now()

# There wasn't a complete list of EtherTypes in scapy so I had to find it online
ether_types = load_obj('ether_types')

ip_protos = load_obj('ip_protos')

filename = 'dump.pcap'

packet_dump = PcapReader(filename)

total_quantity = 0
tcp_udp_quantity = 0
other_quantity = 0

proto_dict = {}
frame_sizes = defaultdict(lambda: 0)
packet_interval_time_speed = OrderedDict()

packet_dump_time = PcapReader(filename)

first_time = last_time = next(packet_dump_time)
for last_time in packet_dump_time:
    pass

first_time = first_time.time
last_time = last_time.time

time_period = last_time - first_time

interval = time_period / 25

left_border = first_time
right_border = first_time + interval

interval_volume = 0
pos = 1

for packet in packet_dump:
    try:
        total_quantity += 1

        packet_size = len(packet)

        if packet_size <= 64:
            frame_sizes[64] += 1
        elif 65 <= packet_size <= 127:
            frame_sizes[127] += 1
        elif 128 <= packet_size <= 255:
            frame_sizes[255] += 1
        elif 256 <= packet_size <= 511:
            frame_sizes[511] += 1
        elif 512 <= packet_size <= 1023:
            frame_sizes[1023] += 1
        elif 1024 <= packet_size <= 1517:
            frame_sizes[1517] += 1
        elif packet_size >= 1518:
            frame_sizes[1518] += 1

        if left_border <= packet.time < right_border:
            interval_volume += packet_size
        else:
            interval_middle_time = first_time + interval * (pos + 0.5)
            packet_interval_time_speed[interval_middle_time] = interval_volume / 1024 / interval
            interval_volume = packet_size
            pos += 1
            left_border = first_time + interval * (pos - 1)
            right_border = first_time + interval * pos

        inspection_result = inspect_packet(packet)

        # UDP or TCP transport layers
        if not isinstance(inspection_result, str):
            if len(inspection_result) == 3:
                tcp_udp_quantity += 1
                # Divide proto to internet and transport layer protocols
                i_proto, t_proto, al_proto = inspection_result
                if i_proto in proto_dict:
                    if t_proto in proto_dict[i_proto]:
                        if al_proto in proto_dict[i_proto][t_proto]:
                            proto_dict[i_proto][t_proto][al_proto]['quantity'] += 1
                            proto_dict[i_proto][t_proto][al_proto]['volume'] += packet_size
                        else:
                            proto_dict[i_proto][t_proto].update({al_proto: {packet.time: packet_size}})
                            proto_dict[i_proto][t_proto].update({al_proto: {'quantity': 1, 'volume': packet_size}})
                    else:
                        proto_dict[i_proto].update({t_proto: {al_proto: {'quantity': 1, 'volume': packet_size}}})
                else:
                    proto_dict[i_proto] = {t_proto: {al_proto: {'quantity': 1, 'volume': packet_size}}}
            # Other transport layers
            elif len(inspection_result) == 2:
                i_proto, t_proto = inspection_result
                if i_proto in proto_dict:
                    if t_proto in proto_dict[i_proto]:
                        proto_dict[i_proto][t_proto]['quantity'] += 1
                        proto_dict[i_proto][t_proto]['volume'] += packet_size
                    else:
                        proto_dict[i_proto][t_proto] = {'quantity': 1, 'volume': packet_size}
                else:
                    proto_dict[i_proto] = {t_proto: {'quantity': 1, 'volume': packet_size}}
        # All other protocols
        else:
            other_quantity += 1
            proto = inspection_result
            if proto in proto_dict:
                proto_dict[proto]['quantity'] += 1
                proto_dict[proto]['volume'] += packet_size
            else:
                proto_dict[proto] = {'quantity': 1, 'volume': packet_size}
    except IndexError:
        # Some packets might have crippled format so the len function and inspection doesn't work
        pass

end_time = datetime.now()
elapsed_time = end_time - start_time
print('Elapsed time: ' + str(elapsed_time))

# Create visualizations of gathered statistics
pie_chart = pygal.Pie(formatter=lambda x: '{:.3f}%'.format(x * 100 / total_quantity))
pie_chart.title = u'Распределение протоколов'

pie_chart_no_ip = pygal.Pie(formatter=lambda x: '{:.3f}%'.format(x * 100 / other_quantity))
pie_chart_no_ip.title = u'Распределение протоколов без IPv4 и IPv6'

pie_chart_tcp_udp = pygal.Pie(formatter=lambda x: '{:.3f}%'.format(x * 100 / tcp_udp_quantity))
pie_chart_tcp_udp.title = u'Распределение протоколов уровня приложений для TCP и UDP'

if 'IP' in proto_dict and 'IPv6' in proto_dict:
    ip_ipv6_tags = True
else:
    ip_ipv6_tags = False

for proto, sub_proto in proto_dict.items():
    # Check if the proto's sub_proto is a dictionary of packets
    if isinstance(sub_proto.values()[0], int):
        quantity = sub_proto['quantity']
    # Parse proto's sub_proto
    else:
        quantity = []
        for item in sub_proto:
            if item in ('UDP', 'TCP'):
                s_quantity = []
                count = 0
                for s_p in sub_proto[item]:
                    count += sub_proto[item][s_p]['quantity']
                    s_quantity.append(
                        {'value': sub_proto[item][s_p]['quantity'], 'label': s_p})
                if ip_ipv6_tags:
                    pie_chart_tcp_udp.add(proto + ': ' + item, s_quantity)
                else:
                    pie_chart_tcp_udp.add(item, s_quantity)
                quantity.append({'value': count, 'label': item})
            else:
                quantity.append({'value': sub_proto[item]['quantity'], 'label': item})
    pie_chart.add(proto, quantity)
    if proto not in ('IP', 'IPv6'):
        pie_chart_no_ip.add(proto, quantity)

render_chart(pie_chart, name='protocols')
render_chart(pie_chart_no_ip, name='protocols_no_ip')
render_chart(pie_chart_tcp_udp, name='tcp_and_udp')

# Create config for traffic speed and time chart
st_chart_config = pygal.Config()
st_chart_config.title = u'Использование ресурсов сети'
st_chart_config.show_legend = False
st_chart_config.x_title = u'Время в формате чч:мм:сс'
st_chart_config.y_title = u'Скорость в КБ/с'
st_chart_config.x_label_rotation = 30
st_chart_config.interpolate = 'hermite'
st_chart_config.interpolation_parameters = {'type': 'kochanek_bartels', 'b': -1, 'c': 1, 't': 1}
st_chart_config.formatter = lambda x: '{:.2f}'.format(x)
st_chart_config.show_y_guides = True

speed_time_chart = pygal.Line(st_chart_config)

# Define value interval for abscissa
x_int = len(packet_interval_time_speed) // 6

get_x_label = x_labels_factory(x_int)
speed_time_chart.x_labels = map(get_x_label, map(datetime.fromtimestamp, packet_interval_time_speed.keys()))

get_interval_value = values_factory(x_int)
interval_values = [get_interval_value(s, t) for t, s in packet_interval_time_speed.items()]

speed_time_chart.add("", interval_values)

render_chart(speed_time_chart, 'time_chart')

# Create config for frame sizes histogram
f_bar_config = pygal.Config()
f_bar_config.title = u'Распределение по размеру кадров'
f_bar_config.show_legend = False
f_bar_config.x_title = u'Размерные группы в байтах'
f_bar_config.y_title = u'Количество кадров'
f_bar_config.show_y_guides = True
f_bar_config.rounded_bars = 10
f_bar_config.print_values = True
f_bar_config.print_values_position = 'top'
f_bar_config.formatter = lambda x: '{:.1f}%'.format(x * 100 / total_quantity)

frame_sizes_bar = pygal.Bar(f_bar_config)

frame_sizes_labels = [u'\u226464',
                      '65-127',
                      '128-255',
                      '256-511',
                      '512-1023',
                      '1024-1517',
                      u'\u22651518']

frame_sizes_bar.x_labels = frame_sizes_labels

frame_sizes_values = [{'value': val, 'color': get_rand_color()} for item, val in
                      sorted(frame_sizes.items())]
frame_sizes_bar.add("", frame_sizes_values)

render_chart(frame_sizes_bar, name='frame_sizes')
