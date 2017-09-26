Program analyzes preliminary recorded pcap file using Python 2.7 library ``Scapy``,
when collecting packet statistics is finished,
it then uses ``Pygal`` library to vizualize statistical data.

Program produces five visualizations which are saved in two formats (svg, png):
 * Protocol distribution
 * Protocol distribution without IPv4 and IPv6
 * Application level protocol distribution for TCP and UDP
 * Traffic IO graph
 * Frame size distribution histogram
