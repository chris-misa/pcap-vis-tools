#!/usr/bin/python3

#
# 3D plotly of packet-level src*dst*time
#

import plotly.graph_objects as go
import plotly
import sys
import re

from scapy.all import *

from socket import inet_aton
from struct import unpack

times = []
src_ips = []
dst_ips = []
lens = []
protos = []
labels = []

USAGE="<source pcap file> <output html graph file> <count or 0 for all>"

if len(sys.argv) != 4:
    print(USAGE)
    sys.exit()

reader = RawPcapReader(sys.argv[1])
nonip = 0
i = 0
total = int(sys.argv[3])
LLcls = conf.l2types.get(reader.linktype)
if LLcls is None:
    print("Unknown link type %d" % reader.linktype)

#print("Start reading %s" % (sys.argv[1],))

firstTime = None

for pkt, meta in reader:

    p = LLcls(pkt)
    if IP in p:
        newTime = float(meta.sec + meta.usec / 1000000)
        if firstTime is None:
            firstTime = newTime
        times.append(newTime - firstTime)
        src_ips.append(unpack("I", inet_aton(p[IP].src))[0])
        dst_ips.append(unpack("I", inet_aton(p[IP].dst))[0])
        lens.append(int(p[IP].len))
        protos.append(int(p[IP].proto))
        labels.append("src: %s dst: %s proto: %d len: %d" % (p[IP].src, p[IP].dst, p[IP].proto, p[IP].len))

    i += 1
    if total != 0 and i == total:
        break

    if i % 100 == 0:
        sys.stdout.write("\rRead %d packets" % (i,))
        sys.stdout.flush()
        
print("\n")

# print("Times:")
# print(times)
# print("src:")
# print(src_ips)
# print("dst:")
# print(dst_ips)
# print("len:")
# print(lens)

scaleLens = [int(l / 250) for l in lens]

fig = go.Figure([go.Scatter3d(x = times, y = dst_ips, z = src_ips, \
       text=labels, \
       mode="markers", marker = dict( \
            color = protos, size = scaleLens, opacity=0.5, \
            line=dict(width=0), \
            colorscale="Cividis", \
            colorbar=dict(tick0=0, dtick=1)))])

fig.update_layout(height=1000)

plotly.offline.plot(fig, filename=sys.argv[2])

print("Done.")
