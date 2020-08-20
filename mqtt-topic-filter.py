#!/usr/bin/python
from bcc import BPF
import binascii
import socket
import struct
import ipaddress

# initialize BPF - load source code
bpf = BPF(src_file="mqtt-topic-filter.c")
# load eBPF function of type SOCKET_FILTER into the kernel
mqtt_filter_function = bpf.load_func("mqtt_filter", BPF.SOCKET_FILTER)
# create a RAW socket and attach eBPF function
BPF.attach_raw_socket(mqtt_filter_function, "eth0")

allowed_topics = bpf.get_table("allowed_topics")

allowed_topics[allowed_topics.Key(int(ipaddress.IPv4Address('192.168.7.65')), b'/my/topic')] = allowed_topics.Leaf(True, False, 10)

while 1:
    (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    print(msg)
    for key, value in allowed_topics.items():
        print(str(ipaddress.IPv4Address(key.src_ip)), key.topic, value.allow_sub, value.allow_pub, value.rate)
