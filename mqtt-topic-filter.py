#!/usr/bin/python
from bcc import BPF
import socket
import os
import binascii
import time

# initialize BPF - load source code
bpf = BPF(src_file="mqtt-topic-filter.c")
# load eBPF function of type SOCKET_FILTER into the kernel
mqtt_filter_function = bpf.load_func("mqtt_filter", BPF.SOCKET_FILTER)
# creat a RAW socket and attach eBPF function
BPF.attach_raw_socket(mqtt_filter_function, "eth0")
# get the socket fd
socket_fd = mqtt_filter_function.sock
# create a Python socket object
sock = socket.fromfd(socket_fd, socket.PF_PACKET, 
                     socket.SOCK_RAW, socket.IPPROTO_IP)
# set as blocking
sock.setblocking(True)
# get reference to bpf allowed topics hash
allowed_topics = bpf.get_table("allowed_topics")

while 1:
    # arg 5 is Message 
    bpf.trace_print(fmt="{5}")
