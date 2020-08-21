#!/usr/bin/python
from bcc import BPF
import ipaddress
import json

# initialize BPF - load source code
bpf = BPF(src_file="mqtt-topic-filter.c")
# load eBPF function of type SOCKET_FILTER into the kernel
mqtt_filter_function = bpf.load_func("mqtt_filter", BPF.SOCKET_FILTER)
# create a RAW socket and attach eBPF function
BPF.attach_raw_socket(mqtt_filter_function, "eth0")
BPF.attach_raw_socket(mqtt_filter_function, "lo")

# attach to allowed topics table
allowed_topics = bpf.get_table("allowed_topics")

# load attached topics from json file
with open('./mqtt-topic-filter.json', 'r+') as fp:
    topicFilters = json.load(fp)
    fp.close()
for topic in topicFilters['data']['topicFilters']:
    allowed_topics[allowed_topics.Key( \
        int(ipaddress.IPv4Address(topic['srcIP'])), \
        topic['topic'].encode() )] = allowed_topics.Leaf( \
            topic['allowSub'], \
            topic['allowPub'], \
            topic['pubRate'])
# display topics data store
for key, value in allowed_topics.items():
    print(str(ipaddress.IPv4Address(key.src_ip)), key.topic, \
        value.allow_sub, value.allow_pub, value.rate)
while 1:
    (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
    print(msg)
