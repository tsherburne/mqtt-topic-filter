#!/usr/bin/python
from bcc import BPF
import ipaddress
import json, os, uuid, requests
import asyncio
import time
import sys
from ariadne import ObjectType, SubscriptionType, make_executable_schema, load_schema_from_path
from ariadne.asgi import GraphQL
import uvicorn

# create storage for status response
status = {}
status['code'] = "Success"
status['message'] = ""

# create response templates
mqttFilterResponse = {}
mqttFilterResponse['status'] = status

global exceptionMsg
exceptionMsg = ""

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

# load mqtt-topic-filter schema
type_defs = load_schema_from_path("./mqtt-topic-filter.graphql")
# load mqtt-topic-filter data file
with open("./mqtt-topic-filter.json") as fp:
    systemModel = json.load(fp)
    fp.close()
topicFilterList = systemModel['data']['topicFilters']
mqttFilterResponse['topicFilters'] = topicFilterList

# setup Query resolvers
query = ObjectType("Query")
@query.field("mqttTopicFilterQuery")
def resolve_mqttTopicFilterQuery(obj, info):
    return mqttFilterResponse

# setup Subscription resolvers
subscription = SubscriptionType()
@subscription.field("policyException")
def policyException_resolver(message, info):
    return message

@subscription.source("policyException")
async def policyException_generator(obj, info):
    global exceptionMsg
    while 1:
        try:
            (task, pid, cpu, flags, ts, exceptionMsg) = bpf.trace_fields(nonblocking=True)
            if exceptionMsg is not None:
                yield exceptionMsg.decode()
                continue
            await asyncio.sleep(1)
        except asyncio.exceptions.CancelledError:
            yield ""
            break

# setup graphQL server from schema, queries and mutations
schema = make_executable_schema(type_defs, [query, subscription])
app = GraphQL(schema, debug=True)

if __name__ == "__main__":
    uvicorn.run(app, host="192.168.7.67", lifespan="off", port=8000, log_level="debug")
    sys.exit(0)

