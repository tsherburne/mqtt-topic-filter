#!/usr/bin/python
from bcc import BPF
import ipaddress, time, sys, uuid, uptime
from datetime import datetime
import json, os, uuid, requests
import asyncio
from ariadne import ObjectType, SubscriptionType, make_executable_schema, load_schema_from_path
from ariadne.asgi import GraphQL
import uvicorn
import threading

# save boottime
global bootTime
bootTime = int(time.time() - uptime.uptime())

# create storage for status response
status = {}
status['code'] = "Success"
status['message'] = ""

# create response templates
mqttFilterResponse = {}
mqttFilterResponse['status'] = status
policyExceptionResponse = {}
policyExceptionResponse['status'] = status
policyExceptionResponse['policyExceptions'] = []

global policyException, exceptionReceived
policyException = {}
exceptionReceived = False

# callback for bpf perf_buffer
def logPolicyException(cpu, data, size):
    global policyException, exceptionReceived, bootTime
    receivedException = {}
    exception = bpf["exceptions"].event(data)
    exceptionTime = datetime.fromtimestamp(int((exception.ts/1000000000) + bootTime))
    receivedException['id'] = str(uuid.uuid1())
    receivedException['timestamp'] = str(exceptionTime)
    receivedException['srcIP'] = str(ipaddress.ip_address(exception.src_ip))
    receivedException['topic'] = str(exception.topic.decode())
    if exception.mqtt_type == 3:
        receivedException['mqttType'] = 'Publish'
    elif exception.mqtt_type == 8:
        receivedException['mqttType'] = 'Subscribe'
    else:
        receivedException['mqttType'] = 'None'

    policyExceptionResponse['policyExceptions'].append(receivedException)

    policyException = receivedException
    exceptionReceived = True

 # initialize BPF - load source code
bpf = BPF(src_file="mqtt-topic-filter.c")
# load eBPF function of type SOCKET_FILTER into the kernel
mqtt_filter_function = bpf.load_func("mqtt_filter", BPF.SOCKET_FILTER)
# create a RAW socket and attach eBPF function
BPF.attach_raw_socket(mqtt_filter_function, "eth0")
BPF.attach_raw_socket(mqtt_filter_function, "lo")

# attach to allowed topics table
allowed_topics = bpf.get_table("allowed_topics")
# attach callback for exceptions perf buffer
bpf["exceptions"].open_perf_buffer(logPolicyException)

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

# store topic filter list
topicFilterList = topicFilters['data']['topicFilters']
mqttFilterResponse['topicFilters'] = topicFilterList

# display topics data store
for key, value in allowed_topics.items():
    print(str(ipaddress.IPv4Address(key.src_ip)), key.topic, \
        value.allow_sub, value.allow_pub, value.rate)

# load mqtt-topic-filter schema
type_defs = load_schema_from_path("./mqtt-topic-filter.graphql")

# setup Query resolvers
query = ObjectType("Query")
@query.field("mqttTopicFilterQuery")
def resolve_mqttTopicFilterQuery(obj, info):
    return mqttFilterResponse

@query.field("mqttPolicyExceptionQuery")
def resolve_mqttPolicyExceptionQuery(obj, info):
    return policyExceptionResponse

# setup Subscription resolvers
subscription = SubscriptionType()
@subscription.field("policyException")
def policyException_resolver(message, info):
    return message

# setup Subscription source from bpf trace
#   /sys/kernel/debug/tracing/trace_pipe
@subscription.source("policyException")
async def policyException_generator(obj, info):
    global policyException, exceptionReceived
    while 1:
        try:
            if exceptionReceived == True:
                yield policyException
                exceptionReceived = False
            await asyncio.sleep(1)

        # subscription or server stopped
        except asyncio.exceptions.CancelledError:
            yield policyException
            break

def pollBuffer():
    while 1:
        # logPolicyException() callback happens before perf_buffer_poll() returns
        bpf.perf_buffer_poll()

# setup daemon thread to handle perf buffer polling and callback
#   daemon is killed when uvicorn exists
thread = threading.Thread(target=pollBuffer)
thread.setDaemon(True)
thread.start()

# setup graphQL server from schema, queries and mutations
schema = make_executable_schema(type_defs, [query, subscription])
app = GraphQL(schema, debug=True)

# start uvicorn ASGI server
uvicorn.run(app, host="192.168.7.67", lifespan="off", port=8000, log_level="debug")
sys.exit(0)
