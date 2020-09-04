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
import pyroute2

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

global policyException, exceptionReceived, exceptionCount
policyException = {}
exceptionReceived = False
exceptionCount = 0

# create dicionary (ip, topic) -> 'index' within policyExceptions list
global exceptionIndex
exceptionIndex = {}


# callback for bpf perf_buffer
def notifyPolicyException(cpu, data, size):
    global policyException, exceptionReceived, bootTime, exceptionCount, exceptionIndex
    receivedException = {}
    exception = bpf["notifications"].event(data)
    exceptionTime = datetime.fromtimestamp(int((exception.initial_ts/1000000000) + bootTime))
    receivedException['id'] = str(uuid.uuid1())
    receivedException['initialTimestamp'] = str(exceptionTime)
    receivedException['latestTimestamp'] = str(exceptionTime)
    receivedException['count'] = 1
    receivedException['srcIP'] = str(ipaddress.ip_address(exception.src_ip))
    receivedException['topic'] = str(exception.topic.decode())
    if exception.mqtt_type == 3:
        receivedException['pubException'] = True
    else:
        receivedException['pubException'] = False
    if exception.mqtt_type == 8:
        receivedException['subException'] = True
    else:
        receivedException['subException'] = False

    policyException = receivedException
    policyExceptionResponse['policyExceptions'].append(receivedException)
 
    # create dictionary to track index within policyExceptions
    exceptionIndex[(exception.src_ip, exception.topic)] = exceptionCount
    exceptionCount += 1

    exceptionReceived = True

 # initialize BPF - load source code
bpf = BPF(src_file="mqtt-topic-filter.c")
# load eBPF function of type BPF.SCHED_CLS into the kernel
mqtt_filter_function = bpf.load_func("mqtt_filter", BPF.SCHED_CLS)

# attach to allowed topics table
allowed_topics = bpf.get_table("allowed_topics")
# attach to policy exceptions table
exceptions = bpf.get_table("exceptions")
# attach callback for exceptions perf buffer
bpf["notifications"].open_perf_buffer(notifyPolicyException)
# setup ingress TC filter
ip = pyroute2.IPRoute()
ipdb = pyroute2.IPDB(nl=ip)
idx = ipdb.interfaces["eth0"].index
ip.tc("add", "clsact", idx)
ip.tc("add-filter", "bpf", idx, ":1", fd=mqtt_filter_function.fd, 
        name=mqtt_filter_function.name, parent="ffff:fff2", classid=1, 
        direct_action=True)

# load attached topic filter policy from json file
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

# store topic filter policy list
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
    global exceptionIndex, bootTime
    # update latestTimestamp, count, subException, pubException
    for k, v in exceptions.items():
        exceptionTime = datetime.fromtimestamp(int((v.latest_ts/1000000000) + bootTime))

        policyExceptionResponse['policyExceptions'][exceptionIndex[(k.src_ip, k.topic)]] \
            ['latestTimestamp'] = str(exceptionTime)
        policyExceptionResponse['policyExceptions'][exceptionIndex[(k.src_ip, k.topic)]] \
            ['count'] = v.count

        if v.pub_exception == 1:
            policyExceptionResponse['policyExceptions'][exceptionIndex[(k.src_ip, k.topic)]] \
                ['pubException'] = True
        else:
            policyExceptionResponse['policyExceptions'][exceptionIndex[(k.src_ip, k.topic)]] \
                ['pubException'] = False
        if v.sub_exception == 1:
            policyExceptionResponse['policyExceptions'][exceptionIndex[(k.src_ip, k.topic)]] \
                ['subException'] = True
        else:
            policyExceptionResponse['policyExceptions'][exceptionIndex[(k.src_ip, k.topic)]] \
                ['subException'] = False

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
        # notifyPolicyException() callback happens before perf_buffer_poll() returns
        #    poll() is blocking
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

# cleanup TC Filter
ip.tc("del", "clsact", idx)
ipdb.release()

sys.exit(0)
