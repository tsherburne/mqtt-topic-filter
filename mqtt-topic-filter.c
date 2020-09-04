#include <net/sock.h>
#include <bcc/proto.h>

// TC_ACT_OK (0), will terminate the packet processing pipeline and
//           allows the packet to proceed
// TC_ACT_SHOT (2), will terminate the packet processing pipeline
//           and drops the packet

#define IP_TCP 6
#define ETH_HLEN 14
#define MAX_TOPIC_LEN 256

#define MQTT_PUB 3
#define MQTT_SUB 8

// allowed ip / topic pairs
struct Key {
    u32   src_ip;
    char  topic[MAX_TOPIC_LEN + 1];
};
struct Policy {
    int   allow_sub;
    int   allow_pub;
    int   rate;
};
BPF_HASH(allowed_topics, struct Key, struct Policy, 256);

// mqtt topic exceptions
struct Exception {
    u64     initial_ts;
    u64     latest_ts;
    u32     count;
    int     sub_exception;
    int     pub_exception;
};
BPF_HASH(exceptions, struct Key, struct Exception, 256);

// mqtt initial notification of exception
struct Notification {
    u64     initial_ts;
    u32     src_ip;
    u32     mqtt_type;
    char    topic[MAX_TOPIC_LEN + 1];
};
BPF_PERF_OUTPUT(notifications);

// mqtt current topic / notification - processed off stack
BPF_ARRAY(current_topic, struct Key, 1);
BPF_ARRAY(current_notification, struct Notification, 1);

int mqtt_filter(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    u8 packet_type = skb->pkt_type;
    // filter packets not for 'us'
    if (packet_type != 0) {
        return TC_ACT_OK;
    }
    // filter IPv4 (0x0800 ethertype)
    if (ethernet->type != 0x0800) {
        return TC_ACT_OK;
    }
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    // filter TCP packets (0x06 ipv4)
    if (ip->nextp != IP_TCP) {
        return TC_ACT_OK;
    }
    u32  ip_header_length = 0;
    ip_header_length = ip->hlen << 2;
    // shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    // filter mqtt packets
    if (tcp->dst_port != 1883) {
        return TC_ACT_OK;
    }

    u32  tcp_header_length = 0;
    tcp_header_length = tcp->offset << 2;

    //calculate payload offset and length
    u32  payload_offset = 0;
    u32  payload_length = 0;
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    payload_length = ip->tlen - ip_header_length - tcp_header_length;

    // fetch mqtt msg type
    u8 mqtt_msg_type = 0;
    mqtt_msg_type = load_byte(skb, payload_offset);
    mqtt_msg_type >>= 4;
    // filter mqtt publish
    if (mqtt_msg_type == MQTT_PUB) {
        // fetch variable length mqtt length
        int multiplier = 1;
        int mqtt_length_size = 0;
        int mqtt_packet_length = 0;
        u8 mqtt_partial_length = 0;
        for (int i = 1; i < 5; i++) {
            mqtt_partial_length = load_byte(skb, payload_offset + i);
            mqtt_packet_length += (mqtt_partial_length & 0x7f) * multiplier;
            multiplier *= 128;
            if ((mqtt_partial_length & 0x80) == 0) {
                mqtt_length_size = i;
                break;
            }
        }
        int payload_index = payload_offset + 1 + mqtt_length_size;
        u8 mqtt_topic_len_msb = 0;
        u8 mqtt_topic_len_lsb = 0;
        u16 mqtt_topic_len = 0;
        int mqtt_payload_len = 0;
        // load topic length bytes
        mqtt_topic_len_msb = load_byte(skb, payload_index);
        payload_index +=1;
        mqtt_topic_len_lsb = load_byte(skb, payload_index);
        payload_index +=1;

        // calculate topic & payload length
        mqtt_topic_len = (mqtt_topic_len_msb << 8) + mqtt_topic_len_lsb;
        mqtt_payload_len = mqtt_packet_length - 1 - mqtt_length_size - mqtt_topic_len;

        // off stack storage for current topic
        int zero = 0;
        struct Key *key = current_topic.lookup(&zero);
        if (key != NULL) {
            __builtin_memset(key, 0, sizeof(*key));
            key->src_ip = ip->src;

            if (mqtt_topic_len > 0 && mqtt_topic_len <= MAX_TOPIC_LEN) {
                // fetch topic
                u16 i = 0;
                for (i = 0; i < MAX_TOPIC_LEN; i++) {
                    key->topic[i] = load_byte(skb, payload_index + i);
                    if (i >= mqtt_topic_len - 1) {
                        break;
                    }
                }
                // check if publish is allowed
                struct Policy *policy;
                policy = allowed_topics.lookup(key);
                if (policy == NULL || policy->allow_pub == 0) {
                    // update exceptions
                    struct Exception *exception;
                    exception = exceptions.lookup(key);
                    if (exception == NULL) {
                        // first time exception
                        struct Exception new_exception = {};
                        __builtin_memset(&new_exception, 0, sizeof(new_exception));
                        new_exception.initial_ts = bpf_ktime_get_ns();
                        new_exception.latest_ts = bpf_ktime_get_ns();
                        new_exception.count = 1;
                        new_exception.pub_exception = 1;
                        exceptions.update(key, &new_exception);
                        // submit a notification using off stack storage
                        int zero = 0;
                        struct Notification *notification = current_notification.lookup(&zero);
                        if (notification != NULL) {
                            __builtin_memset(notification, 0, sizeof(*notification));
                            notification->initial_ts = bpf_ktime_get_ns();
                            notification->src_ip = ip->src;
                            notification->mqtt_type = MQTT_PUB;
                            __builtin_memcpy(notification->topic, key->topic, sizeof(notification->topic));
                            notifications.perf_submit(skb, notification, sizeof(*notification));
                        }
                    }
                    else {
                        // update exception timestamp and count
                        exception->latest_ts = bpf_ktime_get_ns();
                        exception->count += 1;
                        exception->pub_exception = 1;
                    }

                    return TC_ACT_SHOT;
                }
            }
            else
            {
                bpf_trace_printk("Invalid Topic Len: %d\n", mqtt_topic_len);
                return TC_ACT_SHOT;
            }
        }
    }
    return TC_ACT_OK;
}
