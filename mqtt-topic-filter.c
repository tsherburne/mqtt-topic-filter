#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP  6
#define ETH_HLEN 14
#define MAX_TOPIC_LEN 255

struct Key {
    u32   src_ip;
    char  topic[MAX_TOPIC_LEN + 1];
};
struct Leaf {
    int   allow_sub;
    int   allow_pub;
    int   rate;
};
// allowed ip / topic pairs
BPF_HASH(allowed_topics, struct Key, struct Leaf, 256);

int mqtt_filter(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    u8 packet_type = skb->pkt_type;
    // filter packets not for 'us'
    if (packet_type != 0) {
        return -1;
    }
    // filter IPv4 (0x0800 ethertype) 
    if (ethernet->type != 0x0800) {
        return -1;
    }
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    // filter TCP packets (0x06 ipv4)
    if (ip->nextp != IP_TCP) {
        return -1;
    }
    u32  ip_header_length = 0;
    ip_header_length = ip->hlen << 2;
    // shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    // filter mqtt packets
    if (tcp->dst_port != 1883) {
        return -1;
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
    if (mqtt_msg_type == 3) {
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

        // initialized lookup key
        struct Key key;
        __builtin_memset(&key, 0, sizeof(key));
        key.src_ip = ip->src;
        //char mqtt_topic[MAX_TOPIC_LEN + 1];
        if (mqtt_topic_len > 0 && mqtt_topic_len <= MAX_TOPIC_LEN) {
            // fetch topic
            u16 i = 0;
            for (i = 0; i < MAX_TOPIC_LEN; i++) {
                key.topic[i] = load_byte(skb, payload_index + i);
                if (i >= mqtt_topic_len) {
                    break;
                }
            }
            // null terminate 
            key.topic[i] = '\0';
            bpf_trace_printk("MQTT: %u: %s : %d\n", key.src_ip, key.topic, mqtt_payload_len);

            // check if publish is allowed
            struct Leaf *leaf;
            leaf = allowed_topics.lookup(&key);
            if (leaf != NULL) {
                bpf_trace_printk("FOUND: %d : %d\n", leaf->allow_sub, leaf->allow_pub);
            }
            else {
                bpf_trace_printk("Key not found\n");
            }          
        }
        else
        {
            bpf_trace_printk("Invalid Topic Len: %d\n", mqtt_topic_len);
        }
    }  
    // drop the packet
    return -1;
}