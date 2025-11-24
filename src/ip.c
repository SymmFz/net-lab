#include "ip.h"

#include "arp.h"
#include "buf.h"
#include "config.h"
#include "icmp.h"
#include "net.h"
#include "utils.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }

    // TODO: impl ipv6
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if (ip_hdr->version != IP_VERSION_4 ||
        swap16(ip_hdr->total_len16) > buf->len) {
        return;
    }

    uint16_t hdr_checksum16 = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    if (checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE) != hdr_checksum16) {
        return;
    }
    ip_hdr->hdr_checksum16 = hdr_checksum16;

    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;
    }

    if (buf->len > swap16(ip_hdr->total_len16)) {
        if (buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16)) != 0) {
            return;
        }
    }

    if (buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE) != 0) {
        return;
    }

    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) != 0) {
        buf_add_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    if (buf_add_header(buf, sizeof(ip_hdr_t)) != 0) {
        return;
    }

    // header
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / 4;
    ip_hdr->version = 4;  // TODO: Ipv6
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);

    uint16_t flags_fragment = offset;
    flags_fragment = (mf) ? (IP_MORE_FRAGMENT | flags_fragment) : flags_fragment;
    ip_hdr->flags_fragment16 = swap16(flags_fragment);

    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // Checksum
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));

    // send
    arp_out(buf, ip);
}

static uint16_t ip_id = 0;
static int id_generator() {
    return ip_id++;  // overflow is fine.
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    uint16_t ip_header_len = sizeof(ip_hdr_t);
    uint16_t max_payload_len = ETHERNET_MAX_TRANSPORT_UNIT - ip_header_len;  // 1480

    if (buf->len <= max_payload_len) {
        ip_fragment_out(buf, ip, protocol, id_generator(), 0, 0);
        return;
    } else {
        // fragment
        uint16_t fragment_data_size = max_payload_len / 8 * 8;
        uint16_t offset = 0;
        uint8_t *data_ptr = buf->data;
        size_t remaining_len = buf->len;
        int id = id_generator();

        while (remaining_len > 0) {
            buf_t fragment_buf;

            uint16_t current_frag_len = (remaining_len > fragment_data_size) ? fragment_data_size : remaining_len;

            buf_init(&fragment_buf, current_frag_len);
            memcpy(fragment_buf.data, data_ptr, current_frag_len);

            data_ptr += current_frag_len;
            remaining_len -= current_frag_len;

            int mf_flag = (remaining_len > 0) ? 1 : 0;

            ip_fragment_out(&fragment_buf, ip, protocol, id, offset, mf_flag);

            offset += current_frag_len / 8;
        }
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}
