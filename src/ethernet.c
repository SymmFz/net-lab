#include "ethernet.h"

#include "arp.h"
#include "buf.h"
#include "config.h"
#include "driver.h"
#include "net.h"
#include "utils.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // Step1 数据长度检查
    if (buf->len < sizeof(ether_hdr_t)) {
        return;
    }

    // 获取以太网包头
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    if (memcmp(hdr->dst, net_if_mac, NET_MAC_LEN) != 0 &&
        memcmp(hdr->dst, ether_broadcast_mac, NET_MAC_LEN) != 0) {
        return;
    }
    uint16_t protocol = swap16(hdr->protocol16);
    uint8_t src_mac_addr[NET_MAC_LEN];
    memcpy(src_mac_addr, hdr->src, NET_MAC_LEN);

    // Step2 移除以太网包头
    if (buf_remove_header(buf, sizeof(ether_hdr_t)) != 0) {
        return;
    }

    // Step3 想上层传递数据包
    net_in(buf, protocol, src_mac_addr);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // Step1 数据长度检查与填充
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        if (buf_add_padding(buf, ETHERNET_MIN_TRANSPORT_UNIT- buf->len) != 0) {
            return;
        }
    }

    // Step2 添加以太网包头
    if (buf_add_header(buf, sizeof(ether_hdr_t)) != 0) {
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // Step3 填写源和目的 MAC 地址，以及协议类型
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);

    // Step4 发送数据帧
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
