#include "arp.h"

#include "buf.h"
#include "config.h"
#include "ethernet.h"
#include "map.h"
#include "net.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    // Step1 初始化缓冲区
    buf_t txbuf;
    if (buf_init(&txbuf, sizeof(arp_pkt_t)) != 0) {
        fprintf(stderr, "Error in arp_req: buf init failed.");
        return;
    }

    // Step2 填写 ARP 报头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    arp_pkt->hw_type16 = swap16(ARP_HW_ETHER);
    arp_pkt->pro_type16 = swap16(NET_PROTOCOL_IP);
    arp_pkt->hw_len = NET_MAC_LEN;
    arp_pkt->pro_len = NET_IP_LEN;

    memcpy(arp_pkt->sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(arp_pkt->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    memset(arp_pkt->target_mac, 0, NET_MAC_LEN);

    // Step3 设置操作类型
    arp_pkt->opcode16 = swap16(ARP_REQUEST);

    // Step4 发送 ARP 报文
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    // Step1 初始化缓冲区
    buf_t txbuf;
    if (buf_init(&txbuf, sizeof(arp_pkt_t)) != 0) {
        fprintf(stderr, "Error in arp_req: buf init failed.");
        return;
    }

    // Step2 填写 ARP 报头首部
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    arp_pkt->hw_type16 = swap16(ARP_HW_ETHER);
    arp_pkt->pro_type16 = swap16(NET_PROTOCOL_IP);
    arp_pkt->hw_len = NET_MAC_LEN;
    arp_pkt->pro_len = NET_IP_LEN;

    arp_pkt->opcode16 = swap16(ARP_REPLY);

    memcpy(arp_pkt->sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(arp_pkt->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);

    // Step3 发送 ARP 报文
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    // Step1 检查数据长度
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }

    // Step2 报头检查
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    if (arp_pkt->hw_type16 != swap16(ARP_HW_ETHER) ||
        arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP) ||
        arp_pkt->hw_len != NET_MAC_LEN ||
        arp_pkt->pro_len != NET_IP_LEN ||
        (arp_pkt->opcode16 != swap16(ARP_REQUEST) && arp_pkt->opcode16 != swap16(ARP_REPLY))) {
        return;
    }

    // Step3 更新 ARP 表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);

    // Step4 查看缓存情况
    buf_t *txbuf = map_get(&arp_buf, arp_pkt->sender_ip);
    if (txbuf != NULL) {
        ethernet_out(txbuf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        if (arp_pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO

    // Step1 查找 ARP 表
    uint8_t *target_mac = map_get(&arp_table, ip);
    if (target_mac != NULL) {
        // Step2 找到对应的 MAC 地址，直接发送数据包
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
        return;
    }

    // Step3 未找到对应 MAC 地址，若缓冲区有数据包，则丢弃当前数据包
    //       若缓冲区没有数据包，将当前数据包放入缓冲区，并发出 arp 请求
    // TODO: 实现更长的缓冲区，实现不丢包
    buf_t *txbuf = map_get(&arp_buf, ip);
    if (txbuf != NULL) {
        // abort
    } else {
        map_set(&arp_buf, ip, buf);
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}
