#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // TO-DO
    uint16_t len = buf->len;
    udp_hdr_t* udp_hdr = (udp_hdr_t*) buf->data;
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    udp_peso_hdr_t hdr;

    memcpy(&hdr, buf->data, sizeof(udp_peso_hdr_t));

    udp_peso_hdr_t* pkg = (udp_peso_hdr_t*)buf->data;

    memcpy(pkg->src_ip, src_ip, NET_IP_LEN);
    memcpy(pkg->dst_ip, dst_ip, NET_IP_LEN);

    pkg->placeholder = 0;
    pkg->protocol = NET_PROTOCOL_UDP;
    pkg->total_len16 = swap16(len);

    // 查看包数据
    //   printf("ip: %x , %x\n", *(pkg->src_ip+3), *(pkg->dst_ip+3));
    // printf("length: %x \n", pkg->total_len16);
    // printf("checksum: %x\n", udp_hdr->checksum16);
    // for(int i = 0; i< 40 ; i++){
    //     printf(" %hhx ", *((uint8_t*)pkg+ i));
    // }

    udp_hdr->checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t*)pkg, buf->len % 2 == 0 ? buf->len : buf->len+1);
    udp_hdr->checksum16 = swap16(checksum);
    memcpy(pkg, &hdr, sizeof(udp_peso_hdr_t));
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    return checksum; 

}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    if(buf->len < sizeof(udp_hdr_t)){
        return;
    }
    udp_hdr_t* pkg = (udp_hdr_t*) buf->data;
    uint16_t checksum = pkg->checksum16;
    pkg->checksum16 = 0;
    if(checksum != swap16(udp_checksum(buf, src_ip, net_if_ip))){
        return;
    }    
    pkg->checksum16 = checksum;
    uint16_t dst_port = swap16(pkg->dst_port16);
    udp_handler_t* handler = map_get(&udp_table, &dst_port);
    if(handler == NULL){
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, net_if_ip, ICMP_CODE_PORT_UNREACH);

    }
    else{
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(pkg->src_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t* pkg = (udp_hdr_t*) buf->data;
    pkg->dst_port16 = swap16(dst_port);
    pkg->src_port16 = swap16(src_port);
    pkg->total_len16 = swap16(buf->len);
    pkg->checksum16 = 0;
    pkg->checksum16 = swap16(udp_checksum(buf, net_if_ip, dst_ip));
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}
