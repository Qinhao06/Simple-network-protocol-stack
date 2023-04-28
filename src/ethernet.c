#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    if(buf->len < sizeof(ether_hdr_t)){
        fprintf(stderr, "Error in ethernet_in:%zu\n", buf->len);
        return ;
    }

    ether_hdr_t* hdr = (ether_hdr_t*)buf->data;
    uint8_t* src = hdr->src;
    if(buf_remove_header(buf, sizeof(ether_hdr_t))){
        return ;
    }
    

    net_in(buf, swap16(hdr->protocol16), src);

}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    if(buf->len < 46){
        if(buf_add_padding(buf, 46 - buf->len) != 0){
            return;
        }
    }
    if(buf_add_header(buf, sizeof(ether_hdr_t))){
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t*) buf->data;
    for(int i =0 ;i < NET_MAC_LEN; i++){
        (hdr->dst)[i] = mac[i]; 
    }
    for(int i = 0;i < NET_MAC_LEN;i++){
        (hdr->src)[i] = net_if_mac[i];
    }
    hdr->protocol16 = swap16(protocol);
    driver_send(buf);


}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
