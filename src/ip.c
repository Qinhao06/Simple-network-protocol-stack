#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    if(buf->len < sizeof(ip_hdr_t) ){
        fprintf(stderr, "the length of ip error");
        return ;  }
    ip_hdr_t* pkg = (ip_hdr_t*)(buf->data);
    if(pkg->version != IP_VERSION_4 ||(swap16(pkg->total_len16) > buf->len)){
        fprintf(stderr, "the head of ip error\n");
        return ;
    }
    
    uint16_t checksum = pkg->hdr_checksum16;
    pkg->hdr_checksum16 = 0;
    uint16_t cheaksum_result = checksum16((uint16_t*)(pkg), sizeof(ip_hdr_t));
    if(swap16(cheaksum_result) != checksum) {
        fprintf(stderr, "the checksum of ip error\n");
        return;
    }
    pkg->hdr_checksum16 = checksum;
    if(memcmp(pkg->dst_ip, net_if_ip, NET_IP_LEN) != 0){
        return;
    }
    if(buf->len > swap16(pkg->total_len16)){
        buf_remove_padding(buf, buf->len - swap16(pkg->total_len16));
    }
    if(pkg->protocol != NET_PROTOCOL_UDP && pkg->protocol != NET_PROTOCOL_ICMP){
        icmp_unreachable(buf, pkg->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    buf_remove_header(buf, sizeof(ip_hdr_t));
    net_in(buf, pkg->protocol, pkg->src_ip); 
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
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t* pkg = (ip_hdr_t*)buf->data;
    pkg->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    pkg->version = IP_VERSION_4;
    pkg->tos = 0;
    pkg->total_len16 = swap16(buf->len);
    pkg->id16 = swap16(id);
    uint16_t ip_flag_fragment = (offset & 0x1fff);
    if(mf == 1){
        ip_flag_fragment |= IP_MORE_FRAGMENT;
        
    }
    pkg->flags_fragment16 = swap16(ip_flag_fragment);
    pkg->ttl = 64;
    pkg->protocol = protocol;
    memcpy(pkg->dst_ip, ip, NET_IP_LEN);
    memcpy(pkg->src_ip, net_if_ip, NET_IP_LEN);
    pkg->hdr_checksum16 = 0;
    pkg->hdr_checksum16 = swap16(checksum16((uint16_t*)pkg, sizeof(ip_hdr_t)));
    arp_out(buf, ip);


     
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */

int id = -1;

void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    id++;
    size_t pkg_len = 1500 - sizeof(ip_hdr_t);
    int cnt =0;
    buf_t ip_buf;
    for(cnt = 0; pkg_len * (cnt+1) < buf->len; cnt++ ){
        buf_init(&ip_buf, pkg_len);
        memcpy(ip_buf.data , buf->data + cnt * pkg_len, pkg_len);
        ip_fragment_out(&ip_buf, ip, protocol, id, cnt * (pkg_len>>3), 1);
    }
    buf_init(&ip_buf, buf->len - cnt * pkg_len);
    memcpy(ip_buf.data, buf->data + cnt * pkg_len, buf->len - cnt * pkg_len);
    ip_fragment_out(&ip_buf, ip, protocol, id, cnt * (pkg_len >> 3) , 0);

}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}