#ifndef HEADER_H
#define HEADER_H

#endif // HEADER_H

//ethernet header
struct ethernet_hdr
{
    u_int8_t ether_dst_host[6];  //destination mac address )
    u_int8_t ether_src_host[6];  //source mac address
    u_int16_t ether_type;  //L3 protocol info
};

//ip header
struct ip_hdr
{
    u_int8_t IHL:4;  //IP Header Length(/4), HBO(little endian) -> last 4bits
    u_int8_t version:4;  //IPv4 or IPv6, first 4bits
    u_int8_t service;  //service quality
    u_int16_t total_length;  //ip total length
    u_int16_t identification;  //unique number of segmented packet
    u_int16_t flag_offset;  //segmented packet's number = location in origin data
    u_int8_t TTL;  //time to live
    u_int8_t protocol;  //L4 protocol info
    u_int16_t header_checksum;  //error detection
    u_int8_t ip_src_host[4];  //source ip address
    u_int8_t ip_dst_host[4];  //destination ip address
};

//tcp header
struct tcp_hdr
{
    u_int16_t src_port;  //source port number
    u_int16_t dst_port;  //destination port number
    u_int8_t sequence_number[4];  //order of data
    u_int8_t ack_number[4];  //number of the next data
    u_int16_t flags:16;  //flag
    u_int8_t header_length:4;  //tcp header length
    u_int16_t window;  //size of the tcp receive buffer on the receiving side
    u_int16_t checksum;  //error detection
    u_int16_t urgent_point;  //end of urgent data
};

//tcp payload(data)
struct payload
{
    u_int8_t data[20];  //max 20byte
};
