#ifndef TCP_HEADER_H
#define TCP_HEADER_H


#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <map>




// TCP header structure (connection oriented)
struct tcp_header {
    unsigned short int source_port; // 16 bits
    unsigned short int dest_port; // 16 bits
    unsigned int sequence_num; // 32 bits
    unsigned int ack_num; // 32 bits
    unsigned char header_len : 4; // 4 bits
    unsigned char reserved : 6; // 6 bits
    unsigned char urg_flag : 1; // urgent pointer field is significant
    unsigned char ack_flag : 1; // acknowledgement field is significant
    unsigned char psh_flag : 1; // push function
    unsigned char rst_flag : 1; // reset the connection
    unsigned char syn_flag : 1; // synchronize sequence numbers
    unsigned char fin_flag : 1; // no more data from sender
    unsigned short int window_size; // 16 bits
    unsigned short int checksum; // 16 bits
    unsigned short int urgent_ptr; // 16 bits
};




#endif