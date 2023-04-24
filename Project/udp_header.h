#ifndef UDP_HEADER_H
#define UDP_HEADER_H


#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <map>




// UDP header structure (connectionless)
struct udp_header {
    unsigned short int source_port; // 2 bytes
    unsigned short int dest_port; // 2 bytes
    unsigned short int length; // 2 bytes
    unsigned short int checksum; // 2 bytes
};



#endif