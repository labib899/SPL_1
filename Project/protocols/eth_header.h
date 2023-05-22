#ifndef ETH_HEADER_H
#define ETH_HEADER_H


#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <map>




// Ethernet header structure 
struct eth_header 
{
    u_char ether_dhost[6] ; // destination host address 
    u_char ether_shost[6] ; // source host address 
    u_short ether_type ;  // protocol type (IP , ARP , RARP , etc ) 
};



#endif