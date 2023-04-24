#ifndef IP_HEADER_H
#define IP_HEADER_H


#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <map>



// IP header structure
struct ip_header
{	
    unsigned char  version : 4;	
    unsigned char  header_len : 4;
    unsigned char  tos;					 
    unsigned short total_length;		
    unsigned short id;					
    unsigned char  frag_offset : 5;	
    unsigned char  more_fragment : 1;	
    unsigned char  dont_fragment : 1;	
    unsigned char  reserved_zero : 1;	
    unsigned char  frag_offset1;		
    unsigned char  time_to_live;					
    unsigned char  protocol;			
    unsigned short checksum;			
    in_addr        source;				
    in_addr        destination;			
};



#endif