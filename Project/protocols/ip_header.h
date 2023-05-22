#ifndef IP_HEADER_H
#define IP_HEADER_H


#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <map>


using namespace std;



// IP header structure
struct ip_header
{	
    unsigned char  header_len : 4;
    unsigned char  version : 4;	
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



void printIPHeader(struct ip_header* ip)
{
    //cout<<"From : "<<inet_ntoa(ip->source)<<endl;
    //cout<<"To : "<<inet_ntoa(ip->destination)<<endl;


    // printing the IP header fields
    cout << "IP header:" << endl;
    cout << "  Version: " << (int)(ip->version) << endl;
    cout << "  Header length: " << (int)ip->header_len * 4 << " bytes" << endl;
    cout << "  Type of service: " << (int)ip->tos << endl;
    cout << "  Total length: " << ntohs(ip->total_length) <<" bytes" << endl;
    cout << "  Identification: " << ntohs(ip->id) << endl;
    cout << "  More fragments: " << (int)ip->more_fragment << endl;
    cout << "  Don't fragments " << (int)ip->dont_fragment << endl;
    cout << "  Fragmentation offset: " << (int)((ntohs(ip->frag_offset) & 0x1FFF) * 8) << " bytes" << endl;
    cout << "  Time to live: " << (int)ip->time_to_live << endl;
    cout << "  Protocol: " << (int)ip->protocol << endl;
    cout << "  Checksum: " << ntohs(ip->checksum) << endl;
    cout << "  Source address: " << inet_ntoa(ip->source) << endl;
    cout << "  Destination address: " << inet_ntoa(ip->destination) << endl << endl;

    // printing the payload
    const u_char *payload = (const u_char*)ip + ip->header_len * 4;
    int payload_len = ntohs(ip->total_length) - ip->header_len * 4;
    if (payload_len > 0) 
    {
        cout << "Payload:" << endl;
        for (int i = 0; i < payload_len; i++) 
        {
            printf("%02x ", payload[i]);
            if ((i + 1) % 16 == 0) 
            {
                cout << endl;
            }
        }
        cout << endl << endl << endl;
    }
}


#endif