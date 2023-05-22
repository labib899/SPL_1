#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H


#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <map>


using namespace std;


// ICMP header structure
struct icmp_header 
{
    uint8_t type;          // ICMP message type
    uint8_t code;          // Sub-code associated with the message
    uint16_t checksum;     // ICMP message checksum
    union 
    {
        struct 
        {
            uint16_t id;    // ICMP identification field
            uint16_t seq;   // ICMP sequence number field
        } echo; 
                    // Echo Request/Reply header
        uint32_t gateway;   // Gateway address

        struct 
        {
            uint16_t unused; // Unused field
            uint16_t mtu;    // Path MTU discovery maximum segment size
        } frag;             // Fragmentation header
    } un;
};



void printICMPHeader(struct icmp_header* icmp)
{
    //cout << "ICMP Header:" << endl;
    cout << " Type: " << (int)icmp->type << endl;
    cout << " Code: " << (int)icmp->code << endl;
    cout << " Checksum: " << ntohs(icmp->checksum) << endl;
    cout << " Identifier: " << ntohs(icmp->un.echo.id) << endl;
    cout << " Sequence Number: " << ntohs(icmp->un.echo.seq) << endl<<endl;
}





#endif