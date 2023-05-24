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
    uint8_t type;          // 8 bits
    uint8_t code;          // 8 bits
    uint16_t checksum;     // 16 bits

    uint16_t id;    // identification field
    uint16_t seq;   // sequence number field
};



void printICMPHeader(struct icmp_header* icmp)
{
    cout << "ICMP Header:" << endl;
    cout << " Type: " << (int)icmp->type << endl;
    cout << " Code: " << (int)icmp->code << endl;
    cout << " Checksum: " << ntohs(icmp->checksum) << endl;
    cout << " Identifier: " << ntohs(icmp->id) << endl;
    cout << " Sequence Number: " << ntohs(icmp->seq) << endl<<endl;
}





#endif
