#ifndef UDP_HEADER_H
#define UDP_HEADER_H


#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <map>



using namespace std;



// UDP header structure (connectionless)
struct udp_header 
{
    unsigned short int source_port; // 2 bytes
    unsigned short int dest_port; // 2 bytes
    unsigned short int length; // 2 bytes
    unsigned short int checksum; // 2 bytes
};



void printUDPHeader(struct udp_header* udp)
{
    // printing the UDP header fields
    cout << "UDP header:" << endl;
    cout << "  Source port: " << ntohs(udp->source_port) << endl;
    cout << "  Destination port: " << ntohs(udp->dest_port) << endl;
    cout << "  Length: " << ntohs(udp->length) << endl;
    cout << "  Checksum: " << ntohs(udp->checksum) << endl<<endl;
}




#endif