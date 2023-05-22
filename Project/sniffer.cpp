#include <iostream>
#include <pcap.h>
#include <math.h>
#include <string>
#include <sstream>
#include <map>
#include <iterator>
#include "protocols/eth_header.h"
#include "protocols/tcp_header.h"
#include "protocols/udp_header.h"
#include "protocols/icmp_header.h"
#include "protocols/ip_header.h"
#include "protocols/http_parser.h"



using namespace std;


#define ff first
#define ss second




// to keep track lost packets
map<uint,int> ack_map;



void got_packet(u_char *user,const struct pcap_pkthdr *header,const u_char *packet);





int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices, *device;
    
    // finding all available network devices
    if (pcap_findalldevs(&devices,errbuf)==-1)
    {
        cout<< "Couldn't find any device: "<<errbuf<< endl;
        return -1;
    }
    
    // using the first device for packet sniffing (en0)
    device=devices;
    cout<<"Capturing packets with "<<device->name<<"..."<<endl;

    if(device==NULL)
    {
        cout<<"Couldn't find any device"<<endl;
        return -1;
    }
    // opening the device for packet sniffing
    pcap_t *handle=pcap_open_live(device->name,BUFSIZ,1,1000,errbuf);
    if(handle==NULL)
    {
        cout<<"Couldn't open device "<<device->name<<": "<<errbuf<<endl;
        return -1;
    }
    
    /*
    cout<<"Enter the number of packets to be captured: ";
    int numOfPackets;
    cin>>numOfPackets;
    cout<<endl;
    */
    // starting the packet capture loop 
    // -1 instead of numOfPackets to capture indefinitely
    pcap_loop(handle,-1,got_packet,NULL);

    
    // closing the device
    pcap_close(handle);

    
    // freeing the device list
    pcap_freealldevs(devices);


    
    return 0;
}



/*  
user = user defined data structure (not used), pcap_pkthdr = info about the packet,
packet = pointer to the packet data
*/
void got_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) 
{   
    struct eth_header* eth=(struct eth_header*) packet;
    //packet+=sizeof(eth_header); // jump over ethernet header (14 bytes)


    // 0x0800 is IP type
    if(ntohs(eth->ether_type)==0x0800)    
    {
        struct ip_header *ip=(struct ip_header*) (packet+sizeof(eth_header));
        printIPHeader(ip);
        //packet+=sizeof(ip_header); // jump over ip header

        int ip_header_size = (int)ip->header_len * 4;
        if(ip_header_size<20 || ip_header_size>60)
        {
            cout << "Invalid IP Header" << endl;
            return;
        }



        // determining protocols
        if(ip->protocol==6) // IPPROTO_TCP
        {   
            // extracting TCP header from the packet
            struct tcp_header* tcp = (struct tcp_header*) (packet+sizeof(eth_header)+sizeof(ip_header));
            //packet+=sizeof(tcp_header); // jump over tcp header


            if(sizeof(tcp_header)<20 || sizeof(tcp_header)>60)
            {
                cout << "Invalid TCP Header" << endl;
                return;
            }


            // determine if the packet is part of an HTTP connection
            bool isHTTP = (tcp->source_port == htons(80) || tcp->dest_port == htons(80));

            if (isHTTP) 
            {   
                // Extract the HTTP payload
                const u_char* httpPayload = packet+sizeof(eth_header)+sizeof(ip_header)+sizeof(tcp_header);
                int httpPayloadLen = header->caplen - (sizeof(eth_header)+sizeof(ip_header)+sizeof(tcp_header));

                // Parse the HTTP request or response
                if (tcp->dest_port == htons(80)) 
                {
                    HttpRequest request = parseHttpRequest(string(httpPayload,httpPayload + httpPayloadLen));
                    printHttpRequest(request);
                } 
                else 
                {
                    HttpResponse response = parseHttpResponse(string(httpPayload,httpPayload + httpPayloadLen));
                    printHttpResponse(response);
                }
                
                // display the HTTP payload
                /*
                cout << "HTTP Payload:" << endl;
                for (int i = 0; i < httpPayloadLen; i++) 
                {
                    printf("%c", httpPayload[i]);
                }
                cout << endl << endl;
                */
            }

            else
            {   
                // printing TCP header fields
                printTCPHeader(tcp);

                // Printing TCP payload
                const u_char* payload = packet;
                int payload_len = ntohs(ip->total_length) - sizeof(ip_header) - sizeof(tcp_header);
                
                if (payload_len > 0) 
                {
                    cout << "Payload:" << endl;
                    for (int j = 0; j < payload_len; j++) 
                    {
                        printf("%02x ", payload[j]);
                        if ((j + 1) % 16 == 0) 
                        {
                            cout << endl;
                        }
                    }
                    cout << endl << endl << endl;
                }

                // updating ack_map
                uint ACK=ntohl(tcp->ack_num);

                // checking triple duplicate ACKs
                if(ack_map[ACK]>3)
                {
                    cout<<"Triple duplicate ACKs detected. Packet loss may have occurred"<<endl<<endl<<endl;
                    ack_map[ACK]=0; // resetting
                }
            }
        }


        else if(ip->protocol==17) // IPPROTO_UDP
        {   
            // extracting the UDP header from the packet
            struct udp_header* udp = (struct udp_header*) (packet+sizeof(eth_header)+sizeof(ip_header));
            //packet+=sizeof(udp_header); // jump over udp header


            // printing the UDP header fields
            printUDPHeader(udp);


            // Printing UDP payload
            const u_char* payload = packet+sizeof(eth_header)+sizeof(ip_header)+sizeof(udp_header);
            int payload_len = ntohs(udp->length) - sizeof(udp_header); 


            if (payload_len > 0) 
            {
                cout << "Payload:" << endl;
                for (int j = 0; j < payload_len; j++) 
                {
                    printf("%02x ", payload[j]);
                    if ((j + 1) % 16 == 0) 
                    {
                        cout << endl;
                    }
                }
                cout << endl<<endl<<endl;
            }
        }



        else if(ip->protocol==1) // IPPROTO_ICMP
        {   
            // extracting the ICMP header from the packet
            struct icmp_header* icmp = (struct icmp_header*) (packet+sizeof(eth_header)+sizeof(ip_header));
            //packet+=sizeof(icmp_header);


            //printing the ICMP header fields
            printICMPHeader(icmp);


            // Printing ICMP payload
            const u_char* payload = packet+sizeof(eth_header)+sizeof(ip_header)+sizeof(icmp_header);
            int payload_len = ntohs(ip->total_length) - sizeof(ip_header) - sizeof(icmp_header);
            
            if (payload_len > 0) 
            {
                cout << "Payload:" << endl;
                for (int j = 0; j < payload_len; j++) 
                {
                    printf("%02x ", payload[j]);
                    if ((j + 1) % 16 == 0) 
                    {
                        cout << endl;
                    }
                }
                cout << endl<<endl<<endl;
            }
        }

        // printing packet length
        int packet_length = header->caplen;
        cout << "Packet Length: " << packet_length << " bytes" << endl;

        // printing timestamp
        cout << "Packet timestamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << endl<<endl<<endl;

    }

}






// g++ sniffer.cpp -lpcap
