#include <iostream>
#include <pcap.h>
#include <string>
#include <map>
#include "tcp_header.h"
#include "udp_header.h"
#include "icmp_header.h"
#include "ip_header.h"


using namespace std;


#define ff first
#define ss second




void callback(u_char *user,const struct pcap_pkthdr *header,const u_char *packet);





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
    
    /*cout<<"Enter the number of packets to be captured: ";
    int numOfPackets;
    cin>>numOfPackets;
    cout<<endl;*/
    // starting the packet capture loop 
    // -1 instead of numOfPackets to capture indefinitely
    pcap_loop(handle,-1,callback,NULL);
    
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
void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) 
{   
    cout<<"Packet Length: "<<header->len<<endl;

    // display the time stamp of the packet
    cout << "Time stamp: " << header->ts.tv_sec << "." << header->ts.tv_usec << endl;

    map<string,int> protocols;


    // for counting dropped packets
    int drop_count = 0;
    
    if (header->len != header->caplen)
    {
        drop_count++;
    }
    // analyzing the packet
    for(int i=0;i<header->len;i++)
    {
        // extracting the protocol from the packet
        string protocol = "Unknown";
        if(packet[i]==6)
        {
            protocol="TCP";
            // extracting the TCP header from the packet
            const struct tcp_header* tcp = (const struct tcp_header*)(packet + i + sizeof(uint8_t));
            // printing the TCP header fields
            cout << "TCP header:" << endl;
            cout << "  Source port: " << tcp->source_port << endl;
            cout << "  Destination port: " << tcp->dest_port << endl;  
            cout << "  Sequence number: " << tcp->sequence_num << endl;
            cout << "  Acknowledgement number: " << tcp->ack_num << endl;
            cout << "  Header length: " << tcp->header_len << endl;
            cout << "  Urgent pointer flag: " << tcp->urg_flag << endl;
            cout << "  Acknowledgement flag: " << tcp->ack_flag << endl;
            cout << "  Push flag: " << tcp->psh_flag << endl;
            cout << "  Reset flag: " << tcp->rst_flag << endl;
            cout << "  Synchronize flag: " << tcp->syn_flag << endl;
            cout << "  Finish flag: " << tcp->fin_flag << endl;
            cout << "  Window size: " << tcp->window_size << endl;
            cout << "  Checksum: " << tcp->checksum << endl;
            cout << "  Urgent pointer: " << tcp->urgent_ptr << endl<<endl;


            // printing the payload
            const u_char *payload = packet + i + sizeof(uint8_t) + tcp->header_len*4;
            // point to the location in memory where payload data starts
            int payload_len = header->len - (i + sizeof(uint8_t) + tcp->header_len*4);
            // payload len= header len - size of the header
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
        else if(packet[i]==17)
        {
            protocol="UDP";
            // extracting the UDP header from the packet
            const struct udp_header* udp = (const struct udp_header*)(packet + i + sizeof(uint8_t));
            // printing the UDP header fields
            cout << "UDP header:" << endl;
            cout << "  Source port: " << udp->source_port << endl;
            cout << "  Destination port: " << udp->dest_port << endl;
            cout << "  Length: " << udp->length << endl;
            cout << "  Checksum: " << udp->checksum << endl<<endl;


            // printing the payload
            const u_char *payload = packet + i + sizeof(uint8_t) + sizeof(struct udp_header);
            int payload_len = header->len - (i + sizeof(uint8_t) + sizeof(struct udp_header));
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

        else if(packet[i]==1) 
        {
            protocol="ICMP";
            // extracting the ICMP header from the packet
            const struct icmp_header* icmp = (const struct icmp_header*)(packet + i + sizeof(uint8_t));
            //printing the ICMP header fields
            cout << "ICMP Header:" << endl;
            cout << " Type: " << (int)icmp->type << endl;
            cout << " Code: " << (int)icmp->code << endl;
            cout << " Checksum: " << ntohs(icmp->checksum) << endl;
            cout << " Identifier: " << ntohs(icmp->un.echo.id) << endl;
            cout << " Sequence Number: " << ntohs(icmp->un.echo.seq) << endl<<endl;


            // printing the payload
            const u_char *payload = packet + i + sizeof(uint8_t) + sizeof(struct icmp_header);
            int payload_len = header->len - (i + sizeof(uint8_t) + sizeof(struct icmp_header));
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

        else if(packet[i]==4) // checking for IP protocol
        {
            // extracting the IP protocol from the packet
            const struct ip_header* ip = (const struct ip_header*)(packet + i + sizeof(uint8_t));
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
            const u_char *payload = packet + i + sizeof(uint8_t) + sizeof(ip_header);
            int payload_len = header->len - (i + sizeof(uint8_t) + sizeof(ip_header));
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
        // updating the count for the protocol
        protocols[protocol]++;
    }

    // printing the results
    cout<<"Protocols: "<<endl;
    for(const auto &p:protocols)
    {
        cout<<"  "<<p.ff<<": "<<p.ss<<endl;
    }

    // display dropped packet count
    cout << "Dropped packets: " << drop_count << endl<<endl<<endl;
}








// g++ sniffer.cpp -lpcap
