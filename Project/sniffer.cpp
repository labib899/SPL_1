#include <iostream>
#include <pcap.h>
#include <string>
#include <map>


using namespace std;

#define ff first
#define ss second



void callback(u_char *user,const struct pcap_pkthdr *header,const u_char *packet);
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

// UDP header structure (connectionless)
struct udp_header {
    unsigned short int source_port; // 2 bytes
    unsigned short int dest_port; // 2 bytes
    unsigned short int length; // 2 bytes
    unsigned short int checksum; // 2 bytes
};






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
    
    cout<<"Enter the number of packets to be captured: ";
    int numOfPackets;
    cin>>numOfPackets;
    cout<<endl;
    // starting the packet capture loop 
    // -1 instead of numOfPackets to capture indefinitely
    pcap_loop(handle,numOfPackets,callback,NULL);
    
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
    map<string,int> protocols;
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
    cout<<endl<<endl;
}







/*
 This code uses the pcap library to open a network device for packet
 sniffing and register a callback function that will be called for each
 packet received. The callback function analyzes the packet and updates a
 map that tracks the number of packets for each protocol. The final
 results are printed after all packets have been processed.
 
 the pcap_findalldevs function is used to find all available network
 devices. The first device is then used for packet sniffing.
 Additionally, the device list returned by pcap_findalldevs needs to be
 freed using the pcap_freealldevs function after it is no longer needed.
 */

// g++ -std=c++2a sniffer.cpp -lpcap

