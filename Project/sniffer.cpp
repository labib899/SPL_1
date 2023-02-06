#include <iostream>
#include <pcap.h>
#include <string>
#include <map>


using namespace std;

#define F first
#define S second



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
    
    // using the first device for packet sniffing
    device=devices;
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
    
    // starting the packet capture loop
    pcap_loop(handle,-1,callback,NULL);
    
    // closing the device
    pcap_close(handle);
    
    // freeing the device list
    pcap_freealldevs(devices);
    
    return 0;
}




void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    map<string,int> protocols;
    // analyzing the packet
    for(int i=0;i<header->len;i++)
    {
        // extracting the protocol from the packet
        string protocol = "unknown";
        if(packet[i]==6)
        {
            protocol="TCP";
        }
        else if(packet[i]==17)
        {
            protocol="UDP";
        }

        // updating the count for the protocol
        protocols[protocol]++;
    }

    // printing the results
    cout<<"Protocols: "<<endl;
    for(const auto &p:protocols)
    {
        cout<<"  "<<p.F<<": "<<p.S<<endl;
    }
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
