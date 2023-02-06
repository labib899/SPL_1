#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>


using namespace std;


// function to display the list of network interfaces
void list();
void dump_addresses(pcap_addr_t *addresses);



int main()
{
    list();
    return 0;
}



void list()
{
    pcap_if_t *device;
    pcap_if_t *interface;
    char err[PCAP_ERRBUF_SIZE];
    
    if(pcap_findalldevs(&interface,err)==-1)
    {
        cout<<err<<endl;
        return;
    }
    else
    {
        cout<<"List of network interfaces:"<<endl<<endl;
        int i=1;
        for(device=interface;device!=NULL;device=device->next,i++)
        {
            printf("%d: %s: \n",i,device->name);
            dump_addresses(device->addresses);
            printf("\n");
        }
        return;
    }
}


void dump_addresses(pcap_addr_t *addresses)
{
    pcap_addr_t *addr=addresses;
    while(addr)
    {
        struct sockaddr_in *ip=(struct sockaddr_in *)addr->addr;
        struct sockaddr_in *nm=(struct sockaddr_in *)addr->netmask;
        if(ip && nm)
        {
            cout<<"\tIP Address: "<<inet_ntoa(ip->sin_addr)<<endl;
            cout<<"\tSubnet Mask: "<<inet_ntoa(nm->sin_addr)<<endl;
        }
        addr=addr->next;
    }
}


// g++ list.cpp -lpcap
