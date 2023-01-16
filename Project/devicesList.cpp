// g++ devicesList.cpp -lpcap
#include <iostream>
#include <pcap.h>

using namespace std;

//function to display the list of available devices on the network
void list();


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
        cout<<"List of devices:"<<endl;
        int i=1;
        for(device=interface;device!=NULL;device=device->next,i++)
            cout<<"Device "<<i<<": "<<device->name<<endl;
        return;
    }
}

