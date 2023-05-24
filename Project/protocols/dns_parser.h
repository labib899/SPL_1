#ifndef DNS_PARSER_H
#define DNS_PARSER_H


#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>


using namespace std;


// DNS header structure
struct dns_header 
{
    // DNS header fields
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority_rr;
    uint16_t additional_rr;
};



// DNS question structure
struct dns_question 
{
    string name;
    uint16_t type;
    uint16_t qclass;
};


// DNS answer structure
struct dns_answer 
{
    string name;
    uint16_t type;
    uint16_t aclass;
    uint32_t ttl;
    uint16_t rdlength;
    string rdata;
};



// Function to parse DNS header
dns_header parseDNSHeader(const u_char* packet) 
{
    dns_header header;

    // parsing the header fields from the packet
    header.id = ntohs(*((const uint16_t*)packet));
    header.flags = ntohs(*((const uint16_t*)(packet + 2)));
    header.questions = ntohs(*((const uint16_t*)(packet + 4)));
    header.answers = ntohs(*((const uint16_t*)(packet + 6)));
    header.authority_rr = ntohs(*((const uint16_t*)(packet + 8)));
    header.additional_rr = ntohs(*((const uint16_t*)(packet + 10)));

    return header;
}



// Function to parse DNS question
dns_question parseDNSQuestion(const u_char* packet, int offset) 
{
    dns_question question;

    // reading the domain name from the packet
    string domainName;

    while (true) 
    {
        uint8_t labelLength = *(packet + offset);

        if (labelLength == 0) 
        {
            offset++;  // moving past the null label
            break;
        }

        if ((labelLength & 0xC0) == 0xC0) 
        {
            // Compressed label pointer, jump to the offset specified
            uint16_t pointerOffset = ntohs(*((const uint16_t*)(packet + offset))) & 0x3FFF;
            offset = pointerOffset;
            continue;
        }
        offset++;  // Move past the label length

        domainName += string((const char*)(packet + offset), labelLength) + ".";
        offset += labelLength;
    }
    question.name = domainName;

    // parsing the question fields
    question.type = ntohs(*((const uint16_t*)(packet + offset)));
    question.qclass = ntohs(*((const uint16_t*)(packet + offset + 2)));

    return question;
}



// Function to parse DNS packet
void parseDNSPacket(const u_char* packet, int length) 
{
    // parsing DNS header
    dns_header header = parseDNSHeader(packet);

    // printing DNS header information
    cout << "DNS Header:" << endl;
    cout << "ID: " <<  header.id << endl;
    cout << "Flags: " <<  header.flags << endl;
    cout << "Questions: " << header.questions << endl;
    cout << "Answers: " << header.answers << endl;
    cout << "Authority RR: " << header.authority_rr << endl;
    cout << "Additional RR: " << header.additional_rr << endl;
    cout << endl;

    // parsing DNS queries
    int offset = sizeof(dns_header);
    cout << "DNS Queries:" << endl;

    for (int i = 0; i < header.questions; i++) 
    {
        dns_question question = parseDNSQuestion(packet, offset);
        offset += question.name.length() + 2 + 4; // Name + Type + Class

        // Print DNS question information
        cout << "Query " << i + 1 << ":" << endl;
        cout << "Name: " << question.name << endl;

        // printing type
        cout << "Type: ";
        string Type;
        if(question.type==1)
        {
            Type="A";
        }

        else if(question.type==65)
        {
            Type="HTTPS";
        }

        else if(question.type==2)
        {
            Type="NS";
        }

        else if(question.type==5)
        {
            Type="CNAME";
        }

        else if(question.type==6)
        {
            Type="SOA";
        }

        else if(question.type==12)
        {
            Type="PTR";
        }

        else if(question.type==15)
        {
            Type="MX";
        }

        else if(question.type==16)
        {
            Type="TXT";
        }

        else if(question.type==28)
        {
            Type="AAAA";
        }

        else Type="Unknown";

        cout<<Type<<endl;

        // printing class
        cout << "Class: " ;
        string Class;
        if(question.qclass==1)
        {
            Class="IN";
        }

        else if(question.qclass==2)
        {
            Class="CS";
        }

        else if(question.qclass==3)
        {
            Class="CH";
        }

        else if(question.qclass==4)
        {
            Class="HS";
        }

        else Class="Unknown";

        cout<<Class<<endl;
    }

    cout<<endl<<endl;
}



#endif