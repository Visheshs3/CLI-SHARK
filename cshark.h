#ifndef CSHARK_H
#define CSHARK_H
#define _DEFAULT_SOURCE
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <stdbool.h>
#include <ctype.h>


#define MAXDEVICES 100;

#define PROTOCOL_NONE -1
#define PROTOCOL_HTTP  0
#define PROTOCOL_HTTPS 1
#define PROTOCOL_DNS   2
#define PROTOCOL_ARP   3
#define PROTOCOL_TCP   4
#define PROTOCOL_UDP   5

//data sturucture for arp payload
struct arp_payload {
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

#define MAX_PACKET_STORAGE 10000

typedef struct StoredPacket{
    struct pcap_pkthdr header;    // header and data of the packets
    u_char *data;
} StoredPacket;


typedef struct user_data{
    int filter_protocol;
    char* choice;
    bool detailed;
}user_data;

#endif // CSHARK_H