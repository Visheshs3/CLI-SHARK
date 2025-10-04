#ifndef CSHARK_H
#define CSHARK_H

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


#define MAXDEVICES 100;

#define PROTOCOL_HTTP  0
#define PROTOCOL_HTTPS 1
#define PROTOCOL_DNS   2
#define PROTOCOL_ARP   3
#define PROTOCOL_TCP   4
#define PROTOCOL_UDP   5

typedef struct sniffer_context{
    int protocol_option; 
}sniffer_context;

//data sturucture for arp payload
struct arp_payload {
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

#endif // CSHARK_H