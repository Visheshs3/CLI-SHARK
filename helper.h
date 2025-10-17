#ifndef HELPER_H
#define HELPER_H
#include "cshark.h"

// printing the ethertypr
void print_ethertype(u_short ether_type);

//handle printing of ipv6 and return TL-4 header offset
int handle_ipv6(const u_char *packet, int* l4_offset);

// handle printing of ARP request header and returns -1(indicating no TL-4)
int handle_arp(const u_char *packet, int* l4_offset);

// handles printing of IPV4 and return TL-4 header offset
int handle_ipv4(const __u_char *packet, int* l4_offset);

void handle_udp_printing(const u_char *packet, int offset, bool detail);

void handle_tcp_printing(const u_char *packet, int offset, int total_len, bool detail);



#endif