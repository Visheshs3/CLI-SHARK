#include "helper.h"



// LAYER 1 

// printing the ethertypr
void print_ethertype(u_short ether_type) {
    printf("EtherType: ");
    switch (ether_type) {
        case ETHERTYPE_IP: // This constant is 0x0800
            printf("IPv4 (%#04x)\n", ether_type);
            break;
        case ETHERTYPE_IPV6: // This constant is 0x86DD
            printf("IPv6 (%#04x)\n", ether_type);
            break;
        case ETHERTYPE_ARP: // This constant is 0x0806
            printf("ARP (%#04x)\n", ether_type);
            break;
        default:
            printf("Unknown (%#04x)\n", ether_type);
            break;
    }
}


// LAYER 2


//handle printing of ipv6 and return TL-4 header offset
int handle_ipv6(const u_char *packet){
    const struct ip6_hdr *ipv6_header = (const struct ip6_hdr*)(packet + sizeof(struct ether_header));

    char source_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), source_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);

    printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", source_ip, dest_ip);
    printf("           Next Header: %d | Hop Limit: %d | Payload Length: %d\n",
           ipv6_header->ip6_nxt,
           ipv6_header->ip6_hlim,
           ntohs(ipv6_header->ip6_plen));

    return (sizeof(struct ether_header) + sizeof(struct ip6_hdr));
}


// handle printing of ARP request header and returns -1(indicating no TL-4)
int handle_arp(const u_char *packet) {
    const struct arphdr *arp_header = (const struct arphdr*)(packet + sizeof(struct ether_header));
    const struct arp_payload *arp_data = (const struct arp_payload*)(packet + sizeof(struct ether_header) + sizeof(struct arphdr));
    
    char sender_ip_str[INET_ADDRSTRLEN];
    char target_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp_data->sender_ip, sender_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_data->target_ip, target_ip_str, INET_ADDRSTRLEN);

    printf("L3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
           (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply",
           ntohs(arp_header->ar_op),
           sender_ip_str,
           target_ip_str);

    return -1;
    
}

// handles printing of IPV4 and return TL-4 header offset
int handle_ipv4(const __u_char *packet) {
    // Advance the packet pointer past the Ethernet header
    const struct ip *ip_header = (const struct ip*)(packet + sizeof(struct ether_header));

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN); // converts the ip from hex to human readable form
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    int header_length = ip_header->ip_hl * 4;

    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: (%s) %d | TTL: %d\n",
           source_ip,
           dest_ip,
           (ip_header->ip_p == 6)? "TCP" : "UDP",
           ip_header->ip_p,
           ip_header->ip_ttl);

    printf("           ID: %#x | Total Length: %d | Header Length: %d bytes\n",
           ntohs(ip_header->ip_id),
           ntohs(ip_header->ip_len),
           header_length);
    
    return (sizeof(struct ether_header) + header_length);
}




// LAYER 3