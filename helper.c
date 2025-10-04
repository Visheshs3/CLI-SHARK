#include "helper.h"

void print_hex_dump(const u_char *packet, int l6_offset, int len, bool detail);

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
int handle_ipv6(const u_char *packet, int* l4_offset){
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

    *l4_offset = (sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    return ipv6_header->ip6_nxt;
}


// handle printing of ARP request header and returns -1(indicating no TL-4)
int handle_arp(const u_char *packet, int* l4_offset) {
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
    
    *l4_offset = 0;
    return 0;
    
}

// handles printing of IPV4 and return TL-4 header offset
int handle_ipv4(const __u_char *packet, int* l4_offset) {
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
    
    *l4_offset = sizeof(struct ether_header) + header_length;
    return ip_header->ip_p;
}




// LAYER 3

// helper function to get the layer 6 service name
const char* get_service_name(u_short port) {
    switch (port) {
        case 80: return " (HTTP)";
        case 443: return " (HTTPS)";
        case 53: return " (DNS)";
        default: return "";
    }
}


void handle_udp_printing(const u_char *packet, int offset, bool detail){
    struct udphdr *udp_header = (struct udphdr *)(packet + offset);
    
    u_short src_port = ntohs(udp_header->uh_sport);
    u_short dst_port = ntohs(udp_header->uh_dport);

    printf("L4 (UDP): Src Port: %d%s | Dst Port: %d%s | Length: %d | Checksum: %#x\n",
           src_port, get_service_name(src_port),
           dst_port, get_service_name(dst_port),
           ntohs(udp_header->uh_ulen),
           ntohs(udp_header->uh_sum));
    
    int l6_offset = offset + sizeof(struct udphdr);
    int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

    if(payload_len > 0){
        printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",(dst_port == 53) ? "DNS" : "Unknown", dst_port, payload_len);

        print_hex_dump(packet, l6_offset, payload_len, detail);
    }
    
    
    
}

void handle_tcp_printing(const u_char *packet, int offset, int total_len, bool detail) {
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + offset);

    u_short src_port = ntohs(tcp_header->th_sport);
    u_short dst_port = ntohs(tcp_header->th_dport);

    printf("L4 (TCP): Src Port: %d%s | Dst Port: %d%s | Seq: %u | Ack: %u\n",
           src_port, get_service_name(src_port),
           dst_port, get_service_name(dst_port),
           ntohl(tcp_header->th_seq),
           ntohl(tcp_header->th_ack));
    
    // printing flags
    printf("          Flags: [ ");
    if (tcp_header->th_flags & TH_SYN) printf("SYN ");
    if (tcp_header->th_flags & TH_ACK) printf("ACK ");
    if (tcp_header->th_flags & TH_FIN) printf("FIN ");
    if (tcp_header->th_flags & TH_RST) printf("RST ");
    if (tcp_header->th_flags & TH_PUSH) printf("PSH ");
    if (tcp_header->th_flags & TH_URG) printf("URG ");
    printf("] | Window: %d | Checksum: %#x | Header Length: %d bytes\n",
           ntohs(tcp_header->th_win),
           ntohs(tcp_header->th_sum),
           tcp_header->th_off * 4);
    
    int header_size = tcp_header->th_off * 4;
    int l6_offset = offset + header_size;
    int payload_len = total_len - offset - header_size;

    if (payload_len > 0) {
        char *protocol_name = "Unknown";
        if (dst_port == 443 || ntohs(tcp_header->th_sport) == 443) protocol_name = "HTTPS/TLS";
        if (dst_port == 80 || ntohs(tcp_header->th_sport) == 80) protocol_name = "HTTP";
        
        printf("L7 (Payload): Identified as %s on port %d - %d bytes\n", protocol_name, dst_port, payload_len);
        print_hex_dump(packet, l6_offset, payload_len, detail);
    }

}


void print_hex_dump(const u_char *packet, int l6_offset, int len, bool detail) {
    int line_width = 16; 
    const u_char *ch = packet + l6_offset;

    if(!detail && len > 64) len = 64;
    printf("Data (first %d bytes):\n", len);

    for(int i = 0; i < len; i++) {
        if (i % line_width == 0) {
            printf("   ");
        }
        printf("%02x ", ch[i]);

        // Print ASCII value on the right
        if ((i + 1) % line_width == 0 || i == len - 1) {
            // Print spaces for alignment
            for (int j = 0; j < line_width - 1 - (i % line_width); j++) {
                printf("   ");
            }
            printf("  ");

            for (int j = i - (i % line_width); j <= i; j++) {
                if (isprint(ch[j])) {
                    printf("%c", ch[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}