

#include "cshark.h"
#include "helper.h"

StoredPacket *g_session_packets[MAX_PACKET_STORAGE];
int g_session_packet_count = 0;
const char *session_filename = "cshark_session.bin";
int g_active_filter = PROTOCOL_NONE;

char device_list[100][100] = {0};
int fg_process_pid = -1;
long long int count = 0;
FILE *g_session_file = NULL;

//stops the fg-process, here the sniffing
void sigint_handler() {
    if (fg_process_pid != -1) {
        // Send SIGTSTP to the foreground process group
        kill(-fg_process_pid, SIGINT);
    }
}


//add the name of the device in the device list
void add_device(int whence, char* device_name){
    strcpy(device_list[whence], device_name);
}

//clears the devicce list 
void clear_device_list(){
    for (int i = 0; i < 100; i++) {
        device_list[i][0] = '\0';
    }
}

//returns the copy of the choice of the user
char* copy_choice(int choice){
    return strdup(device_list[choice]);
}

//selects the device in a loop if entered wrong
char* select_device(){
    char* choosen_device = 0;
    while(1){
        pcap_if_t *alldevsp;
        char errbuf[PCAP_ERRBUF_SIZE];
        if(pcap_findalldevs(&alldevsp, errbuf) < 0){
            perror("");
            exit(1);
        }

        pcap_if_t* curr_device = alldevsp;
        
        int total_devices = 0;
        while(curr_device != NULL){
            add_device(total_devices, curr_device->name);

            printf("%d - %s", total_devices++, curr_device->name);
            if (curr_device->description)
            printf(" (%s)", curr_device->description);
            printf("\n");

            curr_device = curr_device->next;
        }        
        pcap_freealldevs(alldevsp);

        // choice of the user
        int choice = -1;
        printf("Choose the device to capture data from\n");
        scanf(" %d", &choice);
        if(choice < 0  ||  choice >= total_devices){
            total_devices = 0;
            clear_device_list();
            printf("choose within the range\n");
            while (getchar() != '\n');
            continue;
        }
        choosen_device = copy_choice(choice);
        printf("choosen device is %s\n", choosen_device);
        clear_device_list();
        break;
    }
    return choosen_device;
}


// checks if the packet follows the filtering condition or not
bool isvalid(const u_char *packet, int filter_protocol){
    if (filter_protocol == PROTOCOL_NONE) {
        return true; // No filter applied
    }

    struct ether_header *eth_header = (struct ether_header *)packet;
    u_short ether_type = ntohs(eth_header->ether_type);

    if (filter_protocol == PROTOCOL_ARP) {
        return ether_type == ETHERTYPE_ARP;
    }

    if (ether_type == ETHERTYPE_IP) {
        const struct ip *ip_header = (const struct ip*)(packet + sizeof(struct ether_header));
        int ip_header_len = ip_header->ip_hl * 4;

        if (filter_protocol == PROTOCOL_TCP) {
            return ip_header->ip_p == IPPROTO_TCP;
        }
        if (filter_protocol == PROTOCOL_UDP) {
            return ip_header->ip_p == IPPROTO_UDP;
        }

        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (const struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
            u_short src_port = ntohs(tcp_header->th_sport);
            u_short dst_port = ntohs(tcp_header->th_dport);

            if (filter_protocol == PROTOCOL_HTTP) return (src_port == 80 || dst_port == 80);
            if (filter_protocol == PROTOCOL_HTTPS) return (src_port == 443 || dst_port == 443);

        } else if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = (const struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
            u_short src_port = ntohs(udp_header->uh_sport);
            u_short dst_port = ntohs(udp_header->uh_dport);

            if (filter_protocol == PROTOCOL_DNS) return (src_port == 53 || dst_port == 53);
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        const struct ip6_hdr *ipv6_header = (const struct ip6_hdr*)(packet + sizeof(struct ether_header));
        int l4_offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr);

        if (filter_protocol == PROTOCOL_TCP) {
            return ipv6_header->ip6_nxt == IPPROTO_TCP;
        }
        if (filter_protocol == PROTOCOL_UDP) {
            return ipv6_header->ip6_nxt == IPPROTO_UDP;
        }

        if (ipv6_header->ip6_nxt == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (const struct tcphdr*)(packet + l4_offset);
            u_short src_port = ntohs(tcp_header->th_sport);
            u_short dst_port = ntohs(tcp_header->th_dport);

            if (filter_protocol == PROTOCOL_HTTP) return (src_port == 80 || dst_port == 80);
            if (filter_protocol == PROTOCOL_HTTPS) return (src_port == 443 || dst_port == 443);

        } else if (ipv6_header->ip6_nxt == IPPROTO_UDP) {
            const struct udphdr *udp_header = (const struct udphdr*)(packet + l4_offset);
            u_short src_port = ntohs(udp_header->uh_sport);
            u_short dst_port = ntohs(udp_header->uh_dport);

            if (filter_protocol == PROTOCOL_DNS) return (src_port == 53 || dst_port == 53);
        }
    }
    
    return false;
}

void print_rest(const struct pcap_pkthdr *pkthdr, const u_char *packet, bool detailed){
    struct ether_header *eth_header = (struct ether_header *)packet;
    u_short type = ntohs(eth_header->ether_type);

    int l4_offset = -1;   // if 0 then arp
    int l4_protocol = -1; // if 0 then arp

    // handler for various L3 stuff
    switch (type) {
    case ETHERTYPE_IP:
        l4_protocol = handle_ipv4(packet, &l4_offset);
        break;
    case ETHERTYPE_IPV6:
        l4_protocol = handle_ipv6(packet, &l4_offset);
        break;
    case ETHERTYPE_ARP:
        l4_protocol = handle_arp(packet, &l4_offset);
        break;
    default:
        break;
    }

    // Layer 4

    if(l4_offset > 0){
        if(l4_protocol == IPPROTO_TCP){
            handle_tcp_printing(packet, l4_offset, pkthdr->len, detailed);
        }
        else if(l4_protocol == IPPROTO_UDP){
            handle_udp_printing(packet, l4_offset, detailed);
        }
        //rest skip
    }
}


void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int filter = g_active_filter;
    if(user_data != NULL){
        filter = ((struct user_data*)user_data)->filter_protocol;
    }
    if(isvalid(packet, filter)){
        if (g_session_file != NULL && count < MAX_PACKET_STORAGE) {
            fwrite(pkthdr, sizeof(struct pcap_pkthdr), 1, g_session_file);
            fwrite(packet, pkthdr->caplen, 1, g_session_file);
            fflush(g_session_file);
        }

        count++;  // incrementing global counter

        //basic printing
        char time_buffer[64];
        struct tm *timeinfo = localtime(&pkthdr->ts.tv_sec);
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        struct ether_header *eth_header = (struct ether_header *)packet;
        printf("Packet #%lld | Timestamp: %s.%06ld | Length: %d bytes\n", count, time_buffer, pkthdr->ts.tv_usec, pkthdr->len);
        
        // level 2 printing
        printf("L2 (Ethernet): Dst MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x%s", eth_header->ether_dhost[i], (i == ETHER_ADDR_LEN - 1) ? "" : ":");
        }
        printf(" | Src MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x%s", eth_header->ether_shost[i], (i == ETHER_ADDR_LEN - 1) ? "" : ":");
        }
        printf(" | ");
        u_short type = ntohs(eth_header->ether_type);
        print_ethertype(type);
        print_rest(pkthdr, packet, false);
    

        printf("===================================================================================================\n");
    }


}

// Clears any packets stored in the global array from memory
void clear_session_memory() {
    for (int i = 0; i < g_session_packet_count; i++) {
        free(g_session_packets[i]->data);
        free(g_session_packets[i]);
        g_session_packets[i] = NULL;
    }
    g_session_packet_count = 0;
}

// Reads the binary session file into the global packets array
int load_session_from_file() {
    clear_session_memory();
    FILE *file = fopen(session_filename, "rb"); 
    if (file == NULL) {
        printf("\nError: No session file found. Run a sniffing session first.\n");
        return -1;
    }

    while (g_session_packet_count < MAX_PACKET_STORAGE) {
        struct pcap_pkthdr temp_header; 
        if (fread(&temp_header, sizeof(struct pcap_pkthdr), 1, file) != 1) {
            break; // EOF
        }
        StoredPacket *pkt = malloc(sizeof(StoredPacket));
        pkt->data = malloc(temp_header.caplen);
        if (!pkt || !pkt->data) {
            printf("Error: Memory allocation failed.\n");
            fclose(file);
            exit(1);
        }
        if (fread(pkt->data, 1, temp_header.caplen, file) != temp_header.caplen) {
            free(pkt->data); 
            free(pkt);
            break; // error
        }
        
        pkt->header = temp_header;
        g_session_packets[g_session_packet_count++] = pkt;
    }

    fclose(file);
    return 0 ;
}

// inspection feature
void inspect_session() {
    if(load_session_from_file() < 0) return; 

    if (g_session_packet_count == 0) {
        printf("Session file is empty. Nothing to inspect.\n");
        return;
    }

    printf("\n==================================================================Session Summary==================================================================\n");
    for (long long int i = 0; i < g_session_packet_count; i++) {
        char time_buffer[64];

        struct pcap_pkthdr *pkthdr = &(g_session_packets[i]->header);
        struct tm *timeinfo = localtime(&pkthdr->ts.tv_sec);
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        struct ether_header *eth_header = (struct ether_header *)g_session_packets[i]->data;
        printf("Packet #%lld | Timestamp: %s.%06ld | Length: %d bytes\n", i+1, time_buffer, pkthdr->ts.tv_usec, pkthdr->len);
        
        // level 2 printing
        printf("L2 (Ethernet): Dst MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x%s", eth_header->ether_dhost[i], (i == ETHER_ADDR_LEN - 1) ? "" : ":");
        }
        printf(" | Src MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x%s", eth_header->ether_shost[i], (i == ETHER_ADDR_LEN - 1) ? "" : ":");
        }
        printf(" | ");
        u_short type = ntohs(eth_header->ether_type);
        print_ethertype(type);
        printf("----------------------------------------------------------------------------------------------------\n");
    }
    printf("===================================================================================================\n");

    printf("Enter Packet ID to inspect (1-%d), or 0 to return: ", g_session_packet_count);
    long long int packet_id = 0;
    scanf("%lld", &packet_id);
    if (packet_id > 0 && packet_id <= g_session_packet_count) {
        StoredPacket *selected_pkt = g_session_packets[packet_id - 1];
        struct pcap_pkthdr *pkthdr = &(selected_pkt->header);
        struct tm *timeinfo = localtime(&pkthdr->ts.tv_sec);
        char time_buffer[64];
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        struct ether_header *eth_header = (struct ether_header *)selected_pkt->data;
        printf("Packet #%lld | Timestamp: %s.%06ld | Length: %d bytes\n", packet_id, time_buffer, pkthdr->ts.tv_usec, pkthdr->len);
        
        // level 2 printing
        printf("L2 (Ethernet): Dst MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x%s", eth_header->ether_dhost[i], (i == ETHER_ADDR_LEN - 1) ? "" : ":");
        }
        printf(" | Src MAC: ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            printf("%02x%s", eth_header->ether_shost[i], (i == ETHER_ADDR_LEN - 1) ? "" : ":");
        }
        printf(" | ");
        u_short type = ntohs(eth_header->ether_type);
        print_ethertype(type);
        print_rest(pkthdr, selected_pkt->data, true);
        

    } else if (packet_id != 0) {
        printf("Invalid Packet ID.\n");
    }
}

//prints the filter menu for the user
void print_filter_menu(){
    printf("\n--- Select a Protocol to Filter ---\n");
    printf("0. HTTP\n");
    printf("1. HTTPS\n");
    printf("2. DNS\n");
    printf("3. ARP\n");
    printf("4. TCP\n");
    printf("5. UDP\n");
    printf("-----------------------------------\n");
    printf("Enter filter choice: ");
}

//prints the option menu for user
void printmenu(){
    printf("\n===== C-Shark Menu =====\n");
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n");
    printf("========================\n");
    printf("Enter your choice: ");
}

int main(void){
    count = 0;
    signal(SIGINT, sigint_handler);

    printf("Hello, welocome to C-shark a CLI version of WireShark!\nSelect the number of the device from which you want to sniff the data\n");

    char* choosen_device = select_device();
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t *packet_sniffer = pcap_create(choosen_device, errbuf);
    pcap_set_promisc(packet_sniffer, 1);      // Turn on promiscuous mode
    pcap_set_snaplen(packet_sniffer, 65535);  // Set snapshot length
    pcap_set_timeout(packet_sniffer, 1000);   // Set timeout
    if(pcap_activate(packet_sniffer) != 0){
        pcap_perror(packet_sniffer, "pcap_activate error");
        free(choosen_device);
        return 1;
    }

    while(true){
        printmenu();
        int option = -1;
        scanf(" %d", &option);
        if(option <=0 || option > 4){
            printf("enter a valid option\n");
            while (getchar() != '\n');
            option = -1;
            continue;
        }
        else{
            if (option == 4){
                printf("bye bye bye bye !!!!\n");
                exit(0);
            }
            else if(option == 1 || option == 2){

                g_active_filter = PROTOCOL_NONE; // Default to no filter
                if (option == 2) {
                    print_filter_menu();
                    int filter_choice = -1;
                    if(scanf(" %d", &filter_choice) != 1 || filter_choice < 0 || filter_choice > 5) {
                        printf("Invalid filter choice. Sniffing all packets instead.\n");
                        while (getchar() != '\n'); // Clear input buffer
                    } else {
                        g_active_filter = filter_choice;
                    }
                }

                int child = fork();
                if (child < 0) {
                    perror("fork failed");
                    break;
                }

                if (child == 0){ // Child process
                    g_session_file = fopen(session_filename, "wb");
                    if (g_session_file == NULL) {
                        perror("Failed to open session file");
                        exit(1);
                    }
                    setpgid(0, 0);
                    signal(SIGINT, SIG_DFL);
                    printf("\n[C-Shark] Sniffing on device: %s. Press Ctrl+C to stop.\n", choosen_device);
                    
                    user_data data;
                    data.filter_protocol = g_active_filter;

                    pcap_loop(packet_sniffer, -1, packet_handler, (u_char*)&data); 
                    
                    printf("\n[C-Shark] Sniffing stopped. %lld packets captured.\n", count);
                    fclose(g_session_file);
                    exit(0);
                }
                else{ 
                    fg_process_pid = child;
                    setpgid(child, child); // Move child to its own process group
                    int status;
                    waitpid(child, &status, 0); 
                    count = 0;
                    g_session_packet_count = 0; 
                    fg_process_pid = -1;
                }
            }
            else if(option == 3){
                inspect_session();
            }
            
        }
    }
    free(choosen_device); 
    
    

}