

#include "cshark.h"
#include "helper.h"

StoredPacket *g_session_packets[MAX_PACKET_STORAGE];
int g_session_packet_count = 0;
const char *session_filename = "cshark_session.bin";

char device_list[100][100] = {0};
int fg_process_pid = -1;
long long int count = 0;
FILE *g_session_file = NULL;

//stops the fg-process, here the sniffing
void sigint_handler(int sig) {
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
bool isvalid(const struct pcap_pkthdr *pkthdr){
    return true;
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

    if(isvalid(pkthdr)){
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
    for (int i = 0; i < g_session_packet_count; i++) {
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
    int packet_id = 0;
    scanf("%d", &packet_id);
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

                int child = fork();
                if (child == 0){
                    g_session_file = fopen(session_filename, "wb");  // no need to free the file as w frees it automatically
                    if (g_session_file == NULL) {
                        perror("Failed to open session file");
                        return 1;
                    }
                    setpgid(0, 0);
                    signal(SIGINT, SIG_DFL);
                    printf("\n[C-Shark] Sniffing on device: %s. Press Ctrl+C to stop.\n", choosen_device);
                    pcap_loop(packet_sniffer, -1, packet_handler, NULL); 
                    fclose(g_session_file);
                }
                else{
                    fg_process_pid = child;
                    setpgid(child, child);
                    wait(NULL);
                    count = 0;
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