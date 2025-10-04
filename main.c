#include "cshark.h"
#include "helper.h"

char device_list[100][100] = {0};
int fg_process_pid = -1;
long long int count = 0;

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
bool isvalid(sniffer_context* context, const struct pcap_pkthdr *pkthdr){
    if(context){
        //pass
    }
    else{
        return true;
    }
    return false;
}


void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    sniffer_context *context = (sniffer_context* )user_data;
    if(isvalid(context, pkthdr)){
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

        int offset = 0;

        // handler for various L3 stuff
        switch (type) {
        case ETHERTYPE_IP:
            offset = handle_ipv4(packet);
            break;
        case ETHERTYPE_IPV6:
            offset = handle_ipv6(packet);
            break;
        case ETHERTYPE_ARP:
            offset = handle_arp(packet);
            break;
        default:
            break;
        }

        // Layer 4

        if(offset > -1){

        }

        printf("========================================================================\n");
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

            int child = fork();
            if (child == 0){
                setpgid(0, 0);
                signal(SIGINT, SIG_DFL);
                printf("\n[C-Shark] Sniffing on device: %s. Press Ctrl+C to stop.\n", choosen_device);
                free(choosen_device);
                pcap_loop(packet_sniffer, -1, packet_handler, NULL); 
            }
            else{
                fg_process_pid = child;
                setpgid(child, child);
                free(choosen_device); 
                wait(NULL);
                count = 0;
                fg_process_pid = -1;
            }
        }
    }
    

    int child = fork();

    

}