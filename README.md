# C-Shark: A CLI Network Sniffer

This document outlines the assumptions and key implementation details of C-Shark, a command-line network packet sniffer.

## Assumptions

*   **libpcap Availability:**  The program assumes that `libpcap` is installed on the system.
*   **Root Privileges:**  Sniffing network traffic typically requires root privileges due to the need to put the network interface into promiscuous mode.
*   **Maximum Packet Storage:**  A maximum of `MAX_PACKET_STORAGE` (defined in `cshark.h`) packets can be stored in a session. Older packets will be overwritten if this limit is reached.

## Key Implementation Details

*   **Device Selection:** The program lists available network devices and prompts the user to select one for capturing traffic.
*   **Packet Capture:**  `libpcap` is used to capture network packets.  The `pcap_loop` function continuously captures packets until interrupted.
*   **Packet Filtering:**  The program allows filtering packets based on protocol (HTTP, HTTPS, DNS, ARP, TCP, UDP).
*   **Session Management:** Captured packets can be saved to a binary file (`cshark_session.bin`) for later inspection.
*   **Packet Inspection:**  The program allows loading a previously saved session and inspecting individual packets.  Basic decoding of Ethernet, IP, TCP, and UDP headers is performed.
*   **Signal Handling:**  `SIGINT` (Ctrl+C) is handled to gracefully stop the sniffing process.
*   **Forking:** The sniffing functionality is put into a child process.

## Important Notes

*   The `session_filename` is hardcoded.
*   The device list is cleared after each selection attempt.
*   The program provides basic packet decoding. More detailed protocol analysis could be added.
