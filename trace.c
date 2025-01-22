#include <stdio.h>
#include "checksum.h"
#include <pcap.h>
#include <string.h>

#define PSEUDO_LENGTH 12
#define ETHERNET_LENGTH 14

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void ethernet_header(const struct pcap_pkthdr *h, const u_char *bytes);
void arp_header(const struct pcap_pkthdr *h, const u_char *bytes);
void ip_header(const struct pcap_pkthdr *h, const u_char *bytes);
void udp_header(const struct pcap_pkthdr *h, const u_char *bytes);
void tcp_header(const struct pcap_pkthdr *h, const u_char *bytes);
void tcp_checksum(const struct pcap_pkthdr *h, const u_char *bytes);

uint16_t packet_count = 1;
int8_t ip_protocol = 3; // 0 is udp, 1 is tcp, 2 is icmp
uint8_t ip_header_len = 0;

int main (int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    char inputFile[300] = "./";
    strcat(inputFile, argv[1]);

    pcap_t *file = pcap_open_offline(inputFile, errbuf);
    if(!file)
    {
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }

    pcap_loop(file, 0, packet_handler, NULL);
    pcap_close(file);
    return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    ethernet_header(h, bytes);
    if (ip_protocol == 0) { udp_header(h, bytes); }
    else if (ip_protocol == 1) { tcp_header(h, bytes); }
}

void udp_header(const struct pcap_pkthdr *h, const u_char *bytes) {

    printf("\n\tUDP Header\n\t\t");
    uint16_t source_port = (bytes[ip_header_len + 14] << 8) | bytes[ip_header_len + 15];
    uint16_t dest_port = (bytes[ip_header_len + 16] << 8) | bytes[ip_header_len + 17];
    if (source_port == 53) { printf("Source Port:  DNS\n\t\t"); }
    else { printf("Source Port:  %d\n\t\t", source_port); }
    if (dest_port == 53) { printf("Dest Port:  DNS\n"); }
    else { printf("Dest Port:  %d\n", dest_port); }
}

void tcp_header(const struct pcap_pkthdr *h, const u_char *bytes) {

    uint16_t tcp_start = ip_header_len + ETHERNET_LENGTH;

    printf("\n\tTCP Header\n\t\t");
    uint16_t source_port = (bytes[tcp_start] << 8) | bytes[tcp_start + 1];
    uint16_t dest_port = (bytes[tcp_start + 2] << 8) | bytes[tcp_start + 3];
    if (source_port == 80) { printf("Source Port:  HTTP\n\t\t"); }
    else { printf("Source Port:  %d\n\t\t", source_port); }
    if (dest_port == 80) { printf("Dest Port:  HTTP\n\t\t"); }
    else { printf("Dest Port:  %d\n\t\t", dest_port); }
    uint32_t seq_number = (bytes[tcp_start + 4] << 24) | (bytes[tcp_start + 5] << 16) | (bytes[tcp_start + 6] << 8) | bytes[tcp_start + 7];
    printf("Sequence Number: %u\n\t\t", seq_number);
    uint32_t ack_number = (bytes[tcp_start + 8] << 24) | (bytes[tcp_start + 9] << 16) | (bytes[tcp_start + 10] << 8) | bytes[tcp_start + 11];
    printf("ACK Number: %u\n\t\t", ack_number);
    printf("Data Offset (bytes): %d\n\t\t", ((bytes[tcp_start + 12] & 0xf0) >> 4) * 4);
    printf("SYN Flag: %s\n\t\t", (bytes[tcp_start + 13] & 0x2) == 2 ? "Yes" : "No");
    printf("RST Flag: %s\n\t\t", (bytes[tcp_start + 13] & 0x4) == 4 ? "Yes" : "No");
    printf("FIN Flag: %s\n\t\t", (bytes[tcp_start + 13] & 0x1) == 1 ? "Yes" : "No");
    printf("ACK Flag: %s\n\t\t", (bytes[tcp_start + 13] & 0x10) == 16 ? "Yes" : "No");
    printf("Window Size: %d\n\t\t", (bytes[tcp_start + 14] << 8) | bytes[tcp_start + 15]);
    tcp_checksum(h, bytes);
}


void tcp_checksum(const struct pcap_pkthdr *h, const u_char *bytes) {

    uint16_t pseudo_header[6] = {0};
    memcpy(pseudo_header, &bytes[ETHERNET_LENGTH + 12], 8);
    pseudo_header[4] = 0x600;
    uint16_t ip_total_length = ntohs(*(uint16_t*)&bytes[16]);
    uint16_t tcp_length = htons(ip_total_length - ip_header_len);

    memcpy(pseudo_header + 5, &tcp_length, 2);
    uint16_t tcp_length_seg = ip_total_length - ip_header_len;
    uint16_t tcp_with_pseudo[tcp_length_seg + PSEUDO_LENGTH];
    memcpy(&tcp_with_pseudo, pseudo_header, PSEUDO_LENGTH);
    memcpy(&tcp_with_pseudo[6], &bytes[ETHERNET_LENGTH + ip_header_len], tcp_length_seg);

    printf("Checksum: %s (0x%04x)\n", 
        in_cksum((unsigned short *)&tcp_with_pseudo, tcp_length_seg + PSEUDO_LENGTH)  == 0 ? "Correct" : "Incorrect", 
        ntohs(*(uint16_t*)&bytes[ETHERNET_LENGTH + ip_header_len + 16]));

}

void ip_header(const struct pcap_pkthdr *h, const u_char *bytes) {

    printf("IP Header\n\t\t");
    printf("IP Version: %d\n\t\t", (bytes[14] & 0xf0) >> 4);
    ip_header_len = (bytes[14] & 0xf) * 4;
    printf("Header Len (bytes): %d\n\t\t", ip_header_len);
    printf("TOS subfields:\n\t\t   ");
    printf("Diffserv bits: %d\n\t\t   ", bytes[15] >> 2);
    printf("ECN bits: %d\n\t\t", (bytes[15] & 0x3));
    printf("TTL: %d\n\t\t", bytes[22]);
    ip_protocol = (bytes[23] == 17) ? 0 : (bytes[23] == 6 ? 1 : (bytes[23] == 1 ? 2 : 3));
    printf("Protocol: %s\n\t\t", ip_protocol == 2 ? "ICMP" : (ip_protocol == 1 ? "TCP" : (ip_protocol == 0 ? "UDP" : "Unknown")));
    printf("Checksum: %s (0x%04x)\n\t\t", in_cksum((unsigned short *)&bytes[14], ip_header_len) == 0 ? "Correct" : "Incorrect", (bytes[24] << 8) | bytes[25]);
    printf("Sender IP: %d.%d.%d.%d\n\t\t", bytes[26], bytes[27], bytes[28], bytes[29]);
    printf("Dest IP: %d.%d.%d.%d\n", bytes[30], bytes[31], bytes[32], bytes[33]);
    if(bytes[23] != 1) { return; }
    printf("\n\tICMP Header\n\t\t");
    uint8_t icmp_type = bytes[14 + ip_header_len];
    if(icmp_type != 0 && icmp_type != 8) { printf("Type: %d\n", icmp_type); }
    else { printf("Type: %s\n", icmp_type == 0 ? "Reply" : (icmp_type == 8 ? "Request" : "")); }
}

void arp_header(const struct pcap_pkthdr *h, const u_char *bytes) {

    printf("ARP header\n\t\t");
    printf("Opcode: %s\n\t\t", (bytes[21] == 0x01) ? "Request" : "Reply");
    printf("Sender MAC: %x:%x:%x:%x:%x:%x\n\t\t", bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27]);
    printf("Sender IP: %d.%d.%d.%d\n\t\t", bytes[28], bytes[29], bytes[30], bytes[31]);
    printf("Target MAC: %x:%x:%x:%x:%x:%x\n\t\t", bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37]);
    printf("Target IP: %d.%d.%d.%d\n\n", bytes[38], bytes[39], bytes[40], bytes[41]);
}

void ethernet_header(const struct pcap_pkthdr *h, const u_char *bytes) {

    ip_protocol = 3;
    ip_header_len = 0;
    printf("\nPacket number: %d  Packet Len: %d\n\n", packet_count++, h->len);
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: ");
    for(uint16_t i = 0; i < 6; i++) {
        printf("%x%c", bytes[i], (i < 5) ? ':' : '\n');
    }
    printf("\t\tSource MAC: ");
    for(uint16_t i = 6; i < 12; i++) {
        printf("%x%c", bytes[i], (i < 11) ? ':' : '\n');
    }
    printf("\t\tType: ");
    if(((bytes[12] << 8) | bytes[13]) == 0x0806) {
        printf("ARP\n\n\t");
        arp_header(h, bytes);
    }
    else if(((bytes[12] << 8) | bytes[13]) == 0x0800) {
        printf("IP\n\n\t");
        ip_header(h, bytes);
    }   
}
