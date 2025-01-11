#include <stdio.h>
#include <pcap.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

uint16_t packet_count = 1;

int main (int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *file = pcap_open_offline("./Trace_Files/ArpTest.pcap", errbuf);
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

    printf("Packet number: %d Packet Len: %d\n\n", packet_count++, h->len);

    printf("\tEthernet Header\n");
    printf("\t\t Dest MAC: ");
    for(uint16_t i = 0; i < 6; i++) {
        printf("%x%c", bytes[i], (i < 5) ? ':' : '\0');
    }
    printf("\n\t\t Source MAC: ");
    for(uint16_t i = 6; i < 12; i++) {
        printf("%x%c", bytes[i], (i < 11) ? ':' : '\0');
    }
    printf("\n\t\t Type: ");
    if(((bytes[12] << 8) | bytes[13]) == 0x0806) {
        printf("ARP\n\n");
    }
}
