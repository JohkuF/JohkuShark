#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/ip.h> // for struct iphdr
#include <netinet/tcp.h> // for struct tcphdr
#include <netinet/udp.h> // for struct udphdr
#include <netinet/ip_icmp.h> // for struct icmphdr
#include <netinet/if_ether.h> // for struct ether_header

#define BUFSIZE 16384 // 8192 * 2
#define PAGEWIDTH 30

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packets(const struct pcap_pkthdr *header, const u_char *packet);
void print_protocol(struct protoent *proto);

int main() {

    pcap_if_t *alldevsp , *device;
	pcap_t *handle;

	char errbuf[PCAP_ERRBUF_SIZE];
    char devs[100][100];
    int count = 1 , n;
	
	//First get the list of available devices
	printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}

    printf("\nAvailable devices are: \n");
    for(device = alldevsp; device != NULL; device = device->next)
    {
        printf("%d. %s - %s\n", count, device->name, device->description);

        if(device->name != NULL)
        {
            strcpy(devs[count], device->name);
        }

        count++;
    }

    printf("Select the device to sniff: ");
    scanf("%d", &n);
    char *dev = devs[n];

    handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);

    if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return 1;
    }

    int packet_count = -1;
    pcap_loop(handle, packet_count, packet_handler, NULL);

    pcap_close(handle);

}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    /* Check for ip-packets only */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;


    /* Get the protocol */
    u_char protocol = *(ip_header + 9);

    /* Get the procol name from */
    printf("Official protocol name: %s\n", getprotobynumber(protocol)->p_name);

    //printf("Getprotobynumber, %d", getprotobynumber(protocol)->p_name);


    print_packets(header, packet);

}

void print_protocol(struct protoent *proto) {
    printf("Official protocol name: %s\n", proto->p_name);

    if (proto->p_aliases[0] != NULL) {
        printf("Protocol aliases:\n");
        for (char **alias = proto->p_aliases; *alias != NULL; alias++) {
            printf("%s\n", *alias);
        }
    }

    printf("Protocol number: %d\n", proto->p_proto);
}

void print_packets(const struct pcap_pkthdr *header, const u_char *packet) {
    
    
    // Print the packet data as hexadecimal and ASCII
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");

    int i;
    printf("Packet captured! Length: %d\n", header->len);

    for (i = 0; i < header->len; ++i) {
        printf("%02x", packet[i]);
        if ((i + 1) % PAGEWIDTH == 0) // Print newline after every 16 bytes
            printf("\n");
    }

    printf("\n\n##########################\n\n");
    
    printf("\nASCII representation:\n");
    for (i = 0; i < header->len; ++i) {
        if (isprint(packet[i])) {
            printf("%c", packet[i]);
        } else {
            printf(".");
        }
        if ((i + 1) % PAGEWIDTH == 0) // Print newline after every 16 characters
            printf("\n");
    }

    printf("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");

    printf("\n\n\n\n");

}
