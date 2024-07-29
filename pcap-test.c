#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr {
    u_int8_t ip_vhl;          /* version << 4 | header length >> 2 */
    u_int8_t ip_tos;          /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;         /* fragment offset field */
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr {
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;         /* sequence number */
    u_int32_t th_ack;         /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4, th_off:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4, th_x2:4;
#endif
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)bytes;
   	
    //ethernet header
    printf("ethernet header\n");
    printf("\t|-Destination MAC Address: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    	printf("%02x", eth->ether_dhost[i]);
    	if (i < ETHER_ADDR_LEN - 1) printf(":");
	}	
	printf("\n");

    printf("\t|-Source MAC Address: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    	printf("%02x", eth->ether_shost[i]);
    	if (i < ETHER_ADDR_LEN - 1) printf(":");
}
	printf("\n");

	 if (ntohs(eth->ether_type) == 0x0800) {
        struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr *)(bytes + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(bytes + sizeof(struct libnet_ethernet_hdr) + ((ip_header->ip_vhl & 0x0F) * 4));

	//ip header
	struct in_addr src = ip_header->ip_src;
	struct in_addr dst = ip_header->ip_dst;
	printf("ip header\n");
	printf("\t|-Source address IP:%s\n",inet_ntoa(src));
	printf("\t|-Destination IP Address: %s\n", inet_ntoa(dst));
	
	//tcp header	
	if(ip_header->ip_p == IPPROTO_TCP) {
	printf("Tcp header\n");
	printf("\t|-Source Port: %u\n", ntohs(tcp_header->th_sport));
	printf("\t|-Dest Port: %u\n", ntohs(tcp_header->th_dport));}

	int payload_offset = sizeof(struct libnet_ethernet_hdr) + ((ip_header->ip_vhl & 0x0F) * 4) + (tcp_header->th_off * 4);
        int payload_length = h->caplen - payload_offset;
        int print_length = payload_length > 20 ? 20 : payload_length;
        const u_char *payload = bytes + payload_offset;

        printf("Data (Hex): ");
        for (int i = 0; i < print_length; i++) {
        printf("%02x ", payload[i]);
}
	printf("\n------------------------------------------------------------------\n");
}

}

int main(int argc, char *argv[]) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\nExample: %s wlan0\n", argv[0], argv[0]);
        return 2;
    }

    dev = argv[1];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Device: %s\n", dev);
    printf("Capture start\n");

    int packet_count = 0;
    while (packet_count < 3) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (packet == NULL) {
            fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(handle));
            continue;
        }

        packet_handler(NULL, &header, packet);
        packet_count++;

    	printf("3 packets captured\n");
    	pcap_close(handle);
    }
    	printf("Capture end\n");
}
