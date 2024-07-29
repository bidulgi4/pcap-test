#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; /* 목적지 이더넷 주소 */
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; /* 출발지 이더넷 주소 */
    u_int16_t ether_type;                  /* 프로토콜 */
};

struct libnet_ipv4_hdr {
    u_int8_t ip_vhl;         /* 버전 << 4 | 헤더 길이 >> 2 */
    u_int8_t ip_tos;         /* 서비스 유형 */
    u_int16_t ip_len;        /* 총 길이 */
    u_int16_t ip_id;         /* 식별자 */
    u_int16_t ip_off;        /* 조각 오프셋 필드 */
    u_int8_t ip_ttl;         /* 생존 시간 */
    u_int8_t ip_p;           /* 프로토콜 */
    u_int16_t ip_sum;        /* 체크섬 */
    struct in_addr ip_src, ip_dst; /* 출발지 및 목적지 주소 */
};

struct libnet_tcp_hdr {
    u_int16_t th_sport;      /* 출발지 포트 */
    u_int16_t th_dport;      /* 목적지 포트 */
    u_int32_t th_seq;        /* 시퀀스 번호 */
    u_int32_t th_ack;        /* 확인 응답 번호 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4, th_off:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4, th_x2:4;
#endif
    u_int8_t  th_flags;      /* 제어 플래그 */
    u_int16_t th_win;        /* 윈도우 크기 */
    u_int16_t th_sum;        /* 체크섬 */
    u_int16_t th_urp;        /* 긴급 포인터 */
};

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)bytes;

    // 이더넷 헤더
    printf("이더넷 헤더\n");
    printf("\t|- 목적지 MAC 주소: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", eth->ether_dhost[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");

    printf("\t|- 출발지 MAC 주소: ");
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", eth->ether_shost[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");

    if (ntohs(eth->ether_type) == 0x0800) { // IPv4 확인
        struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr *)(bytes + sizeof(struct libnet_ethernet_hdr));
        
        // IP 헤더 길이 확인
        if (h->len < sizeof(struct libnet_ethernet_hdr) + (ip_header->ip_vhl & 0x0F) * 4) {
            printf("패킷이 IP 헤더를 포함하지 않음\n");
            return;
        }

        struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(bytes + sizeof(struct libnet_ethernet_hdr) + ((ip_header->ip_vhl & 0x0F) * 4));

        // TCP 헤더 길이 확인
        if (h->len < sizeof(struct libnet_ethernet_hdr) + ((ip_header->ip_vhl & 0x0F) * 4) + (tcp_header->th_off * 4)) {
            printf("패킷이 TCP 헤더를 포함하지 않음\n");
            return;
        }

        // IP 헤더
        struct in_addr src = ip_header->ip_src;
        struct in_addr dst = ip_header->ip_dst;
        printf("IP 헤더\n");
        printf("\t|- 출발지 IP 주소: %s\n", inet_ntoa(src));
        printf("\t|- 목적지 IP 주소: %s\n", inet_ntoa(dst));

        // TCP 헤더
        if (ip_header->ip_p == IPPROTO_TCP) {
            printf("TCP 헤더\n");
            printf("\t|- 출발지 포트: %u\n", ntohs(tcp_header->th_sport));
            printf("\t|- 목적지 포트: %u\n", ntohs(tcp_header->th_dport));
        }

        // 페이로드
        int ip_header_len = (ip_header->ip_vhl & 0x0F) * 4;
        int tcp_header_len = tcp_header->th_off * 4;
        int payload_offset = sizeof(struct libnet_ethernet_hdr) + ip_header_len + tcp_header_len;
        int payload_length = h->caplen - payload_offset;
        int print_length = payload_length > 20 ? 20 : payload_length;
        const u_char *payload = bytes + payload_offset;

        printf("데이터 (Hex): ");
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
        fprintf(stderr, "사용법: %s <인터페이스>\n예시: %s wlan0\n", argv[0], argv[0]);
        return 2;
    }

    dev = argv[1];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치를 열 수 없습니다 %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("장치: %s\n", dev);
    printf("캡처 시작\n");

    int packet_count = 0;
    struct pcap_pkthdr header;
    while (packet_count < 3) {
        const u_char *packet = pcap_next(handle, &header);
        if (packet == NULL) {
            fprintf(stderr, "패킷 읽기 오류: %s\n", pcap_geterr(handle));
            continue;
        }

        packet_handler(NULL, &header, packet);
        packet_count++;
    }

    pcap_close(handle);
    printf("캡처 종료\n");
    return 0;
}

