#define __USE_BSD         /* Using BSD IP header           */ 
#include <netinet/ip.h>   /* Internet Protocol             */ 
#define __FAVOR_BSD       /* Using BSD TCP header          */ 
#include <netinet/tcp.h> /* Transmission Control Protocol */ 
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "network/state.h"
#include "network/utilities.h"

#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <signal.h>

static protocol *state;
static char *outfile;
static char *buffer;
static int current_size;
static char *ip_server;
static int port_server;
static u_char protocol_server;

static void usage(int err)
{
    fprintf(stderr, "Usage: ./interceptor -m <protocol> -i <ip_address> -p <port> -d <device> -o <outfile>\n");
    exit(err);
}

static void sig_handler(int sig)
{
    if (sig == SIGINT) {
        if (current_size > 0) {
            if (state->size == 0) {
                messages* new_msg = newMsg(current_size, buffer, NULL);
                state->start_msg = new_msg;
                state->end_msg = new_msg;
                state->size = 1;
            } else {
                state->end_msg = newMsg(current_size, buffer, state->end_msg);
                state->size ++;
            }
        }
        messages *cur_msg = getCurMsg(state);
        debugProtocol(state);
        serialize(state, 0, cur_msg->data, cur_msg->size, outfile);
        deleteProtocol(state);
        puts ("Done generating record!");
        exit(0);
    } else {
        fprintf(stderr, "wasn't expecting that!\n");
        abort();
    }		
}

static void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const u_char *ip_header;
    const u_char *tcp_header, *udp_header, *icmp_header;
    const u_char *payload;
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length, udp_header_length, icmp_header_length;
    int payload_length;
    struct ip* ip_info;
    struct tcphdr* tcp_info;
    struct udphdr* udp_info;
    struct icmphdr* icmp_info;
    int total_headers_size;

    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);
    if (protocol != protocol_server) {
        printf("Not our desired protocol. Skipping...\n\n");
        return;
    }

    ip_info = (struct ip *)ip_header;

    if ( protocol == IPPROTO_TCP ) {
        tcp_header = packet + ethernet_header_length + ip_header_length;

        tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
        tcp_header_length = tcp_header_length * 4;
        printf("TCP header length in bytes: %d\n", tcp_header_length);


        tcp_info = (struct tcphdr *)tcp_header;

        printf("Source: %s ---- %d\n", inet_ntoa(ip_info->ip_src), ntohs(tcp_info->th_sport));
        printf("Destination: %s ---- %d\n", inet_ntoa(ip_info->ip_dst), ntohs(tcp_info->th_dport));

        total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
        printf("Size of all headers combined: %d bytes\n", total_headers_size);
        payload_length = header->caplen -
            (ethernet_header_length + ip_header_length + tcp_header_length);
        printf("Payload size: %d bytes\n", payload_length);
        payload = packet + total_headers_size;
        printf("Memory address where payload begins: %p\n\n", payload);

        if (payload_length > 0) {
            // const u_char *temp_pointer = payload;
            // int byte_count = 0;
            // while (byte_count++ < payload_length) {
            // 	printf("%c", *temp_pointer);
            // 	temp_pointer++;
            // }
            // printf("\n");

            if (ntohs(tcp_info->th_sport) == port_server) {
                if (current_size > 0) {
                    if (state->size == 0) {
                        messages* new_msg = newMsg(current_size, buffer, NULL);
                        state->start_msg = new_msg;
                        state->end_msg = new_msg;
                        state->size = 1;
                    } else {
                        state->end_msg = newMsg(current_size, buffer, state->end_msg);
                        state->size ++;
                    }
                }
                buffer = NULL;
                current_size = 0;
            } else {
                buffer = realloc(buffer, current_size + payload_length);
                memcpy(buffer + current_size, payload, payload_length);
                current_size += payload_length;
            }
        }
    } else if (protocol == IPPROTO_UDP) {
        udp_header = packet + ethernet_header_length + ip_header_length;
        udp_header_length = 8;

        printf("UDP header length in bytes: %d\n", udp_header_length);

        udp_info = (struct udphdr *)udp_header;

#ifdef HAVE_DUMB_UDPHDR
        printf("Source: %s ---- %d\n", inet_ntoa(ip_info->ip_src), ntohs(udp_info->source));
        printf("Destination: %s ---- %d\n", inet_ntoa(ip_info->ip_dst), ntohs(udp_info->dest));
#else
        printf("Source: %s ---- %d\n", inet_ntoa(ip_info->ip_src), ntohs(udp_info->uh_sport));
        printf("Destination: %s ---- %d\n", inet_ntoa(ip_info->ip_src), ntohs(udp_info->uh_dport));
#endif

        total_headers_size = ethernet_header_length + ip_header_length + udp_header_length;

        printf("Size of all headers combined: %d bytes\n", total_headers_size);
        payload_length = header->caplen - total_headers_size;
        printf("Payload size: %d bytes\n", payload_length);
        payload = packet + total_headers_size;
        printf("Memory address where payload begins: %p\n\n", payload);

        if (payload_length > 0) {
            // const u_char *temp_pointer = payload;
            // int byte_count = 0;
            // while (byte_count++ < payload_length) {
            // 	printf("%c", *temp_pointer);
            // 	temp_pointer++;
            // }
            // printf("\n");

#ifdef HAVE_DUMB_UDPHDR
            if (ntohs(udp_info->source) == port_server) {
#else
            if (ntohs(udp_info->uh_sport) == port_server) {
#endif
                if (current_size > 0) {
                    if (state->size == 0) {
                        messages* new_msg = newMsg(current_size, buffer, NULL);
                        state->start_msg = new_msg;
                        state->end_msg = new_msg;
                        state->size = 1;
                    } else {
                        state->end_msg = newMsg(current_size, buffer, state->end_msg);
                        state->size ++;
                    }
                }
                buffer = NULL;
                current_size = 0;
            } else {
                buffer = realloc(buffer, current_size + payload_length);
                memcpy(buffer + current_size, payload, payload_length);
                current_size += payload_length;
            }
        }
    } else if ( protocol == IPPROTO_ICMP ) { // NOT SURE
        icmp_header = packet + ethernet_header_length + ip_header_length;
        icmp_header_length = 8;

        printf("ICMP header length in bytes: %d\n", icmp_header_length);

        icmp_info = (struct icmphdr *)icmp_header;

        total_headers_size = ethernet_header_length + ip_header_length + icmp_header_length;

        printf("Size of all headers combined: %d bytes\n", total_headers_size);
        payload_length = header->caplen - total_headers_size;
        printf("Payload size: %d bytes\n", payload_length);
        payload = packet + total_headers_size;
        printf("Memory address where payload begins: %p\n\n", payload);

        if (payload_length > 0) {
            const u_char *temp_pointer = payload;
            int byte_count = 0;
            while (byte_count++ < payload_length) {
                printf("%c", *temp_pointer);
                temp_pointer++;
            }
            printf("\n");
        }
    }
}

static void init_interceptor(const char *device)
{
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;
    int total_packet_count = 200;
    u_char *my_arguments = NULL;

    char *filter_exp = calloc(1, 100);

    sprintf (filter_exp, "(dst port %d and dst %s) or src port %d", port_server, ip_server, port_server);

    state = newProtocol(0, NULL, NULL, 0);
    current_size = 0;
    buffer = NULL;

    if (pcap_lookupnet(device, &ip, &subnet_mask, error_buffer) == -1) {
        fprintf(stderr, "Could not get information for device: %s\n", device);
        exit(0);
    }

    handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
        exit(0);
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter - %s\n", pcap_geterr(handle));
        exit(0);
    }

    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);
    free (filter_exp);
}


int main (int argc, char *argv[])
{
    int opt;
    char *device;

    signal(SIGINT, sig_handler);

    if ( argc != 11 )
        usage(0);
    while ( (opt = getopt(argc, argv, "m:i:p:d:o:")) != -1 ) {
        switch (opt) {
            case 'i':
                ip_server = optarg;
                break;
            case 'p':
                port_server = atoi(optarg);
                break;
            case 'd':
                device = optarg;
                break;
            case 'o':
                outfile = optarg;
                break;
            case 'm':
                if (!strcmp(optarg, "tcp"))
                    protocol_server = IPPROTO_TCP;
                else if (!strcmp(optarg, "udp"))
                    protocol_server = IPPROTO_UDP;
                else if (!strcmp(optarg, "icmp"))
                    protocol_server = IPPROTO_ICMP;
                else {
                    fprintf(stderr, "Protocol is not supported\n");
                    return EXIT_FAILURE;
                }
                break;
            default:
                usage(0);
        }
    }

    init_interceptor(device);

    return EXIT_SUCCESS;
}

