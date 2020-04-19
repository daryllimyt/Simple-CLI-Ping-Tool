#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <exception>
#include <iostream>
#include <iomanip>

#define PACKET_SIZE 1024
#define PORT_NO 0
#define CHRONO_TYPE std::chrono::time_point<std::chrono::high_resolution_clock>
pid_t pid;             // process id type
int data_length = 56;  // well-formed ping packet size
int sock;
int nsent=0, nreceived=0;
sockaddr_in outgoing_addr;
sockaddr_in incoming_addr;
u_char out_buffer[PACKET_SIZE];
u_char in_buffer[PACKET_SIZE];
CHRONO_TYPE t_start, t_end;

void ping();
void receive();
void statistics(int signal);
u_short checksum(u_short *b, int len);
bool debug = false;

int main(int argc, char *argv[]) {
    try {
        // Check args
        if (argc < 2) {  // missing ip address/port argument
            throw std::runtime_error("[ERROR] Missing ip address as positional terminal argument.");
        }

        // Initialize protocol
        protoent *protocol;
        protocol = getprotobyname("icmp");
        if (!protocol) throw std::runtime_error("[ERROR] getprotobyname error.");

        // Instantiate socket
        sock = socket(PF_INET, SOCK_RAW, protocol->p_proto /* ICMP protocol */);
        if (sock <= 0) throw std::runtime_error("[ERROR] socket error.");

        // Socket options
        const int val = 255;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));  // set buffer size for input, size only matters for tcp
        bzero(&outgoing_addr, sizeof(outgoing_addr));
        outgoing_addr.sin_family = AF_INET;
        outgoing_addr.sin_port = htons(PORT_NO);

        // Initialize hostname
        hostent *hostname;
        u_int inaddr = inet_addr(argv[1]);
        if (inaddr == INADDR_NONE) {
            if ((hostname = gethostbyname(argv[1])) == NULL) throw std::runtime_error("[ERROR] gethostbyname error.");
            memcpy((char *)&outgoing_addr.sin_addr, hostname->h_addr, hostname->h_length);  // copy hostname addr to packet
        } else {
            outgoing_addr.sin_addr.s_addr = inet_addr(argv[1]);
        }

        // Ping
        std::cout << "PING " << argv[1] << "(" << inet_ntoa(outgoing_addr.sin_addr) << "): " << data_length << " data bytes\n";
        signal(SIGINT, statistics);
        while (1) {
            pid = getpid();  // unique process id
            ping();
            receive();
            sleep(1);
        }
        return 0;
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

// Generate checksum
u_short checksum(u_short *b, int len) {
    int sum = 0;
    u_short result = 0;
    u_short *buffer = b;

    // Adding 16 bit segments of the packet (len is in number of bytes)
    for (; len > 1; len -= 2) {
        sum += *buffer++;
    }
    // For odd numbers
    if (len == 1) {
        sum += *(u_char *)buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);  // Carries
    sum += (sum >> 16);
    result = ~sum;  // 1's complement
    return result;
}

void ping() {
    try {
        // Pack data
        int packet_size;
        icmp *packet;

        packet = (icmp *)out_buffer;
        packet->icmp_type = ICMP_ECHO;
        packet->icmp_code = 0;
        packet->icmp_cksum = 0;
        packet->icmp_seq = nsent;
        packet->icmp_id = pid;
        packet_size = 8 + data_length;  // skip ICMP header
        packet->icmp_cksum = checksum((u_short *)packet, packet_size);
        t_start = std::chrono::high_resolution_clock::now();
        int send_result = sendto(sock, out_buffer, packet_size, 0, (struct sockaddr *)&outgoing_addr, sizeof(outgoing_addr));
        if (send_result <= 0) throw std::runtime_error("[ERROR] Sendto error.");
        nsent++;

    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
}

void receive() {
    int len;
    unsigned int incoming_len = sizeof(incoming_addr);

    // Continuously try to receive and unpack packet from host
    while (nreceived != nsent) {
        len = recvfrom(sock, in_buffer, sizeof(in_buffer), 0, (struct sockaddr *)&incoming_addr, &incoming_len);
        if (len < 0) {
            std::cerr << "[ERROR] recvfrom error.\n";
            continue;
        }

        // Non-zero length
        int iphdrlen;  // ip header length
        ip *ip_addr;   // ip address
        icmp *packet;  // icmp packet

        ip_addr = (ip *)in_buffer;  // ip pointer cast on buffer
        iphdrlen = ip_addr->ip_hl << 2;
        packet = (icmp *)(in_buffer + iphdrlen); // cast packet onto buffer skipping header
        len -= iphdrlen; // length of packet without header

        if (len < 8 || !(packet->icmp_type == ICMP_ECHOREPLY) || !(packet->icmp_id == pid)) {
            continue;
        }
        nreceived++;
        // Only reach this point if the packet is complete
        t_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<float> duration = (t_end - t_start)*1000; // Conversion to ms
        auto rtt = duration.count();
        std::cout
            << len << " bytes from " << inet_ntoa(incoming_addr.sin_addr)
            << ": icmp_seq=" << packet->icmp_seq
            // << " ttl=" << ip_addr->ip_ttl
            << ", time=" << std::setprecision(4) << rtt << " ms, "
            << nsent << " packets transmitted, "
            << nreceived << " packets received, " 
            << ((nsent - nreceived) / nsent * 100) << "% packet loss\n";
    }
}

// Display ping statistics upon interrupt
void statistics(int signal) {
    std::cout << "\n-------- PING STATISTICS --------\n";
    std::cout << nsent << " total packets transmitted, "
    << nreceived << " total packets received, " 
    << std::setprecision(4) << ((nsent - nreceived) / nsent * 100) << "% packet loss\n";
    exit(0);
}