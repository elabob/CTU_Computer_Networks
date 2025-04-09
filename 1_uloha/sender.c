#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
/* ked sa budes uz po x-ty krat zase zamyslat co to je: funkcie na pracu s  
internetovymi adresami; prevod IP adresy zo stringu do binarky */

#include <unistd.h> 
/*funkcie na pracu s operacnym systemom, ako je close (na zatvorenie socketu).*/

#define PACKET_MAX_LEN 1024
#define PAYLOAD_SIZE 1020

enum PacketType {
    START = 0,
    FILESIZE = 1,
    FILENAME = 2,
    DATA = 3,
    STOP = 4
};

struct Packet {
    uint32_t packet_type;
    char payload[PAYLOAD_SIZE];
};

void send_packet(int sock, struct sockaddr_in *receiver, struct Packet *packet) {
    char packet_tx[PACKET_MAX_LEN];
    memcpy(packet_tx, (unsigned char *)packet, sizeof(*packet));
    sendto(sock, packet_tx, sizeof(packet_tx), 0, (struct sockaddr *)receiver, sizeof(*receiver)); // send UDP pcket
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("ERROR: Usage: %s <IP> <PORT> <FILE>\n", argv[0]); // shhow how to use
        return 1;
    }

    char *receiver_ip = argv[1];
    int receiver_port = atoi(argv[2]);
    char *file_name = argv[3];

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error creat socket");
        return 1;
    }

    struct sockaddr_in receiver;
    memset(&receiver, 0, sizeof(receiver));
    receiver.sin_family = AF_INET;
    receiver.sin_port = htons(receiver_port);
    inet_pton(AF_INET, receiver_ip, &receiver.sin_addr);

    FILE *file = fopen(file_name, "rb");
    if (!file) {
        perror("Error open file");
        return 1;
    }

    struct Packet packet;

    packet.packet_type = START;
    send_packet(sock, &receiver, &packet);

    packet.packet_type = FILENAME;
    memset(packet.payload, 0, PAYLOAD_SIZE);
    memcpy(packet.payload, file_name, strlen(file_name));
    send_packet(sock, &receiver, &packet);

    fseek(file, 0, SEEK_END);
    uint32_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    packet.packet_type = FILESIZE;
    memcpy(packet.payload, &file_size, sizeof(file_size));
    send_packet(sock, &receiver, &packet);

    while (!feof(file)) {
        packet.packet_type = DATA;
        memset(packet.payload, 0, PAYLOAD_SIZE);
        int read_size = fread(packet.payload, 1, PAYLOAD_SIZE, file);
        send_packet(sock, &receiver, &packet);
    }

    packet.packet_type = STOP;
    send_packet(sock, &receiver, &packet);

    fclose(file);
    close(sock);
    printf("File send complete.\n");
    return 0;
}
