#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>


#include <unistd.h> 

#define PACKET_MAX_LEN 1024
#define PAYLOAD_SIZE 1020

#define MAX_FILE_NAME_LEN 200

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

int receive_packet(int sock, struct sockaddr_in *reciever, struct Packet *packet) {
    char buffer[PACKET_MAX_LEN];
    socklen_t reciever_len = sizeof(*reciever);

    ssize_t received_bytes = recvfrom(sock, buffer, PACKET_MAX_LEN, 0, (struct sockaddr *)reciever, &reciever_len);
    //identifikator socketu, kam se ulozi data, maximalni delka dat, flagy, adresa odesilatele, delka asresy

    if (received_bytes < sizeof(uint32_t)) {
        fprintf(stderr, "Too small packet.\n");
        return 1; 
    }

    
    memcpy(packet, buffer, sizeof(struct Packet));

    return 0; 
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("ERROR: Usage: %s <PORT>\n", argv[0]); 
        return 1;
    }

    int receiver_port = atoi(argv[1]);


    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error creat socket");
        return 1;
    }

    struct sockaddr_in receiver;
    memset(&receiver, 0, sizeof(receiver));
    receiver.sin_family = AF_INET;
    receiver.sin_port = htons(receiver_port);
    receiver.sin_addr.s_addr = INADDR_ANY;      // prijma na jakekoliv adrese prirazene pocitaci

    if (bind(sock, (struct sockaddr *)&receiver, sizeof(receiver)) < 0) {
        fprintf(stderr, "Bind failed");
        close(sock);
        return 1;
    }


    struct Packet packet;
    

    if(receive_packet(sock, &receiver, &packet) != 0){
        return 1;
    }
    if(packet.packet_type != START){
        return 1;
    }

    if(receive_packet(sock, &receiver, &packet) != 0){
        return 1;
    }

    char output_file_name[MAX_FILE_NAME_LEN];
    if (packet.packet_type == FILENAME) {
        strncpy(output_file_name, packet.payload, sizeof(output_file_name) - 1);  
        output_file_name[sizeof(output_file_name) - 1] = '\0';  
    }
    else{
        return 1;
    }

    FILE *file = fopen("cat.jpg","wb");
    if (!file) {
        fprintf(stderr, "Error open file");
        return 1;
    }

    if(receive_packet(sock, &receiver, &packet) != 0){
        fclose(file);
        return 1;
    }

    uint32_t file_size;
    if(packet.packet_type == FILESIZE){
        memcpy(&file_size, packet.payload, sizeof(file_size));  
    }
    

    uint32_t received_bytes_total = 0;
    while (1) {
        if (receive_packet(sock, &receiver, &packet) != 0) {
            fclose(file);
            return 1;
        }
        if (packet.packet_type == DATA) {
            int to_write = PAYLOAD_SIZE;
            if (received_bytes_total + PAYLOAD_SIZE > file_size) {
                to_write = file_size - received_bytes_total;
            }
            fwrite(packet.payload, 1, to_write, file);
            received_bytes_total += to_write;
        } else if (packet.packet_type == STOP) {
            break;
        }
    }
    

    fclose(file);
    close(sock);
    printf("File send complete.\n");
    return 0;
}
