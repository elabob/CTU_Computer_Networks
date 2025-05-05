#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>

#define PACKET_MAX_LEN 1024
#define PAYLOAD_SIZE 1012
#define RECV_TIMEOUT_MS 5000

enum PacketType {
    START = 0,
    FILESIZE = 1,
    FILENAME = 2,
    DATA = 3,
    STOP = 4,
    ACK = 5,
    NACK = 6
};

struct Packet {
    uint32_t packet_type;
    uint32_t sequence_number;
    char payload[PAYLOAD_SIZE];
    uint32_t crc32;
};

unsigned int xcrc32(const unsigned char *buf, int len, unsigned int init);
void send_ack(int sock, struct sockaddr_in *sender, uint32_t sequence_number);
void send_nack(int sock, struct sockaddr_in *sender, uint32_t sequence_number);
void calculate_file_hash(const char *filename, unsigned char hash[SHA256_DIGEST_LENGTH]);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("ERROR: Usage: %s <PORT> <OUTPUT_PREFIX>\n", argv[0]);
        return 1;
    }

    int listen_port = atoi(argv[1]);
    char *output_prefix = argv[2];

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error creating socket");
        return 1;
    }

    struct sockaddr_in receiver_addr;
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    receiver_addr.sin_port = htons(listen_port);

    if (bind(sock, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) < 0) {
        perror("Error binding socket");
        close(sock);
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = RECV_TIMEOUT_MS / 1000;
    tv.tv_usec = (RECV_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("Receiver started on port %d. Waiting for data...\n", listen_port);

    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    char packet_buffer[PACKET_MAX_LEN];
    struct Packet packet;
    
    FILE *output_file = NULL;
    char output_filename[PAYLOAD_SIZE + 100] = {0};
    uint32_t file_size = 0;
    uint32_t current_position = 0;
    uint32_t expected_sequence = 0;
    unsigned char received_hash[SHA256_DIGEST_LENGTH] = {0};
    int in_transfer = 0;

    while (1) {
        memset(packet_buffer, 0, PACKET_MAX_LEN);
        ssize_t recv_len = recvfrom(sock, packet_buffer, PACKET_MAX_LEN, 0, 
                                   (struct sockaddr *)&sender_addr, &sender_len);
        
        sender_addr.sin_port=htons(atoi("14001"));
                                   
        
        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Timeout waiting for packet. Receiver still listening...\n");
                continue;
            } else {
                perror("Error receiving data");
                continue;
            }
        }
        
        memcpy(&packet, packet_buffer, sizeof(packet));
        
        // Kontrola CRC
        uint32_t received_crc = packet.crc32;
        packet.crc32 = 0;
        uint32_t calculated_crc = xcrc32((unsigned char *)&packet, sizeof(packet) - sizeof(uint32_t), 0xFFFFFFFF);
        
        if (calculated_crc != received_crc) {
            printf("CRC error in packet %u, sending NACK\n", packet.sequence_number);
            send_nack(sock, &sender_addr, packet.sequence_number);
            continue;
        }
        
        // Kontrola poradoveho cisla paketu
        if (packet.sequence_number != expected_sequence) {
            printf("Sequence number mismatch: expected %u, got %u\n", expected_sequence, packet.sequence_number);
            
            // Ak sme uz tento paket spracovali, posleme ACK (mozno sa ACK stratil)
            if (packet.sequence_number < expected_sequence) {
                printf("Duplicate packet detected, sending ACK again\n");
                send_ack(sock, &sender_addr, packet.sequence_number);
            } else {
                // Neocakavane cislo sekvencie, odmietame paket
                send_nack(sock, &sender_addr, packet.sequence_number);
            }
            continue;
        }
        
        // Spracovanie paketu na zaklade typu
        switch (packet.packet_type) {
            case START:
                printf("Received START packet\n");
                memcpy(received_hash, packet.payload, SHA256_DIGEST_LENGTH);
                in_transfer = 1;
                expected_sequence++;
                send_ack(sock, &sender_addr, packet.sequence_number);
                break;
                
            case FILENAME:
                printf("Received FILENAME packet\n");
                if (!in_transfer) {
                    printf("Error: FILENAME packet received without START\n");
                    send_nack(sock, &sender_addr, packet.sequence_number);
                    continue;
                }
                
                snprintf(output_filename, sizeof(output_filename), "%s_%s", output_prefix, packet.payload);
                printf("Output filename will be: %s\n", output_filename);
                
                expected_sequence++;
                send_ack(sock, &sender_addr, packet.sequence_number);
                break;
                
            case FILESIZE:
                printf("Received FILESIZE packet\n");
                if (!in_transfer || output_filename[0] == '\0') {
                    printf("Error: FILESIZE packet received in wrong order\n");
                    send_nack(sock, &sender_addr, packet.sequence_number);
                    continue;
                }
                
                memcpy(&file_size, packet.payload, sizeof(file_size));
                printf("File size: %u bytes\n", file_size);
                
                output_file = fopen(output_filename, "wb");
                if (!output_file) {
                    perror("Error opening output file");
                    send_nack(sock, &sender_addr, packet.sequence_number);
                    continue;
                }
                
                current_position = 0;
                expected_sequence++;
                send_ack(sock, &sender_addr, packet.sequence_number);
                break;
                
            case DATA:
                if (!in_transfer || !output_file) {
                    printf("Error: DATA packet received in wrong order\n");
                    send_nack(sock, &sender_addr, packet.sequence_number);
                    continue;
                }
                
                size_t data_size;
                if (current_position + PAYLOAD_SIZE > file_size) {
                    data_size = file_size - current_position;
                } else {
                    data_size = PAYLOAD_SIZE;
                }
                
                size_t written = fwrite(packet.payload, 1, data_size, output_file);
                if (written != data_size) {
                    perror("Error writing to output file");
                    send_nack(sock, &sender_addr, packet.sequence_number);
                    continue;
                }
                
                current_position += data_size;
                printf("Progress: %.2f%%\r", (float)current_position / file_size * 100);
                fflush(stdout);
                
                expected_sequence++;
                send_ack(sock, &sender_addr, packet.sequence_number);
                break;
                
            case STOP:
                printf("\nReceived STOP packet\n");
                if (!in_transfer || !output_file) {
                    printf("Error: STOP packet received in wrong order\n");
                    send_nack(sock, &sender_addr, packet.sequence_number);
                    continue;
                }
                
                fclose(output_file);
                output_file = NULL;
                
                unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
                calculate_file_hash(output_filename, calculated_hash);
                
                int hash_match = 1;
                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    if (calculated_hash[i] != received_hash[i]) {
                        hash_match = 0;
                        break;
                    }
                }
                
                if (hash_match) {
                    printf("SHA-256 verification SUCCESSFUL! File transfer complete.\n");
                    printf("File saved as: %s\n", output_filename);
                } else {
                    printf("SHA-256 verification FAILED! File may be corrupted.\n");
                }
                
                // Posielame ACK aj pri zlyhani hash, pretoze prenos na urovni
                // paketov prebehol spravne
                send_ack(sock, &sender_addr, packet.sequence_number);
                
                // Reset pre dalsi potencialny prenos
                in_transfer = 0;
                expected_sequence = 0;
                memset(output_filename, 0, sizeof(output_filename));
                file_size = 0;
                current_position = 0;
                break;
                
            default:
                printf("Received unknown packet type: %u\n", packet.packet_type);
                send_nack(sock, &sender_addr, packet.sequence_number);
                continue;
        }
    }
    
    close(sock);
    return 0;
}

void send_ack(int sock, struct sockaddr_in *sender, uint32_t sequence_number) {
    struct Packet ack_packet;
    char ack_buffer[PACKET_MAX_LEN];
    
    ack_packet.packet_type = ACK;
    ack_packet.sequence_number = sequence_number;
    memset(ack_packet.payload, 0, PAYLOAD_SIZE);
    ack_packet.crc32 = 0;
    ack_packet.crc32 = xcrc32((unsigned char *)&ack_packet, sizeof(ack_packet) - sizeof(uint32_t), 0xFFFFFFFF);
    
    memcpy(ack_buffer, &ack_packet, sizeof(ack_packet));
    sendto(sock, ack_buffer, sizeof(ack_packet), 0, (struct sockaddr *)sender, sizeof(*sender));
}


void send_nack(int sock, struct sockaddr_in *sender, uint32_t sequence_number) {
    struct Packet nack_packet;
    char nack_buffer[PACKET_MAX_LEN];
    
    nack_packet.packet_type = NACK;
    nack_packet.sequence_number = sequence_number;
    memset(nack_packet.payload, 0, PAYLOAD_SIZE);
    nack_packet.crc32 = 0;
    nack_packet.crc32 = xcrc32((unsigned char *)&nack_packet, sizeof(nack_packet) - sizeof(uint32_t), 0xFFFFFFFF);
    
    memcpy(nack_buffer, &nack_packet, sizeof(nack_packet));
    sendto(sock, nack_buffer, sizeof(nack_packet), 0, (struct sockaddr *)sender, sizeof(*sender));
}


void calculate_file_hash(const char *filename, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for hash calculation");
        return;
    }
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    const int buffer_size = 8192;
    unsigned char buffer[buffer_size];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, buffer_size, file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }
    
    SHA256_Final(hash, &sha256);
    fclose(file);
}

unsigned int xcrc32(const unsigned char *buf, int len, unsigned int init) {
    static const unsigned int crc32_table[] = {     
        0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
        0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
        0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
        0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
        0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
        0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
        0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
        0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
        0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
        0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
        0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
        0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
        0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
        0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
        0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
        0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
        0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
        0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
        0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
        0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
        0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
        0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
        0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
        0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
        0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
        0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
        0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
        0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
        0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
        0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
        0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
        0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
        0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
        0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
        0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
        0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
        0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
        0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
        0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
        0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
        0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
        0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
        0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
        0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
        0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
        0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
        0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
        0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
        0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
        0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
        0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
        0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
    };

    unsigned int crc = init;
    while (len--) {
        crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ *buf) & 255];
        buf++;
    }
    return crc;
}
