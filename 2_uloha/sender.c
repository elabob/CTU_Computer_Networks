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
#define TIMEOUT_MS 1000
#define MAX_RETRIES 10

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
void send_packet_with_retry(int sock, struct sockaddr_in *receiver, struct Packet *packet);
void calculate_file_hash(const char *filename, unsigned char hash[SHA256_DIGEST_LENGTH]);

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("ERROR: Usage: %s <IP> <PORT> <FILE>\n", argv[0]);
        return 1;
    }

    char *receiver_ip = argv[1];
    int receiver_port = atoi(argv[2]);
    char *file_name = argv[3];

    // Vytvorime socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error creating socket");
        return 1;
    }

    // Nastavenie lokálneho portu pre sender podľa NetDerper schémy
    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;
    sender_addr.sin_addr.s_addr = INADDR_ANY;
    sender_addr.sin_port = htons(15001);  // Lokálny port sendera podľa NetDerper schémy

    // Bindovanie socketu na lokálny port
    if (bind(sock, (struct sockaddr *)&sender_addr, sizeof(sender_addr)) < 0) {
        perror("Error binding socket");
        close(sock);
        return 1;
    }

    // Nastavenie cieľovej adresy - port 14000 podľa NetDerper
    struct sockaddr_in receiver_addr;
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(14000);  // Cieľový port 14000 podľa NetDerper
    inet_pton(AF_INET, receiver_ip, &receiver_addr.sin_addr);

    // Nastavenie timeoutu pre prijatie odpovede
    struct timeval tv;
    tv.tv_sec = TIMEOUT_MS / 1000;
    tv.tv_usec = (TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Otvorenie súboru
    FILE *file = fopen(file_name, "rb");
    if (!file) {
        perror("Error opening file");
        close(sock);
        return 1;
    }

    struct Packet packet;
    uint32_t sequence_number = 0;
    
    // Výpočet SHA-256 hash súboru
    unsigned char file_hash[SHA256_DIGEST_LENGTH];
    calculate_file_hash(file_name, file_hash);

    // Poslanie START paketu s hash súboru
    packet.packet_type = START;
    packet.sequence_number = sequence_number++;
    memset(packet.payload, 0, PAYLOAD_SIZE);
    memcpy(packet.payload, file_hash, SHA256_DIGEST_LENGTH);
    packet.crc32 = 0;
    packet.crc32 = xcrc32((unsigned char *)&packet, sizeof(packet) - sizeof(uint32_t), 0xFFFFFFFF);
    send_packet_with_retry(sock, &receiver_addr, &packet);
    
    // Poslanie názvu súboru
    packet.packet_type = FILENAME;
    packet.sequence_number = sequence_number++;
    memset(packet.payload, 0, PAYLOAD_SIZE);
    
    // Ziskanie iba nazvu suboru cez cesty
    char *base_name = strrchr(file_name, '/');
    if (base_name) {
        strncpy(packet.payload, base_name + 1, PAYLOAD_SIZE - 1);
    } else {
        strncpy(packet.payload, file_name, PAYLOAD_SIZE - 1);
    }
    
    packet.crc32 = 0;
    packet.crc32 = xcrc32((unsigned char *)&packet, sizeof(packet) - sizeof(uint32_t), 0xFFFFFFFF);
    send_packet_with_retry(sock, &receiver_addr, &packet);

    // Zistenie velkosti suboru
    fseek(file, 0, SEEK_END);
    uint32_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Poslanie velkosti suboru
    packet.packet_type = FILESIZE;
    packet.sequence_number = sequence_number++;
    memset(packet.payload, 0, PAYLOAD_SIZE);
    memcpy(packet.payload, &file_size, sizeof(file_size));
    packet.crc32 = 0;
    packet.crc32 = xcrc32((unsigned char *)&packet, sizeof(packet) - sizeof(uint32_t), 0xFFFFFFFF);
    send_packet_with_retry(sock, &receiver_addr, &packet);
    
    // Posielanie dat suboru
    uint32_t position = 0;
    size_t read_size;
    
    while (position < file_size) {
        packet.packet_type = DATA;
        packet.sequence_number = sequence_number++;
        memset(packet.payload, 0, PAYLOAD_SIZE);
        
        fseek(file, position, SEEK_SET);
        read_size = fread(packet.payload, 1, PAYLOAD_SIZE, file);
        
        packet.crc32 = 0;
        packet.crc32 = xcrc32((unsigned char *)&packet, sizeof(packet) - sizeof(uint32_t), 0xFFFFFFFF);
        send_packet_with_retry(sock, &receiver_addr, &packet);
        
        position += read_size;
        printf("Progress: %.2f%%\r", (float)position / file_size * 100);
        fflush(stdout);
    }
    printf("\n");

    // Poslanie STOP paketu
    packet.packet_type = STOP;
    packet.sequence_number = sequence_number++;
    memset(packet.payload, 0, PAYLOAD_SIZE);
    packet.crc32 = 0;
    packet.crc32 = xcrc32((unsigned char *)&packet, sizeof(packet) - sizeof(uint32_t), 0xFFFFFFFF);
    send_packet_with_retry(sock, &receiver_addr, &packet);
    
    fclose(file);
    close(sock);
    printf("File transfer completed successfully.\n");
    return 0;
}

// Funkcia na posielanie paketu s opakovanymi pokusmi
void send_packet_with_retry(int sock, struct sockaddr_in *receiver, struct Packet *packet) {
    char packet_buffer[PACKET_MAX_LEN];
    char ack_buffer[PACKET_MAX_LEN];
    struct Packet ack_packet;
    int retries = 0;
    
    // Cieľová adresa pre ACK/NACK odpovede
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    
    while (retries < MAX_RETRIES) {
        // Odoslanie paketu
        memcpy(packet_buffer, packet, sizeof(*packet));
        if (sendto(sock, packet_buffer, sizeof(*packet), 0, (struct sockaddr *)receiver, sizeof(*receiver)) < 0) {
            perror("Error sending packet");
            exit(1);
        }
        
        // Prijatie ACK/NACK odpovede - očakávame z portu 14001 podľa NetDerper schémy
        ssize_t recv_len = recvfrom(sock, ack_buffer, PACKET_MAX_LEN, 0, 
                                    (struct sockaddr *)&sender_addr, &sender_len);
        
        if (recv_len > 0) {
            memcpy(&ack_packet, ack_buffer, sizeof(ack_packet));
            
            // Kontrola spravnosti CRC prijateho potvrdenia
            uint32_t received_crc = ack_packet.crc32;
            ack_packet.crc32 = 0;
            uint32_t calculated_crc = xcrc32((unsigned char *)&ack_packet, sizeof(ack_packet) - sizeof(uint32_t), 0xFFFFFFFF);
            
            if (calculated_crc != received_crc) {
                printf("ACK/NACK CRC error, retrying...\n");
                retries++;
                continue;
            }
            
            if (ack_packet.sequence_number == packet->sequence_number) {
                if (ack_packet.packet_type == ACK) {
                    return;  // Uspesne potvrdenie
                } else if (ack_packet.packet_type == NACK) {
                    printf("Received NACK for packet %u, retrying...\n", packet->sequence_number);
                }
            } else {
                printf("Sequence number mismatch in ACK, expected %u, got %u\n", 
                       packet->sequence_number, ack_packet.sequence_number);
            }
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Timeout waiting for ACK for packet %u, retrying...\n", packet->sequence_number);
        } else {
            perror("Error receiving ACK");
        }
        
        retries++;
    }
    
    fprintf(stderr, "Failed to send packet after %d retries, giving up.\n", MAX_RETRIES);
    exit(1);
}

// Vypocet SHA-256 hash suboru
void calculate_file_hash(const char *filename, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for hash calculation");
        exit(1);
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

// CRC-32 implementacia
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