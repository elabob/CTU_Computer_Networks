#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#define PACKET_MAX_LEN 1024
#define PAYLOAD_SIZE 1012
#define PACKET_WINDOW_SIZE 10

#define DATA_SENDING_PORT "14000"     
#define DATA_RECEIVING_PORT "15000"   
#define ACK_SENDING_PORT "15001"      
#define ACK_RECEIVING_PORT "14001"    

#define TIMEOUT_MS 500

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

void send_response(int sock, struct sockaddr_in *sender, socklen_t sender_len, uint32_t seq, uint32_t type) {
    struct Packet ack;
    ack.packet_type = type;
    ack.sequence_number = seq;
    memset(ack.payload, 0, PAYLOAD_SIZE);
    ack.crc32 = xcrc32((unsigned char*)&ack, sizeof(ack) - sizeof(uint32_t), 0xFFFFFFFF);
    sendto(sock, &ack, sizeof(ack), 0, (struct sockaddr *)sender, sender_len);
}
int wait_for_response(int sock, struct sockaddr_in *receiver, socklen_t receiver_len, uint32_t seq_num, int *is_nack) {
    struct Packet response;
    struct timeval tv;
    fd_set readfds;

    tv.tv_sec = 0;
    tv.tv_usec = TIMEOUT_MS * 1000;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    int activity = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (activity > 0) {
        recvfrom(sock, &response, sizeof(response), 0, (struct sockaddr *)receiver, &receiver_len);
        //printf("I have recieved ACK %u\n",response.sequence_number);


        if (xcrc32((unsigned char*)&response, sizeof(response) - sizeof(uint32_t), 0xFFFFFFFF) != response.crc32) {
            //printf("CRC error\n");
            return 0;
        }

        if (response.sequence_number == seq_num) {
            if (response.packet_type == ACK) {
                *is_nack = 0;
                return 1;
            } else if (response.packet_type == NACK) {
                *is_nack = 1;
                return 1;
            }
        }
        if(response.sequence_number < seq_num){
            return -1;
        }
    }
    //printf("activity error\n");
    return 0;
}

void send_packet(int sock, struct Packet *packet, struct sockaddr_in *receiver, socklen_t receiver_len) {
    packet->crc32 = xcrc32((unsigned char *)packet, sizeof(struct Packet) - sizeof(uint32_t), 0xFFFFFFFF);
    //printf("im here!\n");
    sendto(sock, packet, sizeof(struct Packet), 0, (struct sockaddr *)receiver, receiver_len);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_to_send>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    uint32_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Compute SHA-256
    unsigned char sha_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[PAYLOAD_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, PAYLOAD_SIZE, file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes);
    }
    SHA256_Final(sha_hash, &sha256);
    fseek(file, 0, SEEK_SET);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        fclose(file);
        return 1;
    }

    // Set up the local binding for receiving ACKs
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(atoi(ACK_SENDING_PORT)); // Local port for receiving ACKs
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        close(sock);
        return 1;
    }

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    // Set up target address for sending data
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(atoi(DATA_SENDING_PORT)); // Target port for data
    remote_addr.sin_addr.s_addr = inet_addr("127.0.0.1");    // Target IP

    socklen_t remote_len = sizeof(remote_addr);

    struct Packet window[PACKET_WINDOW_SIZE];
    int base = 0, next_seq = 0;
    int total_packets = (file_size + PAYLOAD_SIZE - 1) / PAYLOAD_SIZE + 4;

    // Send START packet
    struct Packet start;
    memset(&start, 0, sizeof(start));
    start.packet_type = START;
    start.sequence_number = 0;
    memcpy(start.payload, sha_hash, SHA256_DIGEST_LENGTH);
    remote_addr.sin_port = htons(atoi(DATA_SENDING_PORT));
    send_packet(sock, &start, &remote_addr, remote_len);
    printf("send packet was send\n");

    // Wait for ACK
    int is_nack = 0;
    while (!wait_for_response(sock, &remote_addr, remote_len, 0, &is_nack));

    // Send FILENAME packet
    struct Packet fname;
    memset(&fname, 0, sizeof(fname));
    fname.packet_type = FILENAME;
    fname.sequence_number = 1;
    strncpy(fname.payload, filename, PAYLOAD_SIZE - 1);
    remote_addr.sin_port = htons(atoi(DATA_SENDING_PORT));
    send_packet(sock, &fname, &remote_addr, remote_len);
    while (!wait_for_response(sock, &remote_addr, remote_len, 1, &is_nack));

    // Send FILESIZE packet
    struct Packet fsize;
    memset(&fsize, 0, sizeof(fsize));
    fsize.packet_type = FILESIZE;
    fsize.sequence_number = 2;
    memcpy(fsize.payload, &file_size, sizeof(uint32_t));
    remote_addr.sin_port = htons(atoi(DATA_SENDING_PORT));
    send_packet(sock, &fsize, &remote_addr, remote_len);
    while (!wait_for_response(sock, &remote_addr, remote_len, 2, &is_nack));

    // Send DATA packets with sliding window
    next_seq = 3;
    int last_ack = 2;

    while (last_ack < total_packets - 1) {
        int in_window = next_seq - last_ack - 1;
        remote_addr.sin_port = htons(atoi(DATA_SENDING_PORT));
        while (in_window < PACKET_WINDOW_SIZE && next_seq < total_packets - 1) {
            memset(&window[next_seq % PACKET_WINDOW_SIZE], 0, sizeof(struct Packet));
            window[next_seq % PACKET_WINDOW_SIZE].packet_type = DATA;
            window[next_seq % PACKET_WINDOW_SIZE].sequence_number = next_seq;
            size_t read_bytes = fread(window[next_seq % PACKET_WINDOW_SIZE].payload, 1, PAYLOAD_SIZE, file);
            printf("Sending packet %u\n", window[next_seq%PACKET_WINDOW_SIZE].sequence_number);
            send_packet(sock, &window[next_seq % PACKET_WINDOW_SIZE], &remote_addr, remote_len);
            next_seq++;
            in_window++;
        }

        struct Packet response;
        int ret = wait_for_response(sock, &remote_addr, remote_len, last_ack + 1, &is_nack);
        if ( ret == 1) {
            //printf("Got response\n");
            if (!is_nack) {
                last_ack++;
            } else {
                remote_addr.sin_port = htons(atoi(DATA_SENDING_PORT));
                //printf("Sending packet after nack %u\n", window[(last_ack + 1)%PACKET_WINDOW_SIZE].sequence_number);
                send_packet(sock, &window[(last_ack + 1) % PACKET_WINDOW_SIZE], &remote_addr, remote_len);
            }
        }
        else if (ret== 0){
            //printf("asking for packet %u", last_ack +1);
            send_response(sock, &remote_addr, remote_len, last_ack+1, NACK);
        }
    }

    // Send STOP packet
    struct Packet stop;
    memset(&stop, 0, sizeof(stop));
    stop.packet_type = STOP;
    stop.sequence_number = total_packets - 1;
    remote_addr.sin_port = htons(atoi(DATA_SENDING_PORT));
    send_packet(sock, &stop, &remote_addr, remote_len);
    while (!wait_for_response(sock, &remote_addr, remote_len, stop.sequence_number, &is_nack));

    printf("File sent successfully.\n");

    close(sock);
    fclose(file);
    return 0;
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