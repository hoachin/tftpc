#define _POSIX_C_SOURCE 202405L

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PATH_LEN 1460
#define BLOCK_SIZE 512
#define TIMEOUT 5

#define RRQ 1
#define WRQ 2
#define DATA 3
#define ACK 4
#define ERROR 5

int tftpc_socket(const char *host, const char *service, struct sockaddr** saptr, socklen_t* lenp);

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: tftpc <host> <service> <src-file-path> <dest-file-path>\n");
    exit(EXIT_FAILURE);
  }

  const char* host = argv[1];
  const char* service = argv[2];
  const char* src_file_path = argv[3];
  const char* dst_file_path = argv[4];
  const char* mode = "octet";

  int src_path_len = strlen(src_file_path);
  if (src_path_len > MAX_PATH_LEN) {
    fprintf(stderr,
            "Length of source file path greater than max allowed (%d)\n", MAX_PATH_LEN);
    exit(EXIT_FAILURE);
  }

  int dst_path_len = strlen(dst_file_path);
  if (dst_path_len > MAX_PATH_LEN) {
    fprintf(stderr,
            "Length of destination file path greater than max allowed (%d)\n", MAX_PATH_LEN);
    exit(EXIT_FAILURE);
  }

  FILE* fp = fopen(dst_file_path, "w");
  if (!fp) {
    fprintf(stderr, "ERR: unable to open file - %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  socklen_t salen;
  struct sockaddr* sa;
  int sockfd = tftpc_socket(host, service, &sa, &salen);

  char tx_buff[1472];
  char rx_buff[1472];

  size_t offset = 0;
  uint16_t opcode = htons(RRQ);
  memcpy(tx_buff + offset, &opcode, sizeof(opcode));
  offset += sizeof(opcode);

  memcpy(tx_buff + offset, src_file_path, strlen(src_file_path) + 1);
  offset += strlen(src_file_path) + 1;

  memcpy(tx_buff + offset, mode, strlen(mode) + 1);
  offset += strlen(mode) + 1;

  sendto(sockfd, tx_buff, offset, 0, sa, salen);

  int expected_blk = 1;
  while (true) {
    ssize_t nr = recvfrom(sockfd, rx_buff, sizeof(rx_buff), 0, nullptr, nullptr);
    if (nr < 0) {
      fprintf(stderr, "ERR: read - %s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (nr < 4) {
      fprintf(stderr, "WARN: invalid packet received\n");
      continue;
    }

    uint16_t rx_op;
    memcpy(&rx_op, rx_buff, sizeof(uint16_t));
    rx_op = htons(rx_op);
    if (rx_op == DATA) {
      uint16_t rx_blk;
      memcpy(&rx_blk, rx_buff+2, sizeof(uint16_t));
      rx_blk = ntohs(rx_blk);
      if (rx_blk == expected_blk) {
        fprintf(stderr, "DEBUG: GOT BLOCK %d\n", rx_blk);
        fwrite(rx_buff, 1, nr, fp);

        // TODO send ACK
      } else {
        fprintf(stderr, "ERROR: unexpected block %d\n", rx_blk);
        exit(EXIT_FAILURE);
      }

      if (nr < 516) {
        fprintf(stderr, "DEGUG: small packet, all done\n");
        break;
      }
    } else if (rx_op == ERROR) {
      uint16_t err_code;
      memcpy(&err_code, rx_buff+2, sizeof(uint16_t));
      err_code = ntohs(err_code);
      fprintf(stderr, "ERR: code: %d, msg: %.*s", err_code, (int)nr-4,
              rx_buff+4);
      break;
    } else {
      fprintf(stderr, "DEBUG: Unexpected opcode\n");
      exit(EXIT_FAILURE);
    }
  }
}

int tftpc_socket(const char *host, const char *service, struct sockaddr** saptr, socklen_t* lenp) {
  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  struct addrinfo *res = {};
  int n = getaddrinfo(host, service, &hints, &res);
  if (n != 0) {
    fprintf(stderr, "ERR: %s\n", gai_strerror(n));
    exit(EXIT_FAILURE);
  }

  int sockfd;
  struct addrinfo *ressave = res;
  do {
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd >= 0) {
      break;
    }
  } while ((res = res->ai_next) != nullptr);

  if (res == nullptr) {
    fprintf(stderr, "ERR: Unable to connect\n");
    exit(EXIT_FAILURE);
  }

  *saptr = malloc(res->ai_addrlen);
  memcpy(*saptr, res->ai_addr, res->ai_addrlen);
  *lenp = res->ai_addrlen;

  freeaddrinfo(ressave);

  return sockfd;
}
