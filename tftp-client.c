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

enum tftpc_op {
  OP_UNDEFINED,
  OP_UPLOAD,
  OP_DOWNLOAD
};
typedef enum tftpc_op tftpc_op;

enum tftpc_ipv {
  IPV_UNSPEC,
  IPV4,
  IPV6
};
typedef enum tftpc_ipv tftpc_ipv;

struct tftpc_conf {
  const char* host;
  const char* service;
  const char* src_file_path;
  const char* dst_file_path;
  const char* mode;
  tftpc_ipv ipv;
  tftpc_op op;
};
typedef struct tftpc_conf tftpc_conf;

int tftpc_socket(tftpc_conf conf, struct sockaddr** saptr, socklen_t* lenp);
tftpc_conf parse_args(int argc, char** argv);

int main(int argc, char **argv) {
  tftpc_conf conf = parse_args(argc, argv);

  FILE* fp = fopen(conf.dst_file_path, "w");
  if (!fp) {
    fprintf(stderr, "ERR: unable to open file - %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  socklen_t salen;
  struct sockaddr* sa;
  int sockfd = tftpc_socket(conf, &sa, &salen);

  char tx_buff[1472];
  char rx_buff[1472];

  size_t offset = 0;
  uint16_t opcode = htons(RRQ);
  memcpy(tx_buff + offset, &opcode, sizeof(opcode));
  offset += sizeof(opcode);

  memcpy(tx_buff + offset, conf.src_file_path, strlen(conf.src_file_path) + 1);
  offset += strlen(conf.src_file_path) + 1;

  memcpy(tx_buff + offset, conf.mode, strlen(conf.mode) + 1);
  offset += strlen(conf.mode) + 1;

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

tftpc_conf parse_args(int argc, char** argv) {
  tftpc_conf conf = {
    .host = nullptr,
    .service = "tftp",
    .src_file_path = nullptr,
    .dst_file_path = nullptr,
    .mode = "octet",
    .ipv = IPV_UNSPEC,
    .op = OP_UNDEFINED
  };


  int opt;
  while ((opt = getopt(argc, argv, "h:p:s:d:a46rw")) != -1) {
    switch (opt) {
      case 'h':
        conf.host = optarg; break;
      case 'p':
        conf.service = optarg; break;
      case 's':
        conf.src_file_path = optarg; break;
      case 'd':
        conf.dst_file_path = optarg; break;
      case 'a':
        conf.mode = "netascii"; break;
      case '4':
        if (conf.ipv != IPV_UNSPEC) {
          fprintf(stderr, "ERR: cannot specify -4 and -6\n");
          exit(EXIT_FAILURE);
        }
        conf.ipv = IPV4;
        break;
      case '6':
        if (conf.ipv != IPV_UNSPEC) {
          fprintf(stderr, "ERR: cannot specify -4 and -6\n");
          exit(EXIT_FAILURE);
        }
        conf.ipv = IPV6;
        break;
      case 'w':
        if (conf.op != OP_UNDEFINED) {
          fprintf(stderr, "ERR: cannot specify -w and -r\n");
          exit(EXIT_FAILURE);
        }
        conf.op = OP_UPLOAD;
        break;
      case 'r':
        if (conf.op != OP_UNDEFINED) {
          fprintf(stderr, "ERR: cannot specify -w and -r\n");
          exit(EXIT_FAILURE);
        }
        conf.op = OP_DOWNLOAD;
        break;
      case '?':
        fprintf(stderr, "Usage: %s -h <host> -s <src-file> -d <dest-file> [-p <port>] -r|-w [-a] [-4|-6]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  if (!conf.host) {
    fprintf(stderr, "ERR: missing host\n");
    exit(EXIT_FAILURE);
  }

  if (!conf.src_file_path) {
    fprintf(stderr, "ERR: missing source file\n");
    exit(EXIT_FAILURE);
  }

  if (!conf.dst_file_path) {
    fprintf(stderr, "ERR: missing destination file\n");
    exit(EXIT_FAILURE);
  }

  int src_path_len = strlen(conf.src_file_path);
  if (src_path_len > MAX_PATH_LEN) {
    fprintf(stderr,
            "ERR: Length of source file path greater than max allowed (%d)\n", MAX_PATH_LEN);
    exit(EXIT_FAILURE);
  }

  int dst_path_len = strlen(conf.dst_file_path);
  if (dst_path_len > MAX_PATH_LEN) {
    fprintf(stderr,
            "ERR: Length of destination file path greater than max allowed (%d)\n", MAX_PATH_LEN);
    exit(EXIT_FAILURE);
  }

  if (conf.op == OP_UNDEFINED) {
    fprintf(stderr, "ERR: One of -r or -w must be specified\n");
    exit(EXIT_FAILURE);
  }

  if (conf.op == OP_UPLOAD) {
    fprintf(stderr, "ERR: -w currently unsupported\n");
    exit(EXIT_FAILURE);
  }

  return conf;
}

int tftpc_socket(tftpc_conf conf, struct sockaddr** saptr, socklen_t* lenp) {
  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  if (conf.ipv == IPV4) {
    hints.ai_family = AF_INET;
  }
  if (conf.ipv == IPV6) {
    hints.ai_family = AF_INET6;
  }
  hints.ai_socktype = SOCK_DGRAM;

  struct addrinfo *res = {};
  int n = getaddrinfo(conf.host, conf.service, &hints, &res);
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
