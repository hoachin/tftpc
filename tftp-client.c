#define _POSIX_C_SOURCE 202405L

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "tftp-client.h"

int main(int argc, char **argv) {
  tftpc_conf conf = parse_args(argc, argv);


  if (conf.op == OP_READ) {
    read_file(&conf);
  } else if (conf.op == OP_WRITE) {
    write_file(&conf);
  } else {
    FATAL("Unexpected operation %d", conf.op);
  }
}

void read_file(tftpc_conf* conf) {
  socklen_t salen;
  struct sockaddr* sa;
  int sockfd = tftpc_socket(conf, &sa, &salen);

  FILE* fp = fopen(conf->dst_file_path, "w");
  if (!fp) {
    FATAL("Unable to open file - %s", strerror(errno));
  }

  char tx_buff[1472];
  char rx_buff[1472];

  size_t len = create_rrq(conf, sizeof(tx_buff), tx_buff);
  sendto(sockfd, tx_buff, len, 0, sa, salen);

  int expected_blk = 1;
  while (true) {
    ssize_t nr = recvfrom(sockfd, rx_buff, sizeof(rx_buff), 0, nullptr, nullptr);
    if (nr < 0) {
      FATAL("Read failure - %s", strerror(errno));
    }

    if (nr < 4) {
      WARN("Invalid packet received");
      // TODO send error response
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
        DEBUG("GOT BLOCK");
        fwrite(rx_buff, 1, nr, fp);

        // TODO send ACK
      } else {
        // TODO - is this fatal or can we send an error and ignore?
        FATAL( "Unexpected block %d", rx_blk);
      }

      if (nr < 516) {
        DEBUG("Small packet, all done");
        break;
      }
    } else if (rx_op == ERROR) {
      uint16_t err_code;
      memcpy(&err_code, rx_buff+2, sizeof(uint16_t));
      err_code = ntohs(err_code);
      fprintf(stderr, "Error received: code: %d, msg: %.*s\n", err_code, (int)nr-4,
              rx_buff+4);
      break;
    } else {
      // TODO - is this fatal or can we send an error and ignore?
      FATAL("Unexpected opcode");
    }
  }
}

size_t create_rrq(tftpc_conf* conf, size_t buff_len, char buff[static buff_len] ) {
  size_t path_len = strlen(conf->src_file_path) + 1;
  size_t mode_len = strlen(conf->mode) + 1;
  size_t opcode_len = sizeof(uint16_t);
  size_t packet_len = path_len + mode_len + opcode_len;

  if (buff_len < packet_len) {
    FATAL("Packet size bigger than buffer");
  }

  size_t offset = 0;
  uint16_t opcode = htons(RRQ);
  memcpy(buff + offset, &opcode, opcode_len);
  offset += opcode_len;

  memcpy(buff + offset, conf->src_file_path, path_len);
  offset += path_len;

  memcpy(buff + offset, conf->mode, mode_len);
  offset += mode_len;

  return offset;
}

void write_file([[maybe_unused]]tftpc_conf* conf) {
  // TODO

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
          FATAL("Cannot specify -4 and -6");
        }
        conf.ipv = IPV4;
        break;
      case '6':
        if (conf.ipv != IPV_UNSPEC) {
          FATAL("Cannot specify -4 and -6");
        }
        conf.ipv = IPV6;
        break;
      case 'w':
        if (conf.op != OP_UNDEFINED) {
          FATAL("Cannot specify -w and -r");
        }
        conf.op = OP_WRITE;
        break;
      case 'r':
        if (conf.op != OP_UNDEFINED) {
          FATAL("Cannot specify -w and -r");
        }
        conf.op = OP_READ;
        break;
      case '?':
        FATAL("Usage: %s -h <host> -s <src-file> -d <dest-file> [-p <port>] -r|-w [-a] [-4|-6]", argv[0]);
    }
  }

  if (!conf.host) {
    FATAL("Missing host");
  }

  if (!conf.src_file_path) {
    FATAL("Missing source file");
  }

  if (!conf.dst_file_path) {
    FATAL("Missing destination file");
  }

  int src_path_len = strlen(conf.src_file_path);
  if (src_path_len > MAX_PATH_LEN) {
    FATAL("Length of source file path greater than max allowed (%d)", MAX_PATH_LEN);
  }

  int dst_path_len = strlen(conf.dst_file_path);
  if (dst_path_len > MAX_PATH_LEN) {
    FATAL( "Length of destination file path greater than max allowed (%d)", MAX_PATH_LEN);
  }

  if (conf.op == OP_UNDEFINED) {
    FATAL("One of -r or -w must be specified");
  }

  if (conf.op == OP_WRITE) {
    FATAL("-w currently unsupported");
  }

  return conf;
}

int tftpc_socket(tftpc_conf* conf, struct sockaddr** saptr, socklen_t* lenp) {
  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  if (conf->ipv == IPV4) {
    hints.ai_family = AF_INET;
  }
  if (conf->ipv == IPV6) {
    hints.ai_family = AF_INET6;
  }
  hints.ai_socktype = SOCK_DGRAM;

  struct addrinfo *res = {};
  int n = getaddrinfo(conf->host, conf->service, &hints, &res);
  if (n != 0) {
    FATAL("%s", gai_strerror(n));
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
    FATAL("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  *saptr = malloc(res->ai_addrlen);
  memcpy(*saptr, res->ai_addr, res->ai_addrlen);
  *lenp = res->ai_addrlen;

  freeaddrinfo(ressave);

  return sockfd;
}
