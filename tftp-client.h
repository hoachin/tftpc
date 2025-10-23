#ifndef TFTPC_H
#define TFTPC_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#define DEBUG(...) fprintf(stderr, "[DEBUG] %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#define WARN(...)  fprintf(stderr, "[WARN]  %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#define ERROR(...) fprintf(stderr, "[ERROR] %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#define FATAL(...) fprintf(stderr, "[FATAL] %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n"), exit(EXIT_FAILURE)

#define MAX_PATH_LEN 1024
#define BLOCK_SIZE 512
#define TIMEOUT 5

enum opcode {
  RRQ = 1,
  WRQ,
  DATA,
  ACK,
  ERROR
};
typedef enum opcode opcode;

enum tftpc_op {
  OP_UNDEFINED,
  OP_WRITE,
  OP_READ
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

constexpr size_t BUFFER_SIZE = 1400;

struct tftpc_session {
  uint8_t tx_buff[BUFFER_SIZE];
  uint8_t rx_buff[BUFFER_SIZE];
  size_t tx_len;
  size_t rx_len;
  int sockfd;
  socklen_t salen;
  struct sockaddr* sa;
  FILE* fp;
  unsigned block_num;
};
typedef struct tftpc_session tftpc_session;

tftpc_conf parse_args(int argc, char** argv);

tftpc_session init_read_session(tftpc_conf* conf);

int tftpc_socket(tftpc_conf* conf, struct sockaddr** saptr, socklen_t* lenp);

void send_packet(tftpc_session* session);

void recv_packet(tftpc_session* session);

void read_file(tftpc_conf* conf);

void write_file(tftpc_conf* conf);

void create_rrq(tftpc_conf* conf, tftpc_session* session);

void create_ack(tftpc_session* session);

size_t process_data_packet(tftpc_session* session);

void process_error_packet(tftpc_session* session);

void unexpected_packet(tftpc_session* session);

#endif
