#ifndef TFTPC_H
#define TFTPC_H

#include <sys/socket.h>
#include <stdio.h>

#define DEBUG(...) fprintf(stderr, "[DEBUG] %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#define WARN(...)  fprintf(stderr, "[WARN]  %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#define ERROR(...) fprintf(stderr, "[ERROR] %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#define FATAL(...) fprintf(stderr, "[FATAL] %s:%d (%s): ", __FILE__, __LINE__, __func__), fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n"), exit(EXIT_FAILURE)

#define MAX_PATH_LEN 1460
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

tftpc_conf parse_args(int argc, char** argv);

int tftpc_socket(tftpc_conf* conf, struct sockaddr** saptr, socklen_t* lenp);

void read_file(tftpc_conf* conf);

void write_file(tftpc_conf* conf);

size_t create_rrq(tftpc_conf* conf, size_t buff_len, char buff[static buff_len] );

#endif
