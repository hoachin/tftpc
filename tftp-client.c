#define _POSIX_C_SOURCE 202405L

#include "tftp-client.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

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
  tftpc_session session = init_read_session(conf);

  create_rrq(conf, &session);
  send_packet(&session);

  while (session.state == STATE_IN_PROGRESS) {
    recv_packet(&session);

    if (session.rx_len < 4) {
      const char* msg = "Invalid Packet";
      send_error(&session, UNDEFINED, msg, strlen(msg));
      FATAL("Invalid packet received");
    }

    uint16_t rx_op;
    memcpy(&rx_op, session.rx_buff, sizeof(uint16_t));
    rx_op = htons(rx_op);

    switch (rx_op) {
      case DATA:
        process_data_packet(&session);
        create_ack(&session);
        send_packet(&session);
        break;
      case ERROR:
        process_error_packet(&session);
        break;
      default:
        const char* msg = "Illegal operation";
        send_error(&session, ILLEGAL_OPERATION, msg, strlen(msg));
        FATAL("Unexpected opcode %d", rx_op);
        break;
    }
  }
}

void write_file(tftpc_conf* conf) {
  tftpc_session session = init_write_session(conf);

  create_wrq(conf, &session);
  send_packet(&session);

  while (session.state == STATE_IN_PROGRESS) {
    recv_packet(&session);

    if (session.rx_len < 4) {
      const char* msg = "Invalid Packet";
      send_error(&session, UNDEFINED, msg, strlen(msg));
      FATAL("Invalid packet received");
    }

    uint16_t rx_op;
    memcpy(&rx_op, session.rx_buff, sizeof(uint16_t));
    rx_op = htons(rx_op);

    switch (rx_op) {
      case ACK:
        process_ack_packet(&session);
        ssize_t nr = create_data_packet(&session);
        if (nr > 0) {
          // TODO - what if the file is exactly 512bytes in size?
          send_packet(&session);
        }
        break;
      case ERROR:
        process_error_packet(&session);
        break;
      default:
        const char* msg = "Illegal operation";
        send_error(&session, ILLEGAL_OPERATION, msg, strlen(msg));
        FATAL("Unexpected opcode %d", rx_op);
        break;
    }
  }
}

tftpc_session init_read_session(tftpc_conf* conf) {
  tftpc_session session = {};

  socklen_t salen;
  struct sockaddr* sa;
  int sockfd = tftpc_socket(conf, &sa, &salen);

  int fd = open(conf->dst_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    FATAL("Unable to open file - %s", strerror(errno));
  }

  session.state = STATE_IN_PROGRESS;
  session.sockfd = sockfd;
  session.salen = salen;
  session.sa = sa;
  session.fd = fd;

  return session;
}

tftpc_session init_write_session(tftpc_conf* conf) {
  tftpc_session session = {};

  socklen_t salen;
  struct sockaddr* sa;
  int sockfd = tftpc_socket(conf, &sa, &salen);

  int fd = open(conf->dst_file_path, O_RDONLY);
  if (fd < 0) {
    FATAL("Unable to open file - %s", strerror(errno));
  }

  session.state = STATE_IN_PROGRESS;
  session.sockfd = sockfd;
  session.salen = salen;
  session.sa = sa;
  session.fd = fd;

  return session;
}

void send_packet(tftpc_session* session) {
  ssize_t s = sendto(session->sockfd, session->tx_buff, session->tx_len, 0, session->sa, session->salen);
  if (s < 0) {
    FATAL("Send error - %s", strerror(errno));
  }
}

void recv_packet(tftpc_session* session) {
  struct sockaddr* recv_addr = nullptr;
  socklen_t* recv_len = nullptr;

  /* If this is first received packet then need to update the address to match the sender TID
   * to be used in any subsequent send/recv calls */ 
  if (session->block_num == 0) {
    session->salen = sizeof(struct sockaddr_storage);
    recv_addr = session->sa;
    recv_len = &session->salen;
  }
  // TODO after the first recv should confirm any subsequent ones come from the same TID

  ssize_t nr = recvfrom(session->sockfd, session->rx_buff, sizeof(session->rx_buff), 0, recv_addr, recv_len);
  if (nr < 0) {
    const char* msg = "Client error";
    send_error(session, UNDEFINED, msg, strlen(msg));
    FATAL("Read failure - %s", strerror(errno));
  }
  session->rx_len = nr;
}

void process_data_packet(tftpc_session* session) {
  data_packet* dp = (data_packet*)session->rx_buff;
  size_t data_len = session->rx_len - sizeof(data_packet);
  uint16_t block_num = ntohs(dp->block_num);

  if (block_num == session->block_num + 1) {
    DEBUG("GOT BLOCK %d", block_num);
    size_t w = write(session->fd, dp->data, data_len);
    if (w < data_len) {
      const char* msg = "Client error";
      send_error(session, UNDEFINED, msg, strlen(msg));
      FATAL("Short write");
    }
  } else {
    const char* msg = "Unexpected block";
    send_error(session, UNDEFINED, msg, strlen(msg));
    FATAL( "Unexpected block %d", block_num);
  }
  session->block_num++;

  if (data_len < BLOCK_SIZE) {
    DEBUG("Small packet, all done");
    session->state = STATE_COMPLETE;
  }
}

void process_ack_packet(tftpc_session* session) {
  ack_packet* ap = (ack_packet*)session->rx_buff;
  uint16_t block_num = ntohs(ap->block_num);

  if (block_num == session->block_num) {
    DEBUG("GOT ACK FOR %d", block_num);
  } else {
    const char* msg = "Unexpected block";
    send_error(session, UNDEFINED, msg, strlen(msg));
    FATAL( "Unexpected block %d", block_num);
  }
}

void create_error_packet(tftpc_session *session, error_code ec, const char* msg, size_t msglen) {
  session->tx_len = 0;

  uint16_t opcode = htons(ERROR);
  memcpy(session->tx_buff + session->tx_len, &opcode, sizeof(uint16_t));
  session->tx_len += sizeof(uint16_t);

  uint16_t ecode = htons(ec);
  memcpy(session->tx_buff + session->tx_len, &ecode, sizeof(uint16_t));
  session->tx_len += sizeof(uint16_t);

  memcpy(session->tx_buff + session->tx_len, msg, msglen+1);
  session->tx_len += msglen+1;
}

ssize_t create_data_packet(tftpc_session* session) {
  session->tx_len = 0;

  uint16_t opcode = htons(DATA);
  memcpy(session->tx_buff + session->tx_len, &opcode, sizeof(uint16_t));
  session->tx_len += sizeof(uint16_t);

  session->block_num++;
  uint16_t block_num = htons(session->block_num);
  memcpy(session->tx_buff + session->tx_len, &block_num, sizeof(uint16_t));
  session->tx_len += sizeof(uint16_t);

  ssize_t nr = read(session->fd, session->tx_buff, BLOCK_SIZE);
  if (nr < 0) {
    const char* msg = "Client error";
    send_error(session, UNDEFINED, msg, strlen(msg));
    FATAL("Read error - %s", strerror(errno));
  }
  
  if (nr == 0) {
    session->state = STATE_COMPLETE;
  }

  return nr;
}

void process_error_packet(tftpc_session* session) {
  error_packet* ep = (error_packet*)session->rx_buff;
  uint16_t error_code = ep->error_code;
  size_t msglen = session->rx_len - sizeof(error_packet);
  FATAL("Error received: code: %d, msg: %.*s\n", error_code, (int)msglen, ep->msg);
}

void create_ack(tftpc_session* session) {
  session->tx_len = 0;

  uint16_t opcode = htons(ACK);
  memcpy(session->tx_buff + session->tx_len, &opcode, sizeof(uint16_t));
  session->tx_len += sizeof(uint16_t);

  uint16_t block = htons(session->block_num);
  memcpy(session->tx_buff + session->tx_len, &block, sizeof(uint16_t));
  session->tx_len += sizeof(uint16_t);
}

void create_rrq(tftpc_conf* conf, tftpc_session* session) {
  session->tx_len = 0;
  session->state = STATE_IN_PROGRESS;

  size_t path_len = strlen(conf->src_file_path) + 1;
  size_t mode_len = strlen(conf->mode) + 1;
  size_t opcode_len = sizeof(uint16_t);
  size_t packet_len = path_len + mode_len + opcode_len;

  if (sizeof(session->tx_buff) < packet_len) {
    FATAL("Packet size bigger than buffer");
  }

  uint16_t opcode = htons(RRQ);
  memcpy(session->tx_buff + session->tx_len, &opcode, opcode_len);
  session->tx_len += opcode_len;

  memcpy(session->tx_buff + session->tx_len, conf->src_file_path, path_len);
  session->tx_len += path_len;

  memcpy(session->tx_buff + session->tx_len, conf->mode, mode_len);
  session->tx_len += mode_len;
}

void create_wrq(tftpc_conf* conf, tftpc_session* session) {
  session->tx_len = 0;
  session->state = STATE_IN_PROGRESS;

  size_t path_len = strlen(conf->dst_file_path) + 1;
  size_t mode_len = strlen(conf->mode) + 1;
  size_t opcode_len = sizeof(uint16_t);
  size_t packet_len = path_len + mode_len + opcode_len;

  if (sizeof(session->tx_buff) < packet_len) {
    FATAL("Packet size bigger than buffer");
  }

  uint16_t opcode = htons(WRQ);
  memcpy(session->tx_buff + session->tx_len, &opcode, opcode_len);
  session->tx_len += opcode_len;

  memcpy(session->tx_buff + session->tx_len, conf->dst_file_path, path_len);
  session->tx_len += path_len;

  memcpy(session->tx_buff + session->tx_len, conf->mode, mode_len);
  session->tx_len += mode_len;
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

  *saptr = malloc(sizeof(struct sockaddr_storage));
  memcpy(*saptr, res->ai_addr, res->ai_addrlen);
  if (!saptr) {
    FATAL("Unable to allocate socket addr - %s", strerror(errno));
  }
  *lenp = res->ai_addrlen;

  freeaddrinfo(ressave);

  return sockfd;
}

void send_error(tftpc_session* session, error_code ecode, const char* msg, size_t msglen) {
  create_error_packet(session, ecode, msg, msglen);
  send_packet(session);
}
