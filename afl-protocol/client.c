#include <stdio.h>
#include <stdlib.h>

#include "network/state.h"
#include "network/utilities.h"

void usage(char *argv[])
{
  fprintf(stderr, "Usage: %s -p <port> -i <in_file>\n", argv[0]);
  exit(0);
}

void process(char *filename, unsigned int port)
{
  protocol *tmp_prot = unserialize(filename);
  int size;
  char *buffer = dump_data(tmp_prot, &size);
  int sockfd;

  char *sockfile = getenv("SOCK_FILE");
  if (sockfile)
    sockfd = new_unix(sockfile);
  else
    sockfd = new_socket("127.0.0.1", port);

  sendAll(sockfd, buffer, size);
  recvAll(sockfd);
  sleep(2);
  ck_free(buffer);

  deleteProtocol(tmp_prot);
}

int main(int argc, char *argv[])
{
  int opt;
  char *filename;
  unsigned int port;

  if (argc != 5) usage(argv);
  while ( (opt = getopt(argc, argv, "p:i:")) != -1 ) {
    switch (opt) {
      case 'i':
        filename = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      default:
        usage(argv);
    }
  }

  process(filename, port);
  return 0;
}
