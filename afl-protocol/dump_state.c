#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "network/state.h"
#include "network/utilities.h"

void usage(char *argv[])
{
  fprintf(stderr, "Usage: %s -i <in_file>\n", argv[0]);
  exit(0);
}

int main(int argc, char *argv[])
{
  int opt;
  char *filename;

  if (argc != 3) usage(argv);
  while ( (opt = getopt(argc, argv, "i:")) != -1 ) {
    switch (opt) {
      case 'i':
        filename = optarg;
        break;
      default:
        usage(argv);
    }
  }

  protocol *tmp_prot = unserialize(filename);
  debugProtocol(tmp_prot);
  return 0;
}
