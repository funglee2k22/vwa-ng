#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include "server.h"
#include "client.h"

int main(int argc, char** argv)
{
    int port = 18080;
    bool server_mode = false;
    const char *host = NULL;
    const char *address = NULL;
    int runtime_s = 10;
    int ch;
    bool ttfb_only = false;
    bool gso = false;
    const char *logfile = NULL;
    const char *cc = "reno";
    int iw = 10;

    char port_char[16];
    sprintf(port_char, "%d", port);


    run_client(port_char, gso, logfile, cc, iw, host, runtime_s, ttfb_only);


}
