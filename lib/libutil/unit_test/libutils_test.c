#include <stdio.h>
#include "ip_codec_test.h"

int main(int argc, char **argv)
{
    puts("====================start unit tests====================\n");
    puts("====================test ip_codec.c====================");
    test_tcp_checksum();
    puts("ok!");

    puts("====================test ipc.c====================");
    puts("ok!");

    puts("\nall test successfully");
    puts("====================end of unit tests====================");
}