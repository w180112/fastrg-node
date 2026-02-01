#include <stdio.h>

#include <common.h>

#include "fastrg.h"

int main(int argc, char **argv)
{
    if (argc < 5) {
        puts("Too less parameter.");
        puts("Type fastrg <eal_options>");
        return ERROR;
    }

    return fastrg_start(argc, argv);
}
