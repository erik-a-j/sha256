#include "sha256.h"
#include <stdio.h>
#include <string.h>

void printsha256(const uint8_t* src, size_t len)
{
    uint32_t sha[8] = {0};
    sha256(sha, src, len);
    for (int i = 0; i < 8; ++i)
    {
        printf("%08x", sha[i]);
    }
    printf("\n");
}

int main(void)
{
    char empty[128] = {0};
    printsha256(empty, 55);
    printsha256(empty, 56);
    printsha256(empty, 57);
    return 0;
}