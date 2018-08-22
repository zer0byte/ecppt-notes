#include <string.h>
#include <stdio.h>

int main(int argc, char** argv)
{
        argv[1] = (char*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        char buffer[10];
        strcpy(buffer, argv[1]);

        return 0;
}

