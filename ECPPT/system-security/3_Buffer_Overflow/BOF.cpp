#include <string.h>

void myfunction(char *arg);

int main(int argc, char **argv)
{
     myfunction(argv[1]);
     return 0;
}

void myfunction(char *arg)
{
    char stuff[8];
    strcpy(stuff, arg);
} 

