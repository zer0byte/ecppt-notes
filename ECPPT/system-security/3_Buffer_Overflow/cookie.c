#include <stdio.h>

int main()
{
    int cookie=0;
    char buffer[4];
    
    printf("cookie = %08X\n",cookie);
    
    gets(buffer);
    
    printf("cookie = %08X\n",cookie);
    
    if(cookie == 0x31323334 )
    {
        printf("you win!\n");
    }
    else
    {
        printf("try again!\n");
    }
}
