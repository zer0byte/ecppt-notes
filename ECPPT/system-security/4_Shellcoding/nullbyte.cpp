#include <iostream> 
#include <cstring>

int main(int argc, char *argv[]) 
{ 
    char StringToPrint[10];	
	char string1[] = "\x41\x41\x41";
    char string2[] = "\x42\x42\x42\x43\x43\x43";

	strcat(StringToPrint, string1);
	strcat(StringToPrint, string2);
    printf("%s",StringToPrint);
	
    return 0; 
} 

