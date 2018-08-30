#include <windows.h>

char code[] = "shell code will go here!"; 

int main(int argc, char **argv) 
{ 
  int (*func)(); 
  func = (int (*)()) code; 
  (int)(*func)(); 
}
