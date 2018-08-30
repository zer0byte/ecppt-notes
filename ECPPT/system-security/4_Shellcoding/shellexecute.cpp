#include <windows.h>
int main(int argc, char** argv)
{
   ShellExecute(0,"open","cmd",NULL,0,SW_MAXIMIZE);
}
