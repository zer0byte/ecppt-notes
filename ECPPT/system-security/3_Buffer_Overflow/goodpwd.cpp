#include <iostream> 
#include <cstring>
 
int bf_overflow(char *str){ 
       char buffer[10]; 	//our buffer 
       strcpy(buffer,str);	//the vulnerable command 
       return 0; 
} 
 
int good_password(){ 		// a function which is never executed
       printf("Valid password supplied\n"); 
       printf("This is good_password function \n"); 
}
 
int main(int argc, char *argv[]) 
{ 
       int password=0; // controls whether password is valid or not 
       printf("You are in goodpwd.exe now\n"); 
       bf_overflow(argv[1]); //call the function and pass user input 
       if ( password == 1) { 
             good_password(); //this should never happen  
 }
 	 else {
       printf("Invalid Password!!!\n");
 } 
       printf("Quitting sample1.exe\n"); 
       return 0; 
} 

