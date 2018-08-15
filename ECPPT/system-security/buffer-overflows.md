# ECPPT
__________________________
# System Security
# Module 3 - Buffer Overflows

**Note: for further info, independent notes about the assembly language and buffer overflows, and Vivek Ramachandran's videos can be referenced**

_______________________
## 1. Understanding Buffer Overflows
Buffer overflow is a condition in a program where a function attempts to copy more data into a buffer than it can hold. The extra data that cannot be stored, then replaces/overrides another piece of data on the stack.

Suppose the computer allocates a buffer of 40 bytes (or pieces) of memory to store 10 integers (4 bytes per integer)

An attacker sends the computer 11 integers (a total of 44 bytes) as input.

Whenever was in the location after the ten 40 bytes (allocated for our buffer), gets overwritten with the 11th integer of our input.

Remember that the stack grows backward. Therefore the data in the buffer are copied from lowest memory addresses to the highest memory addresses.

One of the vulnerable function in C is **strcpy()** function, which allows buffer overflows to happen, because it has no limit on how big the copied data should be. Using this function, we can overwrite the stack and alter the code flow. The safer alternative of **strcpy()** is **strncpy()**

**Example:**

Suppose we have the following code:
```
int main(int argc, char** argv)
{
  argv[1] = (char*)"AAABBBCCCDDDEEEFFFGGGHHHI"
  char buffer[10];
  strnpy(buffer, argv[1], sizeof(buffer));
  return 0;
}
```

The following is  the new stack frame process review:
1. Push the function parameters
2. Call the function
3. Execute the prologue (which updates **EBP** and **ESP** to create the new stack frame)
4. Allocate local variables

Before

|  ...                          |
|-------------------------------|
| Other local variables         |
| Buffer[10]                    |
| EBP                           |
| Function return address (EIP) |
| Parameters of function        |
| Local variables of main       |
| Return address of main        |
| Parameters of main            |
| **...**                       |

After

|  ...                          |
|-------------------------------|
| Other local variables         |
| AAAB                          |
| BBCC                          |
| CDDD                          |
| EEEF                          |
| FFFG                          |
| GGHH                          |
| HI                            |
| **...**                       |


As a pentester, you can replace **EIP** with the address of the payload you wish to run. This is where it is important to know memory addresses of certain registers.

We can use a helper in order to pass the hexadecimal code as an argument with a 'filler' data. Below is an example of a helper:

```
import sys
import os

payload = "\x41"*22 # \x41 = ASCII for 'A', which is a 'filler' data
payload += "\x48\x15\x40"
command = "goodpwd.exe %s" %(payload)

print path
os.system(command)
```

We did not add **\x00** (**NULL**) byte, in order for the **stycpy()** to not to stop copying data.

**Note : Watch Vivek Ramachandran videos**

_______________________
## 2. Finding Buffer Overflows
These are the examples of operations that **may** be vulnerable to buffer overflows:
- strcpy
- strcat
- gets / fgets
- scanf / fscanf
- printf
- vsprintf
- memcpy

Any function which carries out the following operations may be vulnerable to buffer overflows:
- Does not properly validate inputs before operating
- Does not check input boundaries

However, buffer overflows are problems of unsafe languages. All interpreted languages such as C#, Visual Basic, .Net, Java, etc. are safe from such vulnerabilities.

Moreover, buffer overflows can be triggered by any of the following buffer operations:
- User input
- Data loaded from a disk
- Data from network

If we want to find buffer overflows manually, it can be very time consuming. However, we will document some of the techniques that make this process easier, such as:
- If you are a developer and you have access to the source code, such as statistic analysis tools ([splint](http://www.splint.org/), [Cppcheck](http://cppcheck.sourceforge.net/), etc.). Such tools will try to detect not only buffer overflows but also some other types of errors.

Other techniques are the followings:
- When a crash occurs, be prepared to hunt for the vulnerability with a debugger. Some companies use cloud-fuzzing to brute-force crashing (using file-based inputs). Whenever a crash is found, it is recorded for further analysis
- A dynamic analysis tool like a fuzzer or tracer, which tracks all executions ant the data flow, help in finding problems

**Fuzzing** is a software testing technique that provides invalid data, i.e., unexpected or random data as input to a program. Input can be in any form such as:
- Command line
- Network data
- Databases
- Keyboard/mouse input
- Parameters
- File input
- Shared memory regions
- Environment variables

This technique basically works by supplying a random data to the program, and then the program is checked for incorrect behavior such as:
- Memory hogging (excessive use of memory)
- CPU hogging
- Crashing

Whenever inconsistent behavior is found, all related information is collected, which will later be used by operator to recreate the case and hunt-down/solve the problem.

However, fuzzing is an exponential problem and is also resource-intensive, and therefore, in reality, it cannot be used to test all the cases.

Some fuzzing frameworks:
- [Peach Fuzzing Platform](http://peachfuzzer.com/)
- [Sulley](https://github.com/OpenRCE/sulley)
- [Sfuzz](https://github.com/orgcandman/Simple-Fuzzer)
- [FileFuzz](http://packetstormsecurity.com/files/39626/FileFuzz.zip.html)


#### 2.1 Finding Buffer Overflows in Binary Programs
Let's see how to identify a buffer overflow after the crash of the application.


#### 2.2 Code Observation


#### 2.3 Overflow the Buffer

_______________________
## 3. Exploiting Buffer Overflows


_______________________
## 4. Exploring a Real-World Buffer Overflow


## 5. Security Implementations


_______________________
