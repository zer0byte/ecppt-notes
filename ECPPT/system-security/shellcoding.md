# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# System Security
# Module 4 - Shellcoding

https://cdn.members.elearnsecurity.com/ptp_v5/section_1/module_4/html/index.html

__________________________
## 1. Execute on Shellcode
Once an attacker has identified a vulnerable application, his first objective is to inject shellcode in the software. Then, when the shellcode is successfully injected, the instruction pointer register (**EIP**) is adjusted to point to the shellcode. At this point, the shellcode runs unrestricted.

The shellcode can work two ways; it can get sent through the network (remote buffer overflows) or through the local environment.

But, the **EIP** is not the only method of execution of shellcode. It is possible for a shellcode to execute when a **SEH** (Structured Exception Handling) frame activates. The **SEH** frames store the address to jump to when there is an exception, such as *division* by *zero*.

By overwriting the return address, the attacker can take control of the execution.

__________________________
## 2. Types of Shellcode
Depending on how shellcode run and give control to the attacker, we can identify several types of execution strategies:
- **Local** shellcode<br>
  **Local** shellcode is used to exploit local processes in order to get higher privileges on that machine.

  These are also known as privilege escalation shellcodes and are used in local code execution vulnerabilities.
- **Remote** shellcode<br>
  **Remote** shellcode is sent through the network along with an exploit. The exploit will allow the shellcode to be injected into the process and executed.

  The goal of **remote** code execution is to provide remote access to the exploited machine by means of common network protocols such as **TCP/IP**.

  Remote shellcodes can be sub-divided based on how this connection is set up:
  - Connect back<br>
    A **connect back** shellcode initiates a connection back to the attacker's machine
  - Bind shell<br>
    A **bind shell** shellcode binds a shell (or command prompt) to a certain port on which the attacker can connect
  - Socket reuse<br>
    A **socket reuse** shellcode stablishes as connection to a vulnerable process that does not close before the shellcode is run. The shellcode can then re-use this connection to communicate with the attacker. However, due to their complexity, they are generally not used.

**Staged** shellcodes are used when the shellcode is bigger than the space that an attacker can use for injection (within the process).

In this case, a small piece of shellcode (*Stage 1*) is executed. This code then fetches a larger piece of shellcode (*Stage 2*) into the process memory and executes it.

Staged shellcode may be local or remote and can be sub-divided into **Egg-hunt** shellcode and **Omelet** shellcode.

- **Egg hunt shellcode**<br>
  **Egg-hunt shellcode** is used when a larger shellcode can be injected into the process but, it is unknown where in the process this shellcode will be actually injected. It is divided into 2 pieces:
  - A small shellcode (egg-hunter)
  - The actual bigger shellcode (egg)

  The only thing the egg-hunter shellcode has to do is searching for the bigger shellcode (the egg) within the process address space.

  At that point, thee execution of the bigger shellcode begins.

- **Omelet shellcode** <br>
  **Omelet shellcode** is similar to the egg-hunt shellcode. However, we do not have one larger shellcode (the egg) but a number of smaller shellcodes, eggs. They are combined together and executed

  This type of shellcode is also used to avoid shellcode detectors because each individual egg might be small enough not to raise any alarms but collectively they become a complete shellcode.

**Download and execute shellcodes** do not immediately create a shell when executed. Instead, they download an executable from the Internet and execute it.

This executable can be a data harvesting tool, malware, or simply a backdoor.

__________________________
## 3. Encoding of Shellcode
In the previous module, we introduced the meaning of NULL-free shellcodes. Shellcodes are generally encoded since most vulnerabilities have some form of restriction over data which is being overflowed.

Consider the following snippet:
```
#include <iostream>
#include <cstring>

int main(int argc, char *argv[])
{
  char StringToPrint [20];
  char string1[] = "\x41\x41\x41";
  char string2[] = "\x42\x42\x42\x43\x43\x43";

  strcat(StringToPrint, string1);
  strcat(StringToPrint, string2);
  print("%s", StringToPrint);

  return 0;
}

```

The code simply concatenates the two variabels **string1** and **string2** into **StringToPrint**.

If everything works fine when **printf** gets executed, the program should print the string "AAABBBCCCC".

C language string functions will work till a **NULL**, or **0** bytes is found. If the **string2** variable contained the **NULL** character **\x00**, then the **strcat** function would only copy only the data before. Let's try to edit **string2** by adding a **NULL** character between **\x42** and **\x43**.

Our code should look like this:
```
char string2[] =  "\x42\x42\x42\x00\x43\x43\x43";
```
Which results with: `AAABBBCCC`

If we compile and execute the program, we will see that only part of the string is printed, that is `AAABBB`

As you can see, if our shellcode on contains **NULL** character, it wont work because it contains **strcat**.

**Shellcodes should be Null-free to guarantee the execution**. There are several types of shellcode encoding:
- Null-free Encoding
- Alphanumeric and printable encoding

Encoding a shellcode that contains **NULL** bytes means replacing machine instructions containing zeroes, with instructions that do not contain the zeroes, but that achieve the same tasks.

Let's see an example. Let's say you want to initialize a register to zero. We have different alternatives:

|Machine Code| Assembly | Comment |
|------------|----------|---------|
|B8 00000000|MOV EAX,0|Set EAX to 0|
|33 C0|XOR EAX,EAX |Set EAX to zero|
|B8 78563412|MOV EAX, 0x12345678| This also sets EAX to 0|
|2D 78563412|SUB EAX,0x12345678|||

From this, you should notice that the first instruction (**MOV EAX, 0**) should be avoided because it has **00** within its machine code representation.

Sometimes, the target process filters out all non-alphanumeric bytes from t he data. In such cases, alphanumeric shellcodes are used; however, such case instructions become very limited. To avoid such problems, **Self-modifying Code (SMC)** is used.

In this case, the encoded shellcode is prepended with a small decoder (that has to be valid alphanumeric encoded shellcode), which on execution will decode and execute the main body of shellcode.

__________________________
## 4. Debugging a Shellcode
Before we actually start writing a shellcode, it is useful to introduce a small, simple piece of code that will test to see if a shellcode works. Let's suppose we have a shellcode and we want to verify that it works.

This simplest way is to use the following program:
```
char code[] = "shellcode will go here!";
int main(int argc, char **argv)
{
  int (*func){};
  func = (int (*)()) code;
  (int)(*func)();
}
```

Once we compile and run the program, if it executes as we planned, it means that the shellcode works fine.

Here is a test. If you remember in the previous module, we used a shellcode that was intended to run the Windows Calculator.

Here is the shellcode:
```
"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
"\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
"\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
"\x57\x78\x01\xc2\x8b\x7a\x20\x01"
"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
"\x45\x81\x3e\x43\x72\x65\x61\x75"
"\xf2\x81\x7e\x08\x6f\x63\x65\x73"
"\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
"\xb1\xff\x53\xe2\xfd\x68\x63\x61"
"\x6c\x63\x89\xe2\x52\x52\x53\x53"
"\x53\x53\x53\x53\x52\x53\xff\xd7"
```

Before actually using the shellcode on the target system, we would like to verify that it works. To do so, we need to copy the shellcode into the previous C program.

After that, we need to compile and run the updated program to verify that it works.

It is not important that the program crashes because we can see that the Calculator appears, and it proves that the shellcode works.

This is a very simple C program that will help us test the results of our shellcode writing skills.

__________________________
## 5. Creating our First Shellcode
Although there are many different tools and frameworks that we can use to generate shellcodes automatically, first we will show you how to manually create a shellcode from scratch.

- **Shellcode Goal** <br>
Create a shellcode that will cause the thread to sleep for five seconds
- **Function Needed** <br>
The sleep functionality is provided by the function **Sleep** in *Kernel32.dll* and has the following [definition](https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-sleep):
```
VOID WINAPI Sleep{
  __in DWORD dwMilliseconds
};
```

The previous function requires a single parameter, which specifies the amount of time to sleep in milliseconds.

However, let's use a Disassembler to obtain the address of the Sleep function; this is required because we will create a small shellcode that calls this function.

#### 5.1. Finding Function Addresses
We can obtain the address in different ways and with different tools. To use Immunity Debugger, we have to open the *kernel32.dll* file, right-click on the disassemble panel and select *Search for>Name in all modules*.

Once the new window appears, search for *sleep*. Look at the left-most column to know the address.

Another very easy tool that we can use to get the address of a function is **arwin**. You can find it in the **4_Shellcoding.zip** file available in the members' area.

Once downloaded and extracted, we need to run the tool and provide the name of the module and the string to search.

Our command (to look for the address) will look like the following:
```
arwin.exe kernel32.dll Sleep
```

#### 5.2. Creating a small ASM code
Now that we have the address of the **Sleep** function, and we know that it requires one parameter, the next step is to create a small **ASM** code that calls this function.

Once we have the **ASM** code compiled, we can extract (by decompiling it) the machine code and use it for our shellcode.

As you already know, when a function gets called, its parameters are pushed to the stack.

Therefore, our **ASM** code will first push the parameter to the stack and then call the function **Sleep** by using its address.

The **ASM** code that we will use is:
```
xor eax,eax         ; zero out the eax register
mov eax,5000        ; move the milliseconds value into eax (5000)
push eax            ; push the function parameter onto the stack
mov ebx, 0x757d82d0 ; move the address of Sleep into ebx
call ebx            ; call the function - Sleep(ms);
```

Please note that we can create many different versions of the same code. For example, we can push *5000* directly onto the stack, without zeroing out the **EAX** register, and save one line of code.

Next, we need to compile our **ASM** code. We have already seen in the previous modules how to do this. The command is:
```
nasm -f win32 sleep.asm -o sleep.obj
```
If the command works, you should not get any messages, but a new file named *sleep.obj* is created.

It may sound weird that immediately after we have assembled our file, we have to disassemble it. This is because we want the byte code of our **ASM** instructions and to do so we can use **objdump**, as so:
```
objdump -o -Mintel sleep.obj
```

On the left, we have the byte shellcode, while on the right we have the **ASM** code. Our shellcode is almost done, we just need to do some cleaning up. We need to edit and remove the spaces and add the **\x** prefix.

At the end of the process, we will have something like the following:
```
char code[]=
"\x31\x60"
"\xb8\x88\x13\x00\x00"
"\x50"
"\xbb\xd0\x82\x7d\x75"
"\xff\xd3"

int main(int argc, char **argv)
{
  int (*func)();
  func = (int(*)()) code;
  (int)(*func)();
}
```
This is required to be able to pass the shellcode to our shellcode debugger. Now we can compile the program and run it. If the shellcode works, you will se that the process waits 5 seconds and then crashes.

**Note:**
In order for this test to work correctly, you have to know the address of Sleep() function on you own machine

Remember that not only do different OS may have different addresses, if ASLR is enabled, the address is randomized.

__________________________
## 6. More Advanced Shellcode


__________________________
## 7. Shellcode and Payload Generators
