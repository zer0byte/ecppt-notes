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


__________________________
## 6. More Advanced Shellcode


__________________________
## 7. Shellcode and Payload Generators
