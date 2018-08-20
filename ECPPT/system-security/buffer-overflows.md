# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# System Security
# Module 3 - Buffer Overflows

https://members.elearnsecurity.com/course/resources/1852

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
- A dynamic analysis tool like a **fuzzer** or tracer, which tracks all executions ant the data flow, help in finding problems

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
Another tool that will help you identify buffer overflows is IDA Pro. You can download a free non-commercial [edition](http://www.hex-rays.com/).

_______________________
## 3. Exploiting Buffer Overflows


#### 3.1 Finding the Right Offset
In the previous example, it was easy to find to right offset where to overwrite the **EIP** address. In real exploitation process, the amount of characters needed in order to crash an application may vary in size.

We can check by using various searching methods (e.g. binary search), or we can use some tools.

Tools that may be in use:
- [pattern_create](https://github.com/lattera/metasploit/blob/master/tools/pattern_create.rb) and [pattern_offset](https://github.com/lattera/metasploit/blob/master/tools/pattern_offset.rb) (Ruby)

  The purpose of these scripts are really simple.

  **pattern_create** receives a number and outputs a pattern that is as long as the input.

  If we feed this output to our vulnerable target application, there will be an error message that tells us where the error takes place (which is usually the value of **EIP** register being overwritten)

  **pattern_offset** receives a memory address and outputs how much offset is necessary to overwrite that address.

- [Mona](https://github.com/corelan/mona) ([Tutorial](https://www.corelan.be/index.php/articles/)) (Python)
**Mona** is an (Immunity Debugger) plugin that functions the same as **pattern_create** and **pattern_offset**.

#### 3.2 Overwriting the EIP
Now that know the correct size of our payload, we have to overwrite the **EIP** with a value. Remember that the value we overwrite will be used by the **RET** instruction to return.

**We want to return to our shellcode so that it gets executed.**

At this point, our shellcode is stored at the memory address pointed by **ESP**, therefore, returning to our shellcode means jumping to that address. The problem is that the address in the stack changes dynamically, so we cannot use it to build the exploit.

What we can do is find a **JMP ESP** (or **CALL ESP**) instruction that is in a fixed location of memory.

This way when the program returns, instead of *ABCD*, it will execute a **JMP ESP** (or **CALL ESP**), and it will automatically jump to the area where out shellcode is stored.

In environment where **ASLR** is not enabled, we know that **kernel32.dll** functions are located at fixed addresses in memory; this allows us to perform a **JMP ESP** or a **CALL ESP** to the process address space, a line in *kernel32.dll*.

(**kernel32.dll** is the 32-bit dynamic link library found in the Windows operating system kernel. It handles memory management, input/output operations, and interrupts. When Windows boots up, *kernel32.dll* is loaded into a protected memory space so other applications do not take that space over. Other *.dll* s may also help, not only this one).

We can safely jump to this line and back from the kernel32 to the address in **ESP** (that holds the first line of our shell code).

There are different tools and techniques that we can use to detect the address of a **CALL/JMP ESP**. One of them simply disassemble the *.dll* and then search for the instruction.

To disassemble a *.dll* you can load it into Immunity Debugger (or IDA) an then search for one of two commands: **CALL ESP** or **JMP ESP**.

Another tool that we can use to find **CALL ESP** and **JMP ESP** instructions is **findjmp2**, which receives the target *.dll* and the registry name we want to search

You can also use Mona to do this.

Example:<br>
You can see the *goodpwd.exe*.<br>
The variable command is conmpsed as follows: Junk bytes + **EIP** + shellcode<br>
Also, notice that at the beginning of t he shellcode we added some **NOP** s (\x90). Therefore, once the **JMP ESP** is executed, the first instruction that will be executed is a **NOP**. The program will then continue to slide down the NOPs and execute the actual shellcode.

Program flow:

| |            . . .             | |
|-|------------------------------| |
|(2)|             junk             |<-(1) We start injecting here|
|I|             junk             | |
|I|            . . .             | |
|I|             junk             | |
|I|             junk             | |
|I|       junk (EBP was here)    | |
|I-->|        \x3B\x7D\x26\x77      |(3)-> (kernelbase.dll) 0x77267D3B; **JMP ESP**|
|**ESP**->| shellcode (\x90\x90\x90\x90) |<--I(4) **EIP** will go here, because (3)|
| | shellcode (\x90\x90\x90\x90) | |
| |         shellcode (...)      | | |


**Note:**
Use Windows XP to simulate buffer overflow without **DEP** and **ASLR** protection.
_______________________
## 4. Exploring a Real-World Buffer Overflow


## 5. Security Implementations
#### 5.1 Helpful Tools
[EMET](https://support.microsoft.com/en-us/kb/2458544) (Enhanced Mitigation Experience Toolkit) ([Manual](https://www.microsoft.com/en-us/download/details.aspx?id=50802))
is a utility that help prevent vulnerabilities in software from being successfully exploited. EMET offers many different mitigation technologies, such as DEP, ASLR, SEHOP, and more.

EMET can be used to enhance the security of our system and it can also be used to disable them. This is especially useful when testing our exploits since we can force programs and applications not to use them.

It is important to note that on newer operation systems, ASLE, DEP, and SEHOP cannot be completely disabled..

#### 5.2 ASLR (Address Space Layout Randomization)
The goal of ASLR is to introduce randomness for executables, libraries, and stack in process address space, making it more difficult for an attacker to predict memory addresses.

When ASLR is activated, the OS loads the same executable at different locations in memory every time (at every boot).

You can check it yourself by opening a *.dll* or a *.exe* file in Immunity Debugger and then click on the *executable modules panel*.

With ASLR enabled, some of the modules will not be loaded into predictable memory locations anymore.

Therefore, exploits that work by targeting known memory location (like our CALL/JMP ESP exploit) will not be successful anymore. The address of the operation will change on every reboot on every machine.

ASLR is not enabled for all modules. This means that if a process has ASLR enabled, there could be a *dll* (or another module) in the address space that does not use it, making the process vulnerable to ASLR bypass attack.

The easiest way to verify which processes have ASLR enabled is to download and run [Process Explorer](http://technet.microsoft.com/en-us/sysinternals/bb896653). In the ASLR column, you can see if the process implements or not ASLR.

Immunity Debugger also allows you to check the ASLR status by using Mona to verify modules properties.

#### 5.2.1 [Bypassing Technique](https://www.corelan.be/)
([Other Reference](https://www.fireeye.com/blog/threat-research/2013/10/aslr-bypass-apocalypse-in-lately-zero-day-exploits.html))

There are different methods that we can use, but most of them requires very good experience in reverse engineering, exploit writing, and much more, so we will only discuss some of them.

1. **Non-Randomized Module**

  One of the technique aims to find a module that does not have ASLR enabled and then use a simple **JMP/CALL ESP** from that module.

2. **Brute Force**

  With this method, ASLR can be forced by overwriting the return pointer with plausible addresses until, at some point, we reach the shellcode.

  The success of pure brute-force depends on how tolerant an exploit is to variations in the address space layout (e.g., how many NOPs can be placed in the buffer), and on how many exploitation attempts one can perform.

  This method is typically applied against those services configured to be automatically restarted after a crash.

3. **NOP-Sled**

  We create a big area of NOPs in our shellcode in order to increase the chances to jump to this area.

  The advantage of this technique is that the attacker can guess the jump location with a low degree of accuracy and still successfully exploit the program.

4. **Other methods**
  - [Universal-depalsr-bypass-with-msvcr71-dll-and-mona-py](https://www.corelan.be/index.php/2011/07/03/universal-depaslr-bypass-with-msvcr71-dll-and-mona-py/)
  - [https://www.exploit-db.com/docs/english/17914-bypassing-aslrdep.pdf](https://www.exploit-db.com/docs/english/17914-bypassing-aslrdep.pdf)
  - [Exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)


#### 5.2.2 Protective Measures
We achieve maximum defense when ASLR is correctly implemented and DEP is enabled. For deeper, more technical information on this, please check [here](http://blogs.technet.com/b/srd/archive/2010/12/08/on-the-effectiveness-of-dep-and-aslr.aspx).


#### 5.3 Data Execution Prevention
Another defensive feature designed for OSes is called Data Execution Prevention (DEP). It is a hardware and software defensive measure for preventing the execution of code from pages of memory that are not explicitly marked as executable.

DEP helps prevent certain exploits where the attacker injects new code on the stack.

#### 5.3.1 Bypassing Technique
Bypassing DEP is possible by using a technique called [Return Oriented Programming (ROP)](https://cseweb.ucsd.edu/~hovav/talks/blackhat08.html). ROP consists of finding multiple machine instructions in the program (called gadget), in order to create a chain of instructions that do something.

Since the instructions are part of the stack, DEP does not apply on them.

Gadgets are small groups of instructions that perform some operations (arithmetical operations on registers, check for conditional jumps, store or load data and so on) and that end with RET instruction.

The RET is important since it will allow the chain to work and keep jumping to the next address after executing the small set of instructions.

The purposes of the entire chain are different. We can use ROP gadgets to call a memory protection function (kernel API such as *VirtualProtect*) that can be used to mark the stack as executable; this will allow us to run our shellcode as we have seen in the previous examples.

But we can also use ROP gadgets to execute direct commands or copy data into executable regions and then jump to it.

Mona offers a great feature that generates thee ROP gadget chain for us.

[Here](https://www.corelan.be/index.php/security/rop-gadgets/) you can find list of ROP gadgets from different libraries and .dll files, while [here](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/#buildingblocks) you can find a good article that goes deeper in ROP gadgets.

#### 5.3.2 Protective Measures
In order to avoid exploit of such techniques, ASLR was introduced. By making kernel API's load at random addresses, bypassing DEP becomes hard.

If both DEP and ASLR are enabled, code execution is sometimes impossible to achieve in one attempt.

#### 5.4 Stack Canary and SafeSEH
Another security implementation that has been developed during the years is the Stack Canary (a.k.a. Stack cookie).

The term canary comes from the [canary in a coal mine](https://en.wiktionary.org/wiki/canary_in_a_coal_mine), and its purpose is to modify almost all the function's prologue and epilogue instructions in order to place a small random integer value (canary) right before the return instruction, and detect if a buffer overflow occurs.

As you may have known, most buffer overflows overwrite memory address location in the stack right before the return pointer this means that the canary value will be overwritten too.

When the function returns, the value is checked to make sure that it was not changed. If so, it means that a stack buffer overflow occurred.

#### 5.4.1 Bypassing Technique
In order to bypass this security implementation, one can try to retrieve or guess the canary value, and add it to the payload.

Beside guessing, retrieving or calculating the canary value, [David Litchfield](https://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-litchfield.pdf) developed a method that does not require any of these. If the canary does not match, the exception handler will be triggered. If the attacker can overwrite the Exception Handler Structure ([SEH](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680657(v=vs.85).aspx) and trigger an exception before the canary value is checked, the buffer overflow could still be executed.

#### 5.4.2 Protective Measures
This introduced a new security measures called SafeSEH.

You can read more about it [here](https://msdn.microsoft.com/en-us/library/9a89h429.aspx) and [here](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/) you can find a very good article on how to bypass stack canary.

_______________________
