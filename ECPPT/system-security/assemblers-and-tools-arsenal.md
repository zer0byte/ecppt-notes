# ECPPT
__________________________
# System Security
# Module 2 - Architecture Fundamentals

**Note: for further info, independent notes about the assembly language can be referenced**

_______________________
## 1. Assembler
An assembler is a program that translates the Assembly language to the machine code. There are several different assemblers that depend on the target system's **ISA**:
- Microsoft Macro Assembler ([MASM](https://msdn.microsoft.com/en-us/library/afzk3475.aspx)), x86 assembler that uses Intel syntax for MS-DOS and Microsoft Windows
- GNU Assembler ([GAS](https://www.gnu.org/software/binutils/)), used by GNU Project, default back-end of GCC
- Netwide Assembler ([NASM](http://www.nasm.us/)), x86 architecture used to write 16-bit, 32-bit(IA-32), and 64-bit(x86-64) programs, one of the most popular assemblers for Linux
- Flat Assembler ([FASM](http://flatassembler.net/)), x86, supports Intel-style assembly language on the IA-32 and x86-64

We will use **NASM** in this note

When a source code file is assembled, the resulting file is called an **object file**. It is a binary representation of the program.

While the assembly instructions and the machine code have a one-to-one correspondence, and the translation process may be simple, the assembler does some further operations such as assigning memory location to variables and instructions and resolving symbolic names.

Once the assembler has created the object file, a **linker** is needed in order to create the actual executable file. What a linker does is take one or more object files and combine them to create the executable file.

An example of these object files are the *kernel32.dll* and *user32.dll* which are required to create a windows executables that accesses certain libraries.

The process from the assembly code to the executable file can be represented here:
```
             ASM File
                 |
                 V
           -------------
           | Assembler |
           -------------
      ___________|____________
      |          |            |
      V          V            V
Object File Object File Static Library
      |          |            |
      _________________________
                 |
                 V
             ----------
             | Linker |
             ----------
                 |
                 V
             Executables


```
We will learn how to perform all this process manually
_______________________
## 2. Compiler
The compiler is similar to the assembler. It converts high-level
source code (such as C) into low-level code or directly into an object file. Therefore, once the output file is created, the previous process will be executed on the file. The end result is an executable file.

This is important background knowledge, and although we will not cover the entire, process it is important to know the differences.

_______________________
## 3. NASM
#### 3.1 NASM
**NASM** is an assembler that we will use. To make things easier, we will use the [NASM-X](http://forum.nasm.us/index.php?topic=1853.0) project. It is a collection of macros, includes, and examples to help **NASM** programmers develop applications.


How to install:
1. Download [NASMX](https://sourceforge.net/projects/nasmx/) and extract it to `C:\nasmx`
2. Add the bin to environment variables
3. Run `setpath.bat`

To work with demos:
1. Comment the following line in `C:\nasmx\demos\windemos.inc`
```
%include 'nasm.inc'
```
2. Add directly below it the following code
```
%include 'C:\nasmx\inc\nasmx.inc'
```
3. Open `C:\nasmx\demos\win32\DEMO1`

4. To use the assembler, we run the following command:
```
nasm -f win32 demo1.asm -o demo1.obj
```
5. To link the object files, use **golink**, which is located in the same package (**NASMX**) when **NASM** is downloaded:
```
golink /entry _main demo1.obj kernel32.dll user332.dll
```
6. A prompt will show up if the operations are successful

#### 3.2 ASM Basics
High-level functions such as *strcpy()* are made of multiple **ASM** instructions put together to perform the given operation (copy of 2 strings)

The simplest assembly instruction is **MOV** that moves data from one location to another in memory.

Most instructions have 2 operands and fall into one of the following classes:

Data Transfer | Arithmetic | Control Flow | Other
-----|-----|------|-----
MOV  | ADD | CALL | STI
XCMG | SUB | RET  | CLI
PUSH | MUL | LCOP | IN
POP  | XOR | Jcc  | OUT

The following is an example of a simple assembly code that sums 2 numbers:
```
MOV EAX,2   ; store 2 in EAX
MOV EBX,5   ; store 5 in EBX
ADD EAX,EBX ; do EAX = EAX + EBX  operations
            : now EAX contains the result
```

###### 3.2.1 Intel vs AT&T
Depending on the architectural syntax, instructions and rules may vary. For example, the source and the destination operands may be in different position.

example:

| |Intel (Windows)|AT&T(Linux)|
|-|---------------|-----------|
|Assembly |MOV EAX, 8|MOVL $8, %EAX|
|Syntax   | *<instruction\><destination\><source\>* | *<instruction\><source\><destination\>* |

In AT&T syntax, **%** is put before registers names and **$** is put before numbers.
Another thing to notice is that AT&T adds a suffix to t he instruction, which defines the operand size:
- **Q** (**quad** - 64 bits)
- **L** (**long** - 32 bits)
- **W** (**word** - 16 bits)
- **B** (**byte** - 8 bits)

###### 3.2.2 PUSH Instruction
As it has been said before, **PUSH** stores a value to the top of the stack, causing the stack to be adjusted by -4 bytes (on 32 bit systems): **-0x04**

*Operation : **PUSH 0x12345678***

| | Before PUSH | After PUSH | |
|-|-------------|------------| |
|**Lower memory address**||||
||          | 12345678 |**<- Top of the Stack**|
|**Top of the Stack ->** | 00000001 | 00000001 | |
| | 00000001 | 00000001 | |
| | 00000001 | 00000001 | |
| | 00000001 | 00000001 | |
|**Higher memory address**|||||

Another interesting fact:
**PUSH 0x123456789** can be analogous to some other operations, for example:
```
SUB ESP, 4            ; subtract 4 to ESP -> ESP=ESP-4
MOV [ESP], 0X12345678 ; store the value 0x12345678 to the location
                      ; pointed by ESP. Square brackets indicates to
                      ; address pointed by the registers
```

###### 3.2.3 POP Instruction
As it has been said before, **POP** stores a value to the top of the stack, causing the stack to be adjusted by +4 bytes (on 32 bit systems): **+0x04**

*Operation : **POP reg***

| | Before PUSH | After PUSH | |
|-|-------------|------------| |
|**Lower memory address**||||
|**Top of the Stack ->** | 12345678 |          ||
|| 00000001 | 00000001 | **<- Top of the Stack** |
| | 00000001 | 00000001 | |
| | 00000001 | 00000001 | |
| | 00000001 | 00000001 | |
|**Higher memory address**|||||

Another interesting fact:
**POP EAX** can be analogous to some other operations, for example:
```
MOV EAX, [ESP]        ; store the value pointed by ESP to EAX
                      ; the value at the top of the stack
ADD ESP, 4            ; add 4 to ESP - adjust the top of the stack
```

###### 3.2.4 CALL Instruction
Subroutines are implemented by using **CALL** and **RET** instruction pair.

The **CALL** instruction pushes the current instruction pointer (**EIP**) to the stack and jumps to the function address specified.


Whenever the function executes the **RET** instruction, the last element is popped from the stack, and the CPU jumps to the address.

Example of **CALL** in Assembly:
```
MOV EAX, 1      ; store 1 in EAX
MOV EBX, 2      ; store 2 in EBX
CALL ADD_sub    ; call the subroutine named 'ADD_SUB'
INC EAX         ; Increment EAX: now EAX holds "4"
                ; 2(EBX)+1(EAX)+1(INC)
JMP end_sample
ADD_sub:
ADD EAX, EBX
RETN            ; Function completed
                ; so return back to caller function
end_sample:
```

The following is an example of how to call a procedure. This example begins at *proc_2*:
```
proc proc_1
     Locals none
     MOV ECX, [EBP+8] ; ebp+8 is the function argument
     PUSH ECX
     POP ECX
end_proc
proc proc_2
     Locals none
     invoke proc_1, 5 ; invoke proc_1 proc
endproc
```

## 3.2.5. LEAVE Instruction
Is the same with

```
mov esp, ebp
pop ebp
```

You can learn more about assembly online by yourself.
_______________________
## 4. Tools Arsenal
#### 4.1 Compilers
There are several options on how you can compile your C/C++ code.
It is important tot note that different compilers may result in different outputs.
You can use IDEs or command line.

IDEs:
- Visual Studio
- Orwell Dev-C++
- Code::Blocks

Command line:
- MinGW
- [gcc](https://gcc.gnu.org/onlinedocs/)<br>
example:
`gcc -m32 main.c -o main.o`

#### 4.2 Debuggers
A debugger is a program which runs other programs, in a way that we can exercise control over the program itself. In our specific case, the debugger will help us write exploits, analyze programs, reverse engineer binaries, and much more.

As we will see, the debugger allows us to:
- Stop the program while it is running
- Analyze the stack and its data
- Inspect registers
- Change the program or program variables and more

There are several options of debuggers:
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/)
- [IDA](https://www.hex-rays.com/products/ida/) (Windows, Linux, MacOS)
- [GDB](https://www.gnu.org/software/gdb/) (Unix, Windows)
- [X64DBG](http://x64dbg.com/#start) (Windows)
- [EDB](http://codef00.com/projects#debugger) (Linux)
- [WinDBG](https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx) (Windows)
- [OllyDBG](http://www.ollydbg.de/) (Windows)
- [Hopper](http://www.hopperapp.com/) (MacOS, Linux)


#### 4.3 Decompiling
In order to be a successful pentester, you need to have the knowledge to reverse a compiled application.

You can use **objdump.exe** that is bundled with **gcc** in order to decompile a compiled application.

example: `objdump -d -Mintel main.exe > disasm.txt`

_______________________
