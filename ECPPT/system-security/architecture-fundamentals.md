# ECPPT
# System Security
# Module 1 - Architecture Fundamentals

**Note: for further info, independent notes about the assembly language can be referenced**
_______________________
## 1. Architecture Fundamentals
#### 1.1 CPU, ISA, and Assembly
The CPU is the device in charge of executing the machine code of a program.

CPU instructions are represented in hexadecimal (HEX) format. Due to its complexity, it is impossible for humans to utilize it in its natural format.

Therefore, the same code gets translated into a more readable code; this is called the assembly language (ASM). The 2 most popular are NASM (Netwide Assembler) and MASM (Microsoft Macro Assembler). The assembler we are going  to user in NASM.

This is an example of a machine language code with assembly code besides it:
```
helloworld.exe:
Dissasembly of section .text:
00401500 <_main>:
  401500:  55                    push ebp
  401501:  89 e5                 mov ebp, esp
  401503:  83 e4 f0              and esp, 0xffffff0
  401506:  83 ec 10              sub esp, 0x10
  401509:  e8 72 09 00 00        call 401e80 <___main>
  40150e:  c7 04 24 00 40 40 00  mov DWORD PTR [esp],0x404000
  401515:  e8 de 10 00 00        call 4025f8 <_puts>
  40151a:  b8 00 00 00           mov eax,0x0
  40151f:  c9                    leave
  401520:  c3                    ret

```
***Note: Each CPU has its own instructions set architecture (ISA).***

The ISA is the set of instructions that a programmer (or a compiler) must understand and use to write a program correctly for that specific CPU and machine. In other words, ISA is what a programmer can see: memory, registers, instructions, etc. It provides all the necessary information for who wants to write a program in that machine language

One of the most common ISA in x86 instruction set (or architecture) originated from the Intel 8086. x86 identifies 32-bit processors, while x64 (aka x86_64 or AMD64) identifies the 64-bit versions.

#### 1.2 Registers
The number of bits, 32 or 64, refers to the width of the CPU registers.

Each CPU has its fixed set of registers that are accessed when required. You can think of the registers as temporary variables used by the CPU to get and store data.

There are mainly 2 categories of registers: specific-purpose CPU and general purpose registers (GPRs).

The following table summarizes the eight general purpose registers for x86 architecture.

|x86 Naming Convention | Name | Purpose|
|--------------|------|---------|
| eax | Accumulator   | Used in arithmetic operation |
| ecx | Counter       | Used in shift/rotate instruction and loops |
| edx | Data          | Used in arithmetic operation and I/O |
| ebx | Base          | Used as a pointer to data |
| esp | Stack Pointer | Pointer to the top of the stack |
| ebp | Base Pointer  | Pointer to the base of the stack (aka Stack Base Pointer) |
| esi | Source Index  | Used as a pointer to a source in stream operation |
| edi | Destination   | Used as a pointer to a destination in stream operation |

The naming convention of the old 8-bit CPU had 16-bit register divided into 2 parts:
- A low byte, identified by an **L** at the end of the name
- A high byte, identified by an **H** at the end of the name

The 16-bit naming convention combines the **L** and the **H**, and replaces it with an **X**. While for Stack Pointer, Base Pointer, Source and Destination registers it simply removes the **L**.

In the 32-bit representation, the register acronym is prefixed with **E**, meaning extended. Whereas, in the 64-bit representation, **E** is replaced with the **R**.

Summary:
```
Note : size is in the table not in proportion of the actual register size
------------------------------------------------------------
| Register |Accumulator|  Counter  |    Data   |    Base   |
|----------|-----------|-----------|-----------|-----------|
| 64-bit   |    RAX    |    RCX    |    RDX    |    RBX    |
| 32-bit   |   |  EAX  |   |  ECX  |   |  EDX  |   |  EBX  |
| 16-bit   |     | AX  |     | CX  |     | DX  |     | BX  |
| 8-bit    |     |AH|AL|     |CH|CL|     |DH|DL|     |BH|BL|
------------------------------------------------------------
| Register | Stack Ptr |  Base Ptr |  Source   |Destination|
|----------|-----------|-----------|-----------|-----------|
| 64-bit   |    RSP    |    RBP    |    RSI    |    RDI    |
| 32-bit   |   |  ESP  |   |  EBP  |  |   ESI  |   |  EDI  |
| 16-bit   |     | SP  |     | BP  |     | SI  |     | DI  |
| 8-bit    |     | |SPL|     | |BPL|     | |SIL|     | |DIL|
------------------------------------------------------------
```

In addition to these general purpose registers, there is also another register that will be important for our purposes, the **EIP** (x86 naming convention). The Instruction Pointer (**EIP**) controls the program execution by storing a pointer to the address of the next instruction (machine code) that will be executed


#### 1.3 Process Memory
The process is divided into four regions: Text, Data, the Heap, and Stack.

0 (Lower memory addresses)

| .text | Instructions
|-------|
| .data | Initialized variables
|  BSS  | uninitialized variables
|  Heap |
|   v   |
|       |
|   ^   |
| Stack |

0xFFFFFFFF (Higher memory address)


The **Text** region, or instruction segment, is fixed by the program and contains the program code (instructions). This region is marked as read-only since the program should not change during execution.

The **Data** region is divided into initialized data and uninitialized data. Initialized data includes items such as static and global declared variables that are predefined and can be modified.

The uninitialized data, named Block Started by Symbol (**BSS**), also initializes variables that are initialized to zero or do not have explicit initialization (ex. `static int t`)

Next is the **Heap**, which starts right after the **BSS** segment. During the execution, the program can request more space in memory via `brk` and `sbrk` system calls, used by `mlloc`, `realloc`, and `free`.

The last region of the memory is the **Stack**. For our purposes, this is the most important structure we will deal with.

#### 1.4 The Stack
The stack is a LIFO block of memory. It is located in the higher part of the memory. You ca n think of the stack as an array used for saving a function's return address, passing function arguments, and storing local variables.

The purpose of the **ESP** register (Stack Pointer) is to identify the top of the stack, and it is modified each time a value is pushed in (**PUSH**) or popped out (**POP**).

It is important to note that **stack grows downward**, towards the lower memory addresses.

###### 1.4.1 *PUSH*
**PUSH** Process : **PUSH** is executed, the ESP register is modified<br>
Starting value : The **ESP** points to the top of the stack

**Process:**
A **PUSH** instruction subtracts 4 (in 32-bit) or 8 (in 64-bit) from the **ESP** and writes the data to the memory address in the **ESP**, and then updates the **ESP** to the top of the stack.
Remember that the stack grows downward. Therefore, **PUSH** subtracts 4 or 8. in order to point to a lower memory location on the stack. If we do not subtract it, the **PUSH** operation will overwrite the current location pointed by **ESP** (the top) and we would lose the data.

###### 1.4.2 *POP*
**POP** Process : **POP** is executed, the ESP register is modified<br>
Starting value : The **ESP** points to the top of the stack (previous **ESP** + 4)

**Process:**
The **POP** operation is the opposite of **PUSH**, and retrieves data from the top of t he Stack and stores it to a specified register. Therefore, the data contained at the address location in **ESP** (the top of the stack) is retrieved and stored (usually in another register).

After a **POP** operation, the **ESP** value in incremented, by 4 in x86 or by 8 in x64.

It is important to note that the values in the stack is not deleted (or zeroed), and will only be dereferenced.

###### 1.4.3 *Procedures and Functions*
Procedures and function alter the normal flow of the process. When a function or procedure terminates, it returns control to the statement or instruction that called the function.

###### 1.4.4 *Stack Frame*
The stack consists of logical **stack frames** (portions/areas of the stack) that are **PUSH** ed when calling a function and **POP** ped when returning a value.

When a subroutine, such a a function or procedure, is started, a stack frame is created and assigned to the current **ESP** location (top of the stack); this allows the subroutine to operate independently in its own location in the stack.

When subroutine ends, 2 things happen:
1. The program receives the parameters passed from the subroutine
2. The Instruction Pointer (**EIP**) is reset to the location at the time of the initial call.

In other words, the stack frame keeps track of the location where each subroutine should return the control when it terminates.

This process has 3 main operations:
1. When a function is called, the arguments [(in brackets)] need to be evaluated
2. The control flow jumps to the body of the function, and the program executes its code
3. Once the function ends, a return statement is encountered, the program returns to the function call (the next statement in the code)

Example:
1. Simple Example
```
int b()){
  return 0;
}
int a(){
  b();
  return 0;
}
int main(){
  a();
  return 0;
}
```

|Memory Address|initial|main() calls **a()**|a() calls b()|return from b()|return from a()|
|----|----|----|----|----|----|
|*Lower*||||||
||||Frame for **b()**|||
|||Frame for **a()**|Frame for **a()**|Frame for **a()**||
||Frame for **main()**|Frame for **main()**|Frame for **main()**|Frame for **main()**|Frame for **main()**|
|*Higher*|||||||

2. Parameterized function

```
void functest(int a, int b, int c){
  int test1 = 55;
  int test2 = 56;
}

int main(int arc, char *argv[]){
  int x = 11;
  int z = 12;
  int y = 13;
  functest(30,31,32);
  return 0;
}
```

|Memory Address|Step 1|Step 2|Step 3|Step 4|
|----|----|----|----|----|
|*Lower*|||||
|||||old EBP|
|||old EIP|old EIP|old EIP|
||argc|argc|argc|argc|
||argv|argv|argv|argv|
|...|...|...|...|...|
|*Higher*|||||||


**Step 1**<br>
When t he program starts, the function **main()** parameters (*argc*, *argv*) will be pushed on the stack, from right to left.

**Step 2**<br>
**CALL** the function **main()**. Then, the processor **PUSH** es the content of the **EIP** (Instruction Pointer) to the stack and points to the first byte after the **CALL** instruction.
This process is important because we need to know the address of the next instruction in order t o proceed when we return from the function called.

**Step 3**<br>
The caller (the instruction that executes the function calls - the OS in this case) loses its control, and the callee (the function that is called - the main function) takes control.

**Step 4**<br>
Now that we are in the **main()** function, a new stack frame needs to be created. The stack frame is defines by the **EBP** (Base Pointer) and the **ESP** (Stack Pointer). Because ewe don't want to lose the old stack frame information, we have to save the current **EBP** on the Stack. If we did not do this, when we returned, we will now know that this information belonged to the previous stack frame, the function that called **main()**. Once its value is stored, the **EBP** is updated, and it points to the top of the stack.

###### 1.4.5 *Prologue*
The steps on *example 2* is called the prologue: a sequence of instructions that take place at the beginning of a function. This will occur for all functions. Once the callee gets the control, it will execute the following instructions.

```
push ebp
mov ebp, esp
sub esp, X
```
`push ebp` saves the old base pointer onto the stack

`mov ebp, esp` copies the `esp` value to `ebp`. This creates a new stack frame on top of the stack. The base of the new stack frame is on top of the old stack frame.

`sub esp, X` moves the Stack Pointer (top of the stack) by decreasing its value; this is necessary to make space for local variables that will be inputted.

The following is how the stack looks like at the end of the entire process:

| |                |
|-|----------------|
|FT|       56       |**<- ESP**|
||       55       |
|| Old ebp (main) |**<- EBP**|
|M |    old EIP     |
| |       30       |
| |       31       |
| |       32       |
| |       ...      |
| |      13 (y)    |
| |      12 (z)    |
| |      11 (x)    |
| |     old EBP    |
|OS|     old EIP    |
||      argc      |
||      argv      |
||      ...       |

**FT : Functest stack**
**M  : Main stack**
**OS : OS stack frame**

###### 1.4.6 *Epilogue*
When a code is executes a return statement, the control goes back to the previous procedure and the left stack will be destroyed and the previous stack will be restored. We call this process **epilogue**.

The operations executed by the epilogue are the following:
1. Return the control to the caller
2. Replace the stack pointer with the current base pointer. It restores its value to before the prologue; this is done by **POP** ping the base pointer from the stack.
3. Returns to the caller by **POP** ping the instruction pointer from the stack (stored in the stack) an then jumps  to it.

The following code represents the epilogue:
```
leave
ret
```
It can also be written as follows:
```
move esp, ebp
pop ebp
ret
```

Here is what will happen when **functest()** ends:
`move esp, ebp` will copy the `ebp` value into `esp`, thus `esp` will be moved there.

`pop ebp` will **POP** the value from the top of the stack (top of the stack is pointed by the new `esp`) and copy its value to `ebp`. Since the top of the Stack points to the memory address location where the old **EBP** is stored (the **EBP** of the caller), the caller stack frame is resetored.

`ret` pops the value contained at the top of the stack to the old **EIP** - the next instruction aftere the caller, and jumps to to that location. This gives control back to the caller. **RET** affects only the **EIP** and the **ESP** registers.

#### 1.5 Endianness
Endianness is the way of representing (storing) values in memory.

There are 3 type of endianness, we will explain only 2 of them: big-endian and little-endian

- **Big Endian**
In the big-endian representation, the least significant byte (LSB) is stored at the highest memory address. While the most significant byte is the lower memory address.

Example :
The **0x12345678** value is represented as:

**Highest memory** | Address in memory | Byte value
----|----|----|
 | +0 | 0x12
 | +1 | 0x34
 | +2 | 0x56
**Lowest memory** | +3 | 0x78

or (**Note: Read from right to left**):

Memory   | Data
---------|-------
0028FEB4 | D0000000
0028FEB8 | 000ADEF2
0028FEBC | **78** 56 **34** 12

- **Small Endian**

In the small-endian representation, the least significant byte (LSB) is stored at the lower memory address. While the most significant byte is the highest memory address.

**Highest memory** | Address in memory | Byte value
----|----|----|
 | +0 | 0x78
 | +1 | 0x56
 | +2 | 0x34
**Lowest memory** | +3 | 0x12

or (**Note: Read from left to right**) :

Memory   | Data
---------|-------
0028FEB4 | D0000000
0028FEB8 | 000ADEF2
0028FEBC | **12** 34 **56** 78


#### 1.6 NOPs
**NOPs** (No Operation instruction) is an assembly language instruction that does nothing. When the program encounters a NOP, it will simply skip to the next instruction. In Intel x86 CPUs, **NOP** instructions are represented with the hexadecimal value 0x90.

**NOP** -sled is a technique used during the exploitation process of Buffer Overflows. Its only purpose is to fill a large (or small) portion of the stack with **NOPs**; this allow us to slide to the instruction we want to execute, which is usually put after the **NOP** -sled.

## 2. Security Implementations
#### 2.1 ASLR (Address Space Layout Randomization)
The goal of **ASLR** is to introduce randomness for executables, libraries, and stacks in the memory address space; this makes it more difficult for an attacker to predict memory addresses and causes exploits to fail and crash in the process.

When **ASLR** is activated, the OS loads the same executables at different location in memory every time.

It is important to note that **ASLR** is not enabled for all modules. This means that, even if a process has **ASLR** enabled, there could be a **DLL** in the address space without this protection which could make the process vulnerable to the **ASLR** bypass attack.

**Software:**
To verify the status of ASLR on different programs, download [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) and verify yourself.

Windows provides another tool that helps solve the problem of exploitation, the **Enhanced Mitigation Experience Toolkit** ([**EMET**](https://blogs.technet.microsoft.com/srd/2010/09/02/the-enhanced-mitigation-experience-toolkit-2-0-is-now-available/))

#### 2.2 DEP (Data Execution Prevention)
[**DEP**](https://support.microsoft.com/en-us/help/875352/a-detailed-description-of-the-data-execution-prevention-dep-feature-in) is a defensive hardware and software measure that prevents the execution of code from pages in memory that are not explicitly marked as executable. The code injected into the memory cannot be run from that region; this makes buffer overflow exploitations even harder.

#### 2.3 Stack Cookies (Canary)
The canary, or stack cookie, is a security implementation that places a value next to the return address on the stack.

The function prologue loads a value into this location, while the epilogue makes sure that the value is in tact. As a result, when the epilogue runs, it checks that the value is still there and that is correct.

If it is not, a buffer overflow has probably taken place .This is because a buffer overflow usually overwrites data in the stack.

________________________
