# Assembly
## Parts
Assembly mainly consists of 3 parts, that is registers, program, and stack.
```
|-----------| High memory
|  arg1     |
|-----------|
|  arg2     |
|-----------|
|  return   |
|-----------|
|  old ebp  |
|-----------|----------------
|           |       |       |
|  heap 1   |       V       |
|    ^      |               |
|    |      |               |
|-----------|               |   stack
|           |               |
|  heap 2   |               |
|     ^     |               |
|     |     |               |
|-----------| Low memory ----

```
Notes:
- Heaps are in the Stack
- Heaps contains variable
- Heaps grows from high memory to low memory
- Stack grows from low memory to high memory
- Arguments may also be in the form of heaps

## Program
Program consists of instructions and addresses on its left. <br>
Some notable instructions are:

There are an instruction named system call, by which, assembly program may tell a CPU to do something. You can do a system cal by... (later, forgot)

Flow:
1. Usally ebp are pushed, then ebp are moved to esp
2. Program is executed
3. Leave is called, which moves esp to ebp and pops it, then return is called

## Registers
Registers consists of saves value. Most notable ones are:

Registers | Function
----------|-----------
`ebp`     | A base pointer, which is the base of a stack
`esp`     | A stack pointer, which points to the top of the stack
`eip`     | An instruction pointer, points to the instruction that currently run
`eax`     | General purpose register, usually to hold arithmetic value
`ebx`     | General purpose register
`ecx`     | General purpose register
`edx`     | General purpose register

General purpose registers may also be used to do system calls

## Stack


## gdb
