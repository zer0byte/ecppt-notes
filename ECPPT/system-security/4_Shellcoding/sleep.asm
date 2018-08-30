xor eax,eax
mov eax, 5000        ;pause for 5000ms
push eax;
mov ebx, 0x757d82d0 ;address of Sleep
call ebx;       Sleep(ms);