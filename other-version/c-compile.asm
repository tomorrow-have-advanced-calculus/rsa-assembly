power(int, int):
mov     DWORD PTR [rbp-4], 1 ; int result = 1
.L3:
  cmp     DWORD PTR [rbp-24], 0
  jle     .L2
  mov     eax, DWORD PTR [rbp-4]
  imul    eax, DWORD PTR [rbp-20]
  mov     DWORD PTR [rbp-4], eax
  sub     DWORD PTR [rbp-24], 1
  jmp     .L3
.L2:
  mov     eax, DWORD PTR [rbp-4]
  pop     rbp
  ret


algorithm(int c, int d, int n):
mov     DWORD PTR [rbp-4], 1          ; int mtmp = result = 1
.while_1:
  mov     m, eax                      ; int m = c;
  mov     DWORD PTR [rbp-12], 1       ; int s = 1
  .while_M_lessthen_N:                ; while(m<n) lable
    cmp     m, c
      jge     .calculate_next_value
    
    cmp     s, C ; didnt need to return current calcuated value
      jne     .dont_return_m_mod_n
    ;-------------------------------
    ; return (result * (m%n) ) % n |
    ;______________________________|
    mov     eax, DWORD PTR [rbp-8]
    cdq
    idiv    DWORD PTR [rbp-44]
    mov     eax, edx
    imul    eax, DWORD PTR [rbp-4]
    cdq
    idiv    DWORD PTR [rbp-44]
    mov     eax, edx
    jmp     .return
    ;-------------------------------
  
  .dont_return_m_mod_n: ; s++ & m*=c
    mov     eax, DWORD PTR [rbp-8]
    imul    eax, DWORD PTR [rbp-36]
    mov     DWORD PTR [rbp-8], eax
    add     DWORD PTR [rbp-12], 1
  jmp     .while_M_lessthen_N


  .calculate_next_value:
  
  ; a = d % s
    mov     eax, DWORD PTR [rbp-40]
    cdq
    idiv    DWORD PTR [rbp-12]
    mov     DWORD PTR [rbp-16], edx
    
  ; b = d / s
    mov     eax, DWORD PTR [rbp-40]
    cdq
    idiv    DWORD PTR [rbp-12]
    mov     DWORD PTR [rbp-20], eax
  
  ; mtmp = ( mtmp * power(c, a) ) % n
    mov     edx, DWORD PTR [rbp-16]
    mov     eax, DWORD PTR [rbp-36]
    mov     esi, edx
    mov     edi, eax
    call    power(int, int)
    imul    eax, DWORD PTR [rbp-4]
    cdq
    idiv    DWORD PTR [rbp-44]
    mov     DWORD PTR [rbp-4], edx
  
  ; c = m%n
    mov     eax, DWORD PTR [rbp-8]
    cdq
    idiv    DWORD PTR [rbp-44]
    mov     DWORD PTR [rbp-36], edx
  
  ; d = b
    mov     eax, DWORD PTR [rbp-20]
    mov     DWORD PTR [rbp-40], eax

jmp     .while_1
.return:
leave
ret