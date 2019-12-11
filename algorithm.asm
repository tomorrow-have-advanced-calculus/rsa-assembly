TITLE RSA-FROM-NCU(RSA.asm)

INCLUDE Irvine32.inc
main EQU start@0

RSAlgorithm PROTO, Mt:DWORD, E:DWORD, N:DWORD
power proto , a:DWORD, n:DWORD

.data
readPrimeP BYTE "Enter P ( P must be a random prime number ): ", 0
readPrimeQ BYTE "Enter Q ( Q must be a random prime number ): ", 0
readPubKey BYTE "Enter E, 1 < E < Φ(n): ", 0
readNumMsg BYTE "Enter an Integer: ", 0
match_msg BYTE 10h,"matches",0
Ppri DWORD 0 ; prime number P
Qpri DWORD 0 ; prime number Q
Nmod DWORD 0 ; N is P*Q
PhiN DWORD 0 ; Φ(N) = (p-1)(q-1)
PubE DWORD 0 ; Public key E
PemD DWORD 0 ; Private key D
OMsg DWORD 0
CMsg DWORD 0

Ctmp DWORD 1
OriM DWORD 0
OriD DWORD 0

.code
calculatePrivateKey PROC USES eax ebx ecx edx
xor eax,eax
mov ebx, 2
cal:
  inc ebx 

  mov eax, PubE
  mul ebx
  ; mov ecx, PhiN
  ; div ecx
  div PhiN

  cmp edx, 1
  jne cal
endCal:

  cmp ebx, PubE
  je cal
  mov PemD, ebx
  ret
calculatePrivateKey ENDP

readPublicKeyE PROC USES eax ebx
  mov edx, OFFSET readPubKey
  call WriteString
  call ReadDec
  mov PubE, eax
  call calculatePrivateKey
  ret
readPublicKeyE ENDP

generateKey PROC USES eax ebx
  mul Ppri
  mov Nmod, eax
  mov eax, Ppri
  dec eax
  mov ebx, Qpri
  dec ebx
  mul ebx
  mov PhiN, eax
  call readPublicKeyE
  ret
generateKey ENDP

readTwoPrimeNumber PROC USES eax edx
  push ebp
  mov ebp, esp

  mov edx, OFFSET readPrimeP
  call WriteString
  call ReadDec
  mov Ppri, eax

  mov edx, OFFSET readPrimeQ
  call WriteString
  call ReadDec
  mov Qpri, eax

  call generateKey

  ;call Clrscr

  mov esp, ebp
  pop ebp
  ret
readTwoPrimeNumber ENDP

main PROC
  call readTwoPrimeNumber
  mov eax, PemD
  mov edx, OFFSET readNumMsg

  call dumpRegs
  call WriteString
  call ReadDec
  mov OMsg, eax
  INVOKE RSAlgorithm , OMsg, PubE, Nmod
  call dumpRegs
  call Crlf
  call Crlf
  call Crlf
  mov edx, Nmod
  call dumpRegs
  INVOKE RSAlgorithm , eax, PemD, Nmod
  ; mov eax, OMsg
  call dumpRegs
  exit
main ENDP

RSAlgorithm PROC, M:DWORD, d:DWORD, N:DWORD
;int ctmp = 1
mov Ctmp, 1

while_1:
  mov eax, M ; eax = m = c
  mov ecx, 1 ; ecx = s = 1
  while_m_lessthen_n:
    cmp eax, N
      jae calculate_next_value
    
    cmp ecx, d
      jne dont_return_m_mod_n
    
    ; return m % n
    cdq
    div N
    mov eax, edx

    mul Ctmp

    cdq
    div N
    mov eax, edx
    jmp return
    
    dont_return_m_mod_n:
    mul M
    inc ecx
    
  jmp while_m_lessthen_n
  calculate_next_value:

  push eax ; backup m
  
  ; a = d%s, b = d/s
  mov eax, d
  xor edx, edx
  cdq
  div ecx ; b = eax, a = edx
  
  mov d, eax ; d = b

  ; mov eax, edx; eax = a, edx = b, then eax = power(M, eax)
  INVOKE power, M, edx  ; eax = power(M, a)
  mul Ctmp              ; eax = eax*Ctmp
  cdq	
  div N                ; edx = eax % n
  mov Ctmp, edx         ; storage Ctmp => Ctmp = ( power(c, a)*Ctmp )%n

  pop eax      ; eax = m
  cdq
  div n       ; edx = m % n
  mov M, edx   ; c = m%n

jmp while_1
return:
  ret


RSAlgorithm ENDP

power PROC USES ecx, a:DWORD, n:DWORD
  mov eax, 1
  mov ecx, n
  cmp ecx, 0
  je returnVal
  l:
    mul a
  loop l
  returnVal:
  ret
power ENDP
END main