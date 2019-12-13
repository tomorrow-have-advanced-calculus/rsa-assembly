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
  mov CMsg, eax
  call dumpRegs
  CLR
  call dumpRegs
  INVOKE RSAlgorithm , CMsg, PemD, Nmod
  call Crlf
  call Crlf
  call Crlf
  ; mov eax, OMsg
  call dumpRegs
  exit
main ENDP

RSAlgorithm PROC, M:DWORD, d:DWORD, N:DWORD

rec:
  mov eax, M ;let eax be the base, eax = m = c
  mov ecx, 1 ;ecx = s = 1
fuckingWhile:
  cmp eax, N
    jae L
  cmp ecx, d
    je final
  mul M
  inc ecx
  jmp fuckingWhile
  
L:
  ; call dumpRegs; eax = m => m = c^a
  push eax ;push newM
  mov eax, d ;eax = k = d, calculate a and b
  div ecx ;ecx = s, eax = b, edx = a
  push eax ;push b
  invoke power, M, edx ;calculate M^a
  mul Ctmp
  CDQ
  div N
  mov Ctmp, edx
  pop d ; d = b
  pop eax ; use for calculate new base => m%n
  CDQ
  div N 
  mov M, edx ; c = edx = m%n
  jmp rec
  
final:
  mul Ctmp
  CDQ
  div N
  mov eax, edx
  ret
RSAlgorithm ENDP

power PROC USES ecx, a:DWORD, n:DWORD
  mov eax, 1
  mov ecx, n
  l:
    mul a
  loop l
  ret
power ENDP
END main
