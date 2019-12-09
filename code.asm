TITLE RSA-FROM-NCU(RSA.asm)

INCLUDE Irvine32.inc
main EQU start@0

RSAlgorithm PROTO, Mt:DWORD, E:DWORD, N:DWORD

.data
readPrimeP BYTE "Enter P ( P must be a random prime number ): ", 0
readPrimeQ BYTE "Enter Q ( Q must be a random prime number ): ", 0
readPubKey BYTE "Enter E, 1 < E < Φ(n): ", 0
readNumMsg BYTE "Enter a Integer: ", 0
match_msg BYTE 10h,"matches",0
Ppri DWORD 0 ; prime number P
Qpri DWORD 0 ; prime number Q
Nmod DWORD 0 ; N is P*Q
PhiN DWORD 0 ; Φ(N) = (p-1)(q-1)
PubE DWORD 0 ; Public key E
PemD DWORD 0 ; Private key D
OMsg DWORD 0
CMsg DWORD 0

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

  ; call dumpRegs
  call WriteString
  call ReadDec
  mov OMsg, eax
  INVOKE RSAlgorithm , OMsg, PubE, Nmod
  exit
main ENDP


RSAlgorithm PROC, M:DWORD, K:DWORD, N:DWORD
  ; mov eax, M
  ; mov ecx, 1
  ; whileWithMlessThenN:
    ; cmp ecx, K
    ; je returnMmodN
    ; mul M
    ; inc ecx
  ; cmp eax, N
  ; jl whileWithMlessThenN

; mov ebx, eax
; div N

; call dumpRegs
; INVOKE RSAlgorithm, edx, eax, N
; ret



; returnMmodN:
; div N
; mov eax, edx
; ret

RSAlgorithm ENDP

END main
