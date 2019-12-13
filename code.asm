TITLE RSA-FROM-NCU(RSA.asm)

INCLUDE Irvine32.inc
main EQU start@0

;-------------------------------------------------------------------------------------
; RSAlgorithm         -  encrypte and decrypte function                               |
; power               -  other useful function                                        |
; readInteger         -  easy to print message and read an integer                    |
; printMessage        -  easy to print message and an integer                         |
; printlnMessage      -  easy to print message with change line                       |
; setup               -  rsa generating function                                      |
; coprimeTest         -  setup function's public key test                             |
; generatePrivateKey  -  setup function's generate a private key to decrypte message  |
;-------------------------------------------------------------------------------------
RSAlgorithm PROTO, Mt:DWORD, E:DWORD, N:DWORD
power PROTO , a:DWORD, n:DWORD

readInteger PROTO, msg:PTR BYTE, target:PTR DWORD
printMessage PROTO, msg:PTR BYTE, value:DWORD
printlnMessage PROTO, msg:PTR BYTE, value:DWORD
setup PROTO,  P:PTR DWORD, Q:PTR DWORD, N:PTR DWORD, PN:PTR DWORD, E:PTR DWORD, D:PTR DWORD
coprimeTest PROTO, num:DWORD, N:DWORD, PN:DWORD
generatePrivateKey PROTO, E:DWORD, N:DWORD, D:PTR DWORD

.data
; primeNumber - can be used prime number list
primeNumber DWORD 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191
whitespace BYTE " ", 0
readPrimeP BYTE "Enter P ( P must be a random prime number ): ", 0
readPrimeQ BYTE "Enter Q ( Q must be a random prime number ): ", 0
readPubKey BYTE "Enter E(Public key), 1 < E < Φ(n): ", 0
readNumMsg BYTE "Enter an Integer: ", 0
useableMsg BYTE "Useable number:", 0
pemDKeyMsg BYTE "Your private key: ", 0
plaintextMsg BYTE  "Your Plaintext: ", 9, 0
ciphertextMsg BYTE "Your Ciphertext: ", 9, 0

showModMsg BYTE "Modulus N(mod N): ", 0
showPhiMsg BYTE "Totient N(Φ(N)): ", 0
match_msg BYTE 10h,"matches",0
Ppri DWORD 0  ; prime number P
Qpri DWORD 0  ; prime number Q
Nmod DWORD 0  ; N is P*Q
PhiN DWORD 0  ; Φ(N) = (p-1)(q-1)
PubE DWORD 0  ; Public key E
PemD DWORD 0  ; Private key D

OMsg DWORD 0  ; Plaintext Message
CMsg DWORD 0  ; Ciphertext Message

Ctmp DWORD 1  ; temp memory (RSA Calculation)

.code
readInteger PROC USES eax edx edi, msg:PTR BYTE, target:PTR DWORD

  ; copy target address to edi then copy the value to target address
  mov edi, target
  
  ;print message
  mov edx, msg
  call WriteString
  
  ; read value then write into the [target]
  call ReadDec
  mov [edi], eax

  ret
readInteger ENDP
printMessage PROC USES eax edx, msg:PTR BYTE, value:DWORD
  ; write message
  mov edx, msg
  call WriteString

  ; write integer
  mov eax, value
  call WriteDec

  ret
printMessage ENDP
printlnMessage PROC USES eax edx, msg:PTR BYTE, value:DWORD
  ; call printMessage
  INVOKE printMessage, msg, value
  ; change line
  call Crlf
  ret
printlnMessage ENDP

setup PROC USES eax ebx ecx edx, P:PTR DWORD, Q:PTR DWORD, N:PTR DWORD, PN:PTR DWORD, E:PTR DWORD, D:PTR DWORD
  ; --------------------
  ; print all useable P and Q then P can not be equal Q
  call Crlf
  call Crlf
  lea edi, primeNumber
  call Crlf
  mov edx, OFFSET useableMsg
  call WriteString
  printAllUseableNumber:
    mov ecx, [edi]
    cmp ecx, 181
      jg printAllUseableNumberEnd
    INVOKE printMessage, OFFSET whitespace, ecx
      add edi, 4
  jmp printAllUseableNumber
  printAllUseableNumberEnd:
  call Crlf
  call Crlf
  ; --------------------


  ; --------------------
  ; read P and Q
  INVOKE readInteger, OFFSET readPrimeP, OFFSET Ppri
  INVOKE readInteger, OFFSET readPrimeQ, OFFSET Qpri
  ; --------------------

  ; --------------------
  ; calculate modules N
  mov eax, Ppri
  mul Qpri
  mov Nmod, eax
  ; --------------------
  
  ; --------------------
  ; calculate Totient N
  mov eax, Ppri
  mov ebx, Qpri
  dec eax
  dec ebx
  mul ebx
  mov PhiN, eax
  ; --------------------

  ; --------------------
  ; Print N and Phi(N)
  INVOKE printlnMessage, OFFSET showModMsg, Nmod
  INVOKE printlnMessage, OFFSET showPhiMsg, PhiN
  ; --------------------
  
  ; --------------------
  ; generate useable Public key (number e)
  lea edi, primeNumber
  call Crlf
  mov edx, OFFSET useableMsg
  call WriteString

  publicCoprimeTest:
    ; 1 < ecx < Phi(N)
    mov ecx, [edi]
    cmp ecx, 181
      jg publicCoprimeTestEnd
    cmp ecx, PhiN
      jge publicCoprimeTestEnd
    
    INVOKE coprimeTest, ecx, Nmod, PhiN

    ; call dumpRegs
    cmp eax, 6666
      je dontPrintE

    INVOKE printMessage, OFFSET whitespace, ecx
    dontPrintE:
      add edi, 4
  jmp publicCoprimeTest
  publicCoprimeTestEnd:
  call Crlf
  call Crlf
  ; --------------------

  ; --------------------
  ; read public key ( E ) then generate private key
  INVOKE readInteger, OFFSET readPubKey, OFFSET PubE
  INVOKE generatePrivateKey, PubE, Nmod, OFFSET PemD
  INVOKE printlnMessage, OFFSET pemDKeyMsg, PemD
  ; --------------------
  
  ret
setup ENDP
coprimeTest PROC, num:DWORD, N:DWORD, PN:DWORD
  ; --------------------
  ; test num is coprime with N or not
  mov eax, N
  CDQ
  div num
  cmp edx, 0
    je returnNCP ; not coprime with N return 6666
  ; --------------------

  ; --------------------
  ; test num is coprime with PhiN or not
  mov eax, PhiN
  CDQ
  div num
  cmp edx, 0
    je returnNCP ; not coprime with PhiN
  jmp return
  ; --------------------

  returnNCP:
    mov eax, 6666
  return:
    ret
coprimeTest ENDP
generatePrivateKey PROC, E:DWORD, N:DWORD, D:PTR DWORD
  ; --------------------
  ; setup first private
  xor eax,eax
  mov ebx, 2
  ; --------------------

  ; --------------------
  ; Start calculate private key
  cal:
    inc ebx 

    mov eax, PubE
    mul ebx
    div PhiN

    cmp edx, 1
      jne cal 
  endCal:
  ; --------------------

  ; --------------------
  ; if e*d !≡ 1 (mod N) then calculate an new key
  cmp ebx, PubE
    je cal
  mov PemD, ebx
  ; --------------------
  ret
generatePrivateKey ENDP
main PROC
  
  INVOKE setup, OFFSET Ppri, OFFSET Qpri, OFFSET Nmod, OFFSET PhiN, OFFSET PubE, OFFSET PemD
  call Crlf
  
  ; read a integer to encrypte
  INVOKE readInteger, OFFSET readNumMsg, OFFSET OMsg
  call Crlf

  ; encrypte message
  INVOKE RSAlgorithm , OMsg, PubE, Nmod
  INVOKE printlnMessage, OFFSET ciphertextMsg, eax
  
  ; decrypte message
  INVOKE RSAlgorithm , eax, PemD, Nmod
  INVOKE printlnMessage, OFFSET plaintextMsg, eax
  call Crlf
  
  exit
main ENDP

RSAlgorithm PROC USES ecx edx, M:DWORD, d:DWORD, N:DWORD
;https://github.com/tomorrow-have-advanced-calculus/algorithm/blob/master/loop.js
;int ctmp = 1
mov Ctmp, 1

while_1:
  mov eax, M ; eax = m = c
  mov ecx, 1 ; ecx = s = 1
  while_m_lessthen_n:
    cmp eax, N
      jae while_m_lessthen_n_End
    
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
  while_m_lessthen_n_End:

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