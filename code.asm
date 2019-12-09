TITLE RSA-FROM-NCU(RSA.asm)

INCLUDE Irvine32.inc
main EQU start@0

match_single PROTO, str1:PTR BYTE, str2:PTR BYTE, len:DWORD

.data
readPrimeP BYTE "Enter P ( P must be a random prime number ): ", 0
readPrimeQ BYTE "Enter Q ( Q must be a random prime number ): ", 0
match_msg BYTE 10h,"matches",0
Ppri DWORD 0
Qpri DWORD 0
Nmul DWORD 0
PhiN DWORD 0

.code
generateKey PROC USES eax ebx
	mul	Ppri
	mov	Nmul, eax
	mov	eax, Ppri
	dec	eax
	mov	ebx, Qpri
	dec	ebx
	mul	ebx
	mov	PhiN, eax
	ret
generateKey ENDP
readInput PROC USES eax edx
	push ebp
	mov ebp, esp

	mov	edx, OFFSET readPrimeP
	call	WriteString
	call	ReadDec
	mov	Ppri, eax

	mov	edx, OFFSET readPrimeQ
	call	WriteString
	call	ReadDec
	mov	Qpri, eax

	call	generateKey

	call	Clrscr

	mov	esp, ebp
	pop	ebp
	ret
readInput ENDP

match_single PROC USES edx ecx edi esi,  str1:PTR BYTE, str2:PTR BYTE, len:DWORD

  ret
match_single ENDP

main PROC
	call readInput
  exit
main ENDP
END main
