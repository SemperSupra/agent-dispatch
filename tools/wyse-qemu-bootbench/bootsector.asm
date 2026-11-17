; Public synthetic QEMU BIOS execution marker. Original tiny disposable test.
; Not the real Wyse UEFI recovery image, VM OS or GPU benchmark.
BITS 16
ORG 0x7c00
start:
  cli
  xor ax, ax
  mov ds, ax
  mov si, message
  mov dx, 0x00e9
.print:
  lodsb
  test al, al
  jz .work
  out dx, al
  jmp .print
.work:
  mov ecx, 3000000
.loop:
  dec ecx
  jnz .loop
  mov dx, 0x00f4
  mov al, 0x10
  out dx, al
.hang:
  hlt
  jmp .hang
message: db 'R44_GUEST_BOOTSECTOR_EXECUTED=PASS',10,0
times 510-($-$$) db 0
dw 0xaa55
