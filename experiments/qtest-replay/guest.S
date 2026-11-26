/* Independent guest program for a single synthetic legacy VirtIO fixture.
 * BIOS boot sector; explicit PCI config and guest IN/OUT instructions.
 * Debugcon bytes, not a guest assertion of success, are the evidence.
 */
.code16
.section .text
.global _start
.macro write32 port,val
 movw $\port,%dx
 movl $\val,%eax
 outl %eax,%dx
.endm
.macro write16 port,val
 movw $\port,%dx
 movw $\val,%ax
 outw %ax,%dx
.endm
.macro write8 port,val
 movw $\port,%dx
 movb $\val,%al
 outb %al,%dx
.endm
.macro emit
 movw $0xe9,%dx
 .rept 4
 outb %al,%dx
 rorl $8,%eax
 .endr
.endm
.macro read32 port
 movw $\port,%dx
 inl %dx,%eax
 emit
.endm
.macro read16 port
 xorl %eax,%eax
 movw $\port,%dx
 inw %dx,%ax
 emit
.endm
.macro read8 port
 xorl %eax,%eax
 movw $\port,%dx
 inb %dx,%al
 emit
.endm
_start:
 cli
 xorw %ax,%ax
 movw %ax,%ds
 movw %ax,%ss
 movw $0x7c00,%sp
 /* Output fixture header and independent precondition observations. */
 movl $0x35454856,%eax
 emit
 write32 0xcf8,0x80003000
 read32 0xcfc
 write32 0xcf8,0x80003010
 write32 0xcfc,0x1001
 read32 0xcfc
 write32 0xcf8,0x80003004
 write16 0xcfc,1
 write8 0x1012,0
 write8 0x1012,1
 write8 0x1012,3
 read8 0x1012
 write16 0x100e,0
 read16 0x100c
 read32 0x1008
 /* Same semantic experiment, independently authored guest operations. */
 write16 0x100e,1
 read16 0x100c
 write32 0x1008,1
 read32 0x1008
 write16 0x1010,1
 read8 0x1012
 write16 0x100e,0
 read16 0x100c
 read32 0x1008
 write8 0xf4,0x10
1: hlt
 jmp 1b
.org 510
.word 0xaa55
