# 🎯 Level0 - The Beginning

![Helldivers Salute](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExejJwMnpmeXZ0dHp1enptbDE2am9la2Z4Ymg0eXczcmRiNzFqczJjMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/VJN5s9dNGXLDqkLYF4/giphy.gif)

Welcome to the first level of Rainfall! 🌧️

## 📋 Binary Analysis

### 🔍 Decompiled Code (Ghidra)
```c
undefined4 main(undefined4 param_1,int param_2)
{
  int iVar1;
  char *local_20;
  undefined4 local_1c;
  __uid_t local_18;
  __gid_t local_14;
  
  iVar1 = atoi(*(char **)(param_2 + 4));
  if (iVar1 == 0x1a7) {
    local_20 = strdup("/bin/sh");
    local_1c = 0;
    local_14 = getegid();
    local_18 = geteuid();
    setresgid(local_14,local_14,local_14);
    setresuid(local_18,local_18,local_18);
    execv("/bin/sh",&local_20);
  }
  else {
    fwrite("No !\n",1,5,(FILE *)stderr);
  }
  return 0;
}
```

## 🚨 Vulnerability

The binary has the **SUID bit** set for `level2` user, meaning it runs with `level2` privileges.

- ✅ Checks if the first argument equals `423` (`0x1a7` in hexadecimal)
- 🐚 If true, spawns a shell with `level2` privileges after setting the effective UID/GID
- 🎯 Simple privilege escalation through correct input

## 💣 Exploit

Simply pass `423` as the first argument:

```bash
./level0 423
```

Then read the password:

```bash
cat /home/user/level1/.pass
```

## 🔑 Key Points

- 🔢 **Magic number**: `0x1a7` = `423` (decimal)
- 🔐 **Binary permissions**: `-rwsr-s---+ 1 level2 users`
- ⚙️ Uses `setresuid`/`setresgid` to set privileges before spawning shell
- 🎮 No buffer overflow needed, just simple logic bypass
- ⚡ Difficulty: **Trivial** - Perfect warm-up!

---

> 💡 **Tip**: Always check for magic numbers and SUID binaries!
