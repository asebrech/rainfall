# 🎯 Level0 - The Beginning

![Helldivers Salute](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExeGJwbjNyMW40cTRnZWk0Y3NtejlzdzN5dWFyNGVwcDUxcGVudGpsaCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/KAf66yGCa93uTqod1q/giphy.gif)

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

The binary has the **SUID bit** set for `level1` user, meaning it runs with `level1` privileges.

- ✅ Checks if the first argument equals `423` (`0x1a7` in hexadecimal)
- 🐚 If true, spawns a shell with `level1` privileges after setting the effective UID/GID
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

---

> 💡 **Tip**: Always check for magic numbers and SUID binaries!

## 🎉 Victory!

![Helldivers Celebration](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExempicnBhODF0Y3BrZG5zaWIzMmM2MWExdDZuYWNnYWJrdnRtYXg4MyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MlyicdUndRbn5zUiAL/giphy.gif)

**Flag captured!** 🚩

```
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
