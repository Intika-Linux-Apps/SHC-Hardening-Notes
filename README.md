# SHC-Hardening-Notes


Protect from ld_preload 
```
    if (getenv("LD_PRELOAD")) {if(strcmp(getenv("LD_PRELOAD"), "") != 0) {exit(0);exit(0);}}
    unsetenv("LD_PRELOAD");
```

Preload lib code
```
setenv("LD_PRELOAD","/home/intika/Downloads/down/shc/src/test/x.so",1);
```

Alternative preload lib code (not working for execl)
```
        if(dlopen("/test/x.so", RTLD_LAZY | RTLD_GLOBAL))
        printf("libc loading succeeded\n");
        else
        printf("libc loading failed\n");   
```

System() alternative (system use fork and execl)
```
int runThis=execl("/bin/sh", "sh", "-c", "sleep 50", (char *) 0);
```

Arguments manipulation
```
strncpy(argv[0], "mynewcmdlinehere", strlen(argv[0]));
strncpy(argv[1], "randomtrash", strlen(argv[1]));
```

# Links
https://stackoverflow.com/questions/54819710/hide-execl-arguments-from-ps/

https://unix.stackexchange.com/a/404180/120919

https://samanbarghi.com/blog/2014/09/05/how-to-wrap-a-system-call-libc-function-in-linux/

https://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/

https://github.com/Intika-Linux-Apps/Ptrace-Redirect

https://unix.stackexchange.com/questions/403870/hide-arguments-to-program-without-source-code

