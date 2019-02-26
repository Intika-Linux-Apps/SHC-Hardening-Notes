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

# SO Question

**How to hide/change a process argument after `execl()`? or how can we hide/change arguments of a child process that is using `system()` / `execl()`?**

Working on [SHC][1] (the purpose of this application is to compile a bash script into a binary) i am using `execl()` function to execute the sh script; The problem is that `execl()` argument are exposed to `ps`; the purpose of this question is to make SHC just a little bit more reliable and solve some issues reported by users.


    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    
    int main(int argc,char* argv[]){
    
        int runThis;
    
        //Create child process
        if(fork() == 0){ 
            printf("I'm the child\n");
            //runThis = system("echo test; sleep 30");
            runThis = execl("/bin/sh", "sh", "-c", "echo test; sleep 30", (char *) 0);
            exit(0);
        } else {
            printf("I'm the parent.\n");
        }
    
        printf("Continue main\n");
    
        return 0;
    }

When running this code, `sh -c echo test; sleep 30` is exposed to `ps`

**Solution attempt 1: successful but not reliable** 

Hiding commands arguments with `ld_preload` can be done with this [solution][2] or by using `setenv("LD_PRELOAD","myLib.so",1);` (`dlopen()` will not work with `execl()`), this solution require indeed loading a library to our application.

**Solution attempt 2: semi successful**

Wrapping `__libc_start_main` with `ld --wrap=symbol`, this works for parent but the code is not wrapped after `execl()` / `system()`

    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include <signal.h>
    #include <unistd.h>
    
    int __real___libc_start_main(int (*main) (int, char **, char **), int argc, char **ubp_av, void (*init) (void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end));
    
    int __wrap___libc_start_main(int (*main) (int, char **, char **), int argc, char **ubp_av, void (*init) (void), void (*fini)(void), void (*rtld_fini)(void), void (*stack_end)) {    
        printf("Main called\n");
        //ubp_av[1] = "test";
        int result = __real___libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
        return result;
    }

Build commands: (`wrap.c` is the code above and `example.c` is the first code sample)

    gcc -c example.c -o 1.o;
    gcc -c wrap.c -o 2.o;  
    gcc -Wl,-wrap,__libc_start_main -Wl,-wrap=__libc_start_main 1.o 2.o -o myapp

**Solution attempt 3: semi successful**

Similar to attempt 2, it consist of linking the code of attempt 1 at build time... but this does not work with `execl()`
 
- build the library as libfoo or an other name `gcc -Wall -O2 -fpic -shared -Wl,-soname,libfoo.so -ldl -o libfoo.so wrap.c` (wrap.c is the code from attempt 1)
- install it `sudo ln -s /path/libfoo.so /usr/lib64/libfoo.so`
- link it `gcc example.c -o myapp -L.. -lfoo`

**Solution attempt 4: related but not useful here**

Ptrace can be used from the parent process to modify the child argument after `execl()` [example-1][3] [example-2][4]

  [1]: https://github.com/neurobin/shc
  [2]: https://unix.stackexchange.com/a/403918
  [3]: https://github.com/alfonsosanchezbeato/ptrace-redirect
  [4]: https://github.com/emptymonkey/ptrace_do

# SO Answers 

**Alternative solution:** 

Bash content can be piped and thus hidden from ps 

    script="script goes here"
    echo $script | bash

**Mitigated solution:** 

This is not a perfect solution, but it will answer the question, this code will create an `shc_x.c` under /tmp build it, then preload it with environment variable. 

shc_x.c, inject the bash sh content to ******** argument by replacing it and change the location of child commands arguments and thus hide them from ps as well.

**shc_x.c:** (this file is generated with the second code)

    /*
     * Copyright 2019 - Intika <intika@librefox.org>
     * Replace ******** with secret read from fd 21
     * Also change arguments location of sub commands (sh script commands)
     * gcc -Wall -fpic -shared -o shc_secret.so shc_secret.c -ldl 
     */
    
    #define _GNU_SOURCE /* needed to get RTLD_NEXT defined in dlfcn.h */
    #define PLACEHOLDER "********"
    #include <dlfcn.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <stdio.h>
    #include <signal.h>
    
    static char secret[128000]; //max size
    typedef int (*pfi)(int, char **, char **);
    static pfi real_main;
    
    // copy argv to new location
    char **copyargs(int argc, char** argv){
        char **newargv = malloc((argc+1)*sizeof(*argv));
        char *from,*to;
        int i,len;
    
        for(i = 0; i<argc; i++){
            from = argv[i];
            len = strlen(from)+1;
            to = malloc(len);
            memcpy(to,from,len);
            // zap old argv space
            memset(from,'\0',len);      
            newargv[i] = to;
            argv[i] = 0;
        }
        newargv[argc] = 0;
        return newargv;
    }
    
    static int mymain(int argc, char** argv, char** env) {
        //fprintf(stderr, "Inject main argc = %d\n", argc);
        return real_main(argc, copyargs(argc,argv), env);
    }
    
    int __libc_start_main(int (*main) (int, char**, char**),
                          int argc,
                          char **argv,
                          void (*init) (void),
                          void (*fini)(void),
                          void (*rtld_fini)(void),
                          void (*stack_end)){
        static int (*real___libc_start_main)() = NULL;
        int n;
    
        if (!real___libc_start_main) {
            real___libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
            if (!real___libc_start_main) abort();
        }
    
        n = read(21, secret, sizeof(secret));
        if (n > 0) {
          int i;
    
        if (secret[n - 1] == '\n') secret[--n] = '\0'; 
          for (i = 1; i < argc; i++)
            if (strcmp(argv[i], PLACEHOLDER) == 0)
              argv[i] = secret;
        }
        
        real_main = main;
    
        return real___libc_start_main(mymain, argc, argv, init, fini, rtld_fini, stack_end);
    }

**On the main c application:**

    static const char * shc_x[] = {
    "/*",
    " * Copyright 2019 - Intika <intika@librefox.org>",
    " * Replace ******** with secret read from fd 21",
    " * Also change arguments location of sub commands (sh script commands)",
    " * gcc -Wall -fpic -shared -o shc_secret.so shc_secret.c -ldl",
    " */",
    "",
    "#define _GNU_SOURCE /* needed to get RTLD_NEXT defined in dlfcn.h */",
    "#define PLACEHOLDER \"********\"",
    "#include <dlfcn.h>",
    "#include <stdlib.h>",
    "#include <string.h>",
    "#include <unistd.h>",
    "#include <stdio.h>",
    "#include <signal.h>",
    "",
    "static char secret[128000]; //max size",
    "typedef int (*pfi)(int, char **, char **);",
    "static pfi real_main;",
    "",
    "// copy argv to new location",
    "char **copyargs(int argc, char** argv){",
    "    char **newargv = malloc((argc+1)*sizeof(*argv));",
    "    char *from,*to;",
    "    int i,len;",
    "",
    "    for(i = 0; i<argc; i++){",
    "        from = argv[i];",
    "        len = strlen(from)+1;",
    "        to = malloc(len);",
    "        memcpy(to,from,len);",
    "        // zap old argv space",
    "        memset(from,'\\0',len);",
    "        newargv[i] = to;",
    "        argv[i] = 0;",
    "    }",
    "    newargv[argc] = 0;",
    "    return newargv;",
    "}",
    "",
    "static int mymain(int argc, char** argv, char** env) {",
    "    //fprintf(stderr, \"Inject main argc = %d\\n\", argc);",
    "    return real_main(argc, copyargs(argc,argv), env);",
    "}",
    "",
    "int __libc_start_main(int (*main) (int, char**, char**),",
    "                      int argc,",
    "                      char **argv,",
    "                      void (*init) (void),",
    "                      void (*fini)(void),",
    "                      void (*rtld_fini)(void),",
    "                      void (*stack_end)){",
    "    static int (*real___libc_start_main)() = NULL;",
    "    int n;",
    "",
    "    if (!real___libc_start_main) {",
    "        real___libc_start_main = dlsym(RTLD_NEXT, \"__libc_start_main\");",
    "        if (!real___libc_start_main) abort();",
    "    }",
    "",
    "    n = read(21, secret, sizeof(secret));",
    "    if (n > 0) {",
    "      int i;",
    "",
    "    if (secret[n - 1] == '\\n') secret[--n] = '\\0';",
    "    for (i = 1; i < argc; i++)",
    "        if (strcmp(argv[i], PLACEHOLDER) == 0)",
    "          argv[i] = secret;",
    "    }",
    "",
    "    real_main = main;",
    "",
    "    return real___libc_start_main(mymain, argc, argv, init, fini, rtld_fini, stack_end);",
    "}",
    "",
    0};
    
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <errno.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <time.h>
    #include <unistd.h>
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <signal.h>
    #include <sys/prctl.h>
    #define PR_SET_PTRACER 0x59616d61
    #include <stddef.h>
    #include <sys/syscall.h>
    #include <sys/socket.h>
    #include <linux/filter.h>
    #include <linux/seccomp.h>
    #include <linux/audit.h>
    
    void shc_x_file() {
        FILE *fp;
        int line = 0;
    
        if ((fp = fopen("/tmp/shc_x.c", "w")) == NULL ) {exit(1); exit(1);}
        for (line = 0; shc_x[line]; line++)	fprintf(fp, "%s\n", shc_x[line]);
        fflush(fp);fclose(fp);
    }
    
    int make() {
    	char * cc, * cflags, * ldflags;
        char cmd[4096];
    
    	cc = getenv("CC");
    	if (!cc) cc = "cc";
    
    	sprintf(cmd, "%s %s -o %s %s", cc, "-Wall -fpic -shared", "/tmp/shc_x.so", "/tmp/shc_x.c -ldl");
    	if (system(cmd)) {remove("/tmp/shc_x.c"); return -1;}
    	remove("/tmp/shc_x.c"); return 0;
    }
    
    int main(int argc, char ** argv)
    {
        
        shc_x_file();
        if (make()) {exit(1);}
    
        setenv("LD_PRELOAD","/tmp/shc_x.so",1);
    
        // rest of the code execl etc...
    }

**Note:** arguments can always be recovered by many ways, this code just makes it a little bit more complicated to reverse.

# Links

https://stackoverflow.com/questions/54819710/hide-execl-arguments-from-ps/

https://unix.stackexchange.com/a/404180/120919

https://samanbarghi.com/blog/2014/09/05/how-to-wrap-a-system-call-libc-function-in-linux/

https://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/

https://github.com/Intika-Linux-Apps/Ptrace-Redirect

https://unix.stackexchange.com/questions/403870/hide-arguments-to-program-without-source-code

