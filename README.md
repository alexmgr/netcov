Netcov purpose is to perform tracing of network daemons at runtime to collect 
code coverage information.

#How to build:
* `git clone git@secrepo.eng.citrite.net:alexmon/netcov.git`
* `PIN_ROOT=~/src/pin-2.14-71313-clang.5.1-mac/ make`

#How to run:
* `PIN_ROOT=~/src/pin-2.14-71313-clang.5.1-mac/ ~/src/pin-2.14-71313-clang.5.1-mac/pin.sh -t obj-intel64/netcallgraph.dylib -- target_binary`
* `netcallgraph` will create a named pipe on which it will write information in
the following format: `syscall_name:fd:trace\n`

#Useful options:
* `-m` allows to whitelist modules for which to collect runtime information. It
is recommended to use it

#Example run:

`tcp` is a dummy tcp server with nested branches:
```
if (read(conn_desc, buff, sizeof(buff) - 1) > 0) {                                                                 
    printf("Received %s\n", buff);                                                                                 
    if (buff[0] == 'A') {                                                                                          
        printf("Took first branch\n");                                                                             
        if (buff[1] == 'B') {                                                                                      
            printf("Took second branch\n");                                                                        
            if (buff[2] == 'C') {                                                                                  
                printf("Took third branch\n");                                                                     
                if (strncmp(buff + 3, "1234567890", 10) == 0) {                                                    
                    printf("Good job!\n");                                                                         
                    write(conn_desc, "Good job!", 10);                                                             
                }                                                                                                  
            }                                                                                                      
        }                                                                                                          
    } 
```

Run `netcallgraph` against it to collect callgraph traces (collect only edges
belonging to the `tcp` module):
`PIN_ROOT=~/src/pin-2.14-71313-clang.5.1-mac/ ~/src/pin-2.14-71313-clang.5.1-mac/pin.sh -t obj-intel64/netcallgraph.dylib -m tcp -- ~/stash/tcp`

Opening named pipe /tmp/netcallgraph. Halting until other end opened for read


In another shell, read from `/tmp/netcallgraph` fifo and watch the trace change when sending packets to the dummy server:

`cat /tmp/netcallgraph`

`echo stuff | nc localhost 1234`

close:6=libsystem_kernel.dylib+99604->tcp+3266;tcp+3266->tcp+3278;tcp+3278->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3296;tcp+3296->tcp+3540;

`echo A | nc localhost 1234`

close:6=libsystem_kernel.dylib+99604->tcp+3266;tcp+3266->tcp+3278;tcp+3278->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3296;tcp+3296->tcp+3318;tcp+3318->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3332;tcp+3332->tcp+3540;

`echo otherstuff | nc localhost 1234`

close:6=libsystem_kernel.dylib+99604->tcp+3266;tcp+3266->tcp+3278;tcp+3278->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3296;tcp+3296->tcp+3540;

`echo AB | nc localhost 1234`

close:6=libsystem_kernel.dylib+99604->tcp+3266;tcp+3266->tcp+3278;tcp+3278->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3296;tcp+3296->tcp+3318;tcp+3318->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3332;tcp+3332->tcp+3354;tcp+3354->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3368;tcp+3368->tcp+3540;

`echo ABC | nc localhost 1234`

close:6=libsystem_kernel.dylib+99604->tcp+3266;tcp+3266->tcp+3278;tcp+3278->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3296;tcp+3296->tcp+3318;tcp+3318->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3332;tcp+3332->tcp+3354;tcp+3354->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3368;tcp+3368->tcp+3390;tcp+3390->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3404;tcp+3404->libsystem_platform.dylib+4640;libsystem_platform.dylib+4989->tcp+3440;tcp+3440->tcp+3540;

`echo ABC1234567890 | nc localhost 1234`
Good job!% 
write:6=libsystem_kernel.dylib+99604->tcp+3266;tcp+3266->tcp+3278;tcp+3278->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3296;tcp+3296->tcp+3318;tcp+3318->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3332;tcp+3332->tcp+3354;tcp+3354->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3368;tcp+3368->tcp+3390;tcp+3390->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3404;tcp+3404->libsystem_platform.dylib+4640;libsystem_platform.dylib+4989->tcp+3440;tcp+3440->tcp+3451;tcp+3451->libsystem_c.dylib+273904;libsystem_c.dylib+274110->tcp+3465;
close:6=