---
layout: project
title:  "Project 1I: Basic Stack Smashing and Assembly"
date:   2018-1-23
due: 2018-2-9
categories: project assignment
permalink: /project/1
---

This is a snapshot of the assignment from 2018-1-22. The course
webpage is the **will likely change**. Refer to the course webpage for
updated project specs.

**Caution!** This code will be graded on the virtual machine for the
course. Magic constants, like the position of the stack, are
**absolutely not** portable across machines. Therefore, do your
exploit-generation on the virtual machine for the course. **No**
partial-credit will be given for solutions that work on your machine
but not mine.

In this project you'll perform a set of basic exploits against a file
server. The file server we build in this project will store files for
the chat server we eventually build. For this project, you'll mostly
be concerned with merely using and exploiting the server, you
shouldn't have to write large amounts of C code.

This portion of the project is individual work. During the course of
this project you are allowed access to all online resources, but you
are required to cite any resource that gave you any significant
insight into the project, including conversations you had with your
classmates. You will put these sources in `SOURCES.md` within this
folder.

Please respect the department's collaboration policy. Specifically,
you are not allowed to look at any other student's *code* (or do
anything equivalent, such as talking through your code on a
line-by-line basis). You may discuss pseudo-code on the board, but
afterwards you must erase it (so as to not let anyone else see it) and
then cite your conversation with the other person in a comment in your
code (and in the sources file).

**If you get stuck, look at the hints / advice at the bottom of this
guide.**

# Project Overview

The goal of this project is to teach you the following:
- A refresher on C / assembly
- An introduction to web protocols
- Interacting with a server manually via `telnet`
- Writing socket-based programs in Python
- Use GDB and other debuggers to understand program code

You should first obtain the starter files for this project, perform a
`git clone` of this project's repository:

    git clone github.com/security-course/file-server

The file server is contained in a file `server.c`

# Collaboration Policy

Specific examples that extend the collaboration policy for this lab:

- It is okay to work through concepts on the board, but you **may
  not** give away **any** concrete addresses from the program (since
  finding these is part of the lab). Instead, use placeholder
  addresses when doing calculations with another student. E.g., you
  might say "Well, we realized that if the buffer is Y in length, and
  our shellcode is Z bytes long, we needed to insert X = Y-Z bytes of
  empty space after the shellcode"

- Please discuss the tools you used with other students. For example,
  you may say "I used GDB's `layout asm` to show the current
  instruction as I injected the shellcode."

- You may **not** look at another student's screen or talk to someone
  at such a low level as to be looking at their screen in spirit.

# Structure of the Server and `telnet` Tutorial

This assignment will have you launch an attack against a small server,
which can serve--among other things--HTML and image files. The server
is implemented in the file `server.c`.

This server is woefully incomplete: it only implements a very tiny
part of the HTTP--the exchange-format used between web-browsers and
servers. And yet this server still implements enough of HTTP to be
able to display static content.

The word "server" is used all over the place in tech. For this
assignment, a "server" means an application that can exchange data
with a user on the other end of a communication channel (frequently
called a "port"). You don't need to understand networking to do this
project, and you can largely follow this tutorial to complete the
assignment.

Begin by building the server:

    make fs

This command builds the version of the server with all of the fancy
modern protection mechanisms enabled, so it won't be susceptible to
(as many of) the attacks we'll launch in this assignment.

To run the server, type the following:

    ./fs "secret" "hello my message is here"

The server takes two arguments: the secret password, and a secret
message. The server shouldn't reveal this message to the user unless
they send a command to the server to authenticate with the password
(set on the command line here as `secret`).

Now the server should be running on port 5000. This means that it's
listening for connections. To talk to the server, you can use the
`telnet` program. To do this:

    telnet localhost 5000

The first command-line argument is the server to connect to. This
could be a remote host, like cnn.com, but in this case it's going to
be a special host named `localhost`, which is an alias for the IP
address `127.0.0.1`. This is like talking to a remote machine, across
the internet, except instead of talking to cnn.com, you're talking to
a server running your local machine.

Once we're connected, we can start sending the server commands:

    hello
    Hello!

When we type in "hello", the server replies back with "Hello!." The
complete list of commands is documented below.

This server also supports a form of HTTP, which is a standard format
(protocol) used to exchange data between your web browser and the
server itself. Think of the web browser as doing this same stuff that
you're typing into `telnet` in a specific way, except that it's doing
it using a program. To see this, open a web browser (inside of the VM,
using the user interface) and point the address address bar at
`localhost:5000`. Like navigating to `cnn.com`, the server sends the
necessary commands to our server application to retrieve the page. You
should be able to see the server application generating some logs as
it does this, so you can see which files get requested.

You can generate this yourself, after you telnet to the address, type
in the following:

Here's the complete list of commands:

- `hello`, replies back with `Hello!`
- `goodbye`, terminates the connection
- `echo <text>`, replies back with "Server is echoing: " followed by <text>
- `setmsg <msg>`, sets a global variable in the server named `special_message`
- `getmsg`, gets the special message set with `setmsg`
- `authenticate <tried_password>`, authenticates the connection to
  with a password when `<tried_password>` matches the password set via
  command-line argument. Once the connection has been authenticated,
  it will reveal the "secret message", which is also specified on the
  command line.
- `getsecret`, gets the secret, assuming the connection has been
  authenticated
- `shell`, starts a shell *on the server*, that can be typed into via
  the telnet connection (i.e., when you type into it, it's actually a
  shell on the server).
- `get <URI> <http-version>` GETs a resource using the HTTP protocol.

Here's an example 

```
authenticate secret
You are now authenticated
getsecret
hello my message is here
echo Hi, my name is Charles!
Server is echoing: Hi, my name is Charles!
getmsg
Here is a special message
shell
```

## More resources

I expect you to be able to pick up and read through `server.c` on your
own, and this is specifically part of the project. A large part of
security (and software-engineering at large) is figuring out other
people's code. So work through it, and when you get stuck, play around
with `telnet`. When you get confused, insert `logmsg` or `printf`
statements, or (better yet) walk through it in the debugger.

### Notes on Safety, Ethics, and "Realness"

This server is written to be extremely insecure, and contains even
more vulnerabilities than I discuss in this assignment. Running an
insecure server is an easy way to get hacked, so system administrators
typically use a
[firewall](https://en.wikipedia.org/wiki/Firewall_(computing)) to keep
you from opening up servers on random ports and putting them out on
the internet. For example, we have a firewall at Haverford that stops
the server under my desk from sending talking to the rest of the
internet.

Finally, this part of the project is fairly unrealistic. I have added
a ton of extra commands to the server to make it easier for you to
understand and exploit. Exploiting a real web server would mean
reading lots and lots of code to try to find a mistake. We will likely
do that later in the course, but for now try not to worry too much
about it. I've included the "GET" command in here to foreshadow the
next part of the assignment: the group project involves
collaboratively fleshing out the rest of this server and performing
some attacks on it.

### Part 0: Writing in C / Assembly, and using GDB

For this part of the project, you will write a function in C that
finds the maximum value in a list.

The signature for the function:

    // Max gives the max of `num_ints`
    int max(int *ints, int num_ints);

#### Task 0a: Coding in C and Understanding Assembly

Write and test this function (and *only* this function, no `main`
function)in a file named `max.c`. Then compile the function into
assembly-language form using the following command:

    gcc -S max.c 

The result will be a file, `max.s`, which contains the
assembly-language code for the project.

**Deliverable**: the file `max.s`, with comments.

Comment the code with enough detail so that I can follow it along. For
example, detail what each operation means, talks about where items
will be laid out on the stack, what purpose each register serves,
etc..

Then answer the following questions in this document (right here in
the README):

**Deliverable** the questions here

Q1. Where is each of the arguments `ints` and `num_ints` passed (i.e.,
in which register, on the stack, etc..)

Q2. Describe in words or as an ASCII-art diagram, the stack layout at
    the invocation of the function `max`

Q3. Where is each local variable stored in the function, specifically
in relation to the base pointer?

#### Task 0b: Using GDB

I have included a program, `max_main.c`, which will use your `max.s`
file. To compile `max_main.c` in a way such that it can use your
`max.s` code, first compile `max.s` from assembly to binary code:

    gcc -c max.s

The `-c` tells gcc to *compile* the file to binary code, but not to
*link* it. Linking is the process by which the compiler grabs up all
of the different functions, including the `main` function, and splices
them all together into a binary that you can actually run. But since
`max.s` doesn't *have* a main function, `gcc` can't fully link it. Now
you have a binary file `max.o`, which you can link with the `main`
function in `max_main.c`. The following command compiles `max_main.c`
and links it with `max.o`:

    gcc max.o max_main.c -o max

The output is now a file you can run named max.

Read GDB's documentation on the following commands: 

TODO

### Part 1: Crash the Server

Consider the `handle_connection` function inside of of the `server`
executable. The local variables for `handle_connection` will be laid
out on the stack in order. The variable `string` is a fixed-length
buffer, into which (because of the way the program is written) you can
write more than 100 bytes. This opens up the possibility for a
stack-smashing attack.

When you get done, it should look like this:

```
Got a connection on port 5000, handling now.
ffffe3a0
Received some data!
echo <more stuff here>
Segmentation fault (core dumped)
```

### Task 1a: Drawing the Stack

_Deliverable_: Draw `handler_connection`'s stack right after the line
that checks `prefix("hello",buffer)`. You can do this on a piece of
paper or in digitized form. Whatever you do, digitize it (either by
taking a picture with your phone, scanner, etc..) and submit it as
`stack-inside-echo.<png/jpg>`. I highly suggest you reconstruct this
using GDB.

Your image **must include** all of the relevant local variables for
`handle_connection` at that point, and must show (at least) the
position of the saved instruction pointer `%rip`.

_Bonus points_: You will get +1 bonus points if you can generate
this image using `gdb`. However, you must make gdb print out enough of
the stack to show the saved base pointer and return address.

#### Hints on this part

Consider using the following GDB commands:

- `info frame`
- `info locals`
- `print <address-in-hex>`
- `print $rsp` / etc.. (for registers)
- `x/20xb <address>` / `x/20xb $rsp` / etc.. 
  - This says print the next 20 bytes starting at `<address>`, print
    them in hex (that's what the `x` after 20 means), print them one
    byte at a time (that's what the `b` means).

**Remember the stack grows down!**

### Task 1b: Smashing the Stack

This program is insecure because it has a stupidly-obvious buffer
overflow attack: the variable `string` in `handle_connection` is a
buffer of size 100, but inputs of up to 1024 can be read into the
larger (global) `buffer` variable. Figure out an input that could be
sent to the server that would cause the return instruction pointer to
be overwritten, so that--upon returning from `handle_connection`, the
program would go to a nonsense location and the program would
crash. (FYI: the reason why it would crash is that control flow would
wander into an unmapped page, generating a segmentation fault.)

Once you figure it out, run the server with the following parameters:

    ./server mypassword message

And then in another terminal telnet into the server to perform your
attack.

There's one trickery here: after sending the `echo` command, the
server will keep accepting input. Part of the assignment is to figure
out how to handle that (it's not hard once you step back and look at
all of the available commands).

Attach the output of the server here (showing that it crashes):

**Deliverable**: Copy and paste server output into 1b_server.txt

**Deliverable**: Copy and paste telnet input / output into 1b_telnet.txt

### Part 2: Scripting the Attack

Attacks can be complicated. You don't want to have to literally sit and
type your exploit into telnet. Especially as your attack gets more and
more complicated. Instead, you'd like to use a higher-level language
to script the attack. What's more, sometimes we will need to generate
binary data that's not easy to type out in ASCII. Python will let us
construct those payloads programmatically. For this and the next
project, we're going to write these scripts ourselves.

I've included a simple script, `client.py`.

Script your attack in the function `crash_server`. You might think to
use the following Python socket functions:

- [`send`](https://docs.python.org/3/library/socket.html#socket.socket.send)
- [`recv`](https://docs.python.org/3/library/socket.html#socket.socket.recv)

Among the others listed there. I encourage you to read a good amount
of that page. For example, you could write `s.send("echo hello")` to
send "echo hello" to the server. Note that the Python API takes care
of some of the ceremony of doing things like writing the length.

**Deliverable**: the Python function `crash_server` inside
`client.py`, which crashes the server.

#### Hints on this part

One common scenario when writing exploit payloads is that we find
ourselves writing some number of uninteresting bytes followed by
(e.g.,) an address that you'd like to smash into `%rip`. This is
because--to exploit a buffer overflow--we have to fill up the whole
buffer. In these scenarios, it's common to use a script to construct
the payload. For example, you could write a script in Python to insert
25 `A`s before the ultimate bytes `0x23, 0x42 0x43 0x22` (which might
be the address you want to inject, etc..).

- `send` expects a byte string as argument. To turn a Python string
  into an array of bytes, use the following: `"echo ".encode()`.

- If you want to represent a *single* byte, use b'\x23', which
  represents the single byte containing the hex value 0x23.

- For example, if you wanted to write the string containing the bytes
  0x23, 0x24, 0x57, and 0x42, in that order, you could write
  b'\x2e\x24\x57\x42'

- You will probably want to want combine the string "echo " with a
  sequence of bytes. To do this, you can simply add them together
  (since Python's add is overloaded): "echo ".encode() + b'\x41' * 23
  generates the ASCII for "echo " (note the space), followed by the
  letter 'A' (ASCII-encoded) 23 times.

### Part 3: Owning Control Flow

Craft an exploit that will force the program to print out "Hello,
world!\n". To do this, follow the same technique you did in parts 1
and 2, but instead of making `%rip` become some nonsense value, make
it the address of the function `hello_world`. That way, when the
program returns from `handle_connection`, it will then go to
`hello_world` instead.

_Deliverable_: write your exploit inside of the Python function
`hello_world`.

Notes:

- It is **totally okay** if the server crashes after printing "Hello,
  world!"

When you get done, the server should do something like this:

```
Hello, world!
Illegal instruction (core dumped)
```

#### Hints on this part

Use GDB to manually figure out how to redirect control flow at
first. This helps you get a feel for where things should be in memory,
and you can draw them out on a whiteboard or on paper as you use
GDB. It also helps you debug your exploit as you develop it.

For example, here's one run of the program where I tell GDB to show me
what the contents of memory are around the current stack pointer
(which I got via `info register esp`).

The first thing I do is to ask where the current saved RIP is stored:

```
(gdb) info frame
Stack level 0, frame at 0x7fff5fbff4e0:
 rip = 0x100000e04 in foo; saved rip = 0x1500e0000
 called by frame at 0x7fff5fbff4e8
 Arglist at 0x7fff5fbff4d0, args:
 Locals at 0x7fff5fbff4d0, Previous frame's sp is 0x7fff5fbff4e0
 Saved registers:
  rbp at 0x7fff5fbff4d0, rip at 0x7fff5fbff4d8
```

It tells us that the saved RIP is at `0x1500e0000`. This is the
address we want to overwrite. Let's find out where `helloWorld` is
located:

```
(gdb) info address hello_world
Symbol "hello_world" is at 0x100000e50 in a file compiled without debugging.
```

So we need to set the RIP to point to that address:

```
(gdb) set *(0x7fff5fbff4d8) = 0x100000e50
```

Now, let's check that I got it right (I didn't the first few times I
did this..):

```
(gdb) info frame
Stack level 0, frame at 0x7fff5fbff4e0:
 rip = 0x100000e04 in foo; saved rip = 0x100000e50
 called by frame at 0x7fff5fbff510
 Arglist at 0x7fff5fbff4d0, args:
 Locals at 0x7fff5fbff4d0, Previous frame's sp is 0x7fff5fbff4e0
 Saved registers:
  rbp at 0x7fff5fbff4d0, rip at 0x7fff5fbff4d8
(gdb) info address helloWorld
Symbol "helloWorld" is at 0x100000e50 in a file compiled without debugging.
```

Finally, let's run it:

```
(gdb) continue
Continuing.
Successfully copied the input!
Hello, world!
<Segfault>
```

Now, your job is to create a payload that does this!

**Caution!**

- Remember, you're on a little-endian machine. So if I give you the
number 0xDEADBEEFDEADBEEF, it will be represented as
0xEFBEADDEFEBEADDE.

- The stack grows **down**!

### Part 4: Executing Shellcode

Now you can control control-flow. Great. But say you want to run your
*own* code. To do this, you need to inject some assembly code into
your program, and then have `%rip` jump to the shellcode.

Your task in this part is to inject the shellcode into the program
(via the buffer overflow) and then jump to it. I have included a
sample shellcode in the file `shellcode.c` (its assembly is given,
too).

For this part, do something like this:

echo ... a: shellcode here ... smashed-rip-address

Think about where the shellcode will be placed in memory (using GDB if
you need), and make `%rip` navigate to that point in memory, thereby
executing the shell.

_Deliverable_: write your shellcode injection in the Python function
`inject_execute_shellcode`

#### Tip on This Part

You're going to want to place your shellcode somewhere inside the
buffer, and then smash the stack so that control flows back to
wherever you placed that shellcode. Therefore, you need to figure out
the position of the `string` variable. You can do this by attaching
GDB to a running process: start up the server in one console window,
and then in another type `ps -a | grep fs_nsp_nnx`. Look at the number
in the first column. Then do `sudo gdp -p <number>` (enter `testvm`
for the password). This will let you debug the server as it runs. You
can then set a breakpoint inside of `handle_connection` and print out
the location of the variable `string`.

### Part 5: Leak the Secret from the Server (w/o auth)

The server implements some code to check that the user types in a
proper `authenticate` command before allowing the secret message to be
retrieved. E.g., if I simply telnet into the server and then type in
`getsecret` I get the message: "You are not authenticated right now,
first use the `authenticate` command."

Your job in this part is to figure out how to get the server to give
me the secret message without typing in the password.

**Note:** You may **not** discuss this part of the project with your
classmates (even at a high-level). Your job in this part is to hunt
through the program, using it's logic, to figure out how you could
exploit it.

**Deliverable**: the function `print_secret`, which prints the
password from the server.

### Part 6: Protecting Against the Attacks

The reason we were able to launch all of these attacks is due to the
buffer overflow exploit in `handle_connection`. Modify `server.c` so
that this attack goes away.

_Deliverable_: the file `server_fixed.c`, which is not susceptible to
the same attacks given in parts 2 through 5.

### **Challenge Problem**: Reverse Engineering (**)

This problem is worth +3% bonus.

I have included a program, `challenge.o`, in binary-only form. Your
job is to figure out how to run it in a way that causes it to print
out "Hello, world!\n". The program has been compiled without stack
protection and will be run with ASLR disabled. You must show me the
command-line arguments I can use to get it to work. But you must
*also* show your work and tell me how you got there. Solutions that
technically work but aren't explained will receive no credit.

This challenge problem is 2/3 stars, meaning it's quite difficult, but
not impossible. The task itself isn't really any different than what
you've done in this assignment. The main challenge is that you don't
have the code.

**Hint**: Use the debugger for interactive disassembly of this
program. This will also help you figure out what address to
target. Use a disassembler or reverse engineering toolkit.

**Deliverable**: `bonus.txt`, which describes the techniques and shows
how to run the program to get it to print "Hello, world!"

### **Challenge Problem**: Shellcoding (**)

This problem is worth +2% bonus. I have included a script, `./myscr`,
in this directory. Figure out how to modify the shellcode so that
instead of executing `/bin/sh`, it executes `./myscr`

**Hint**: Look carefully at the disassembly and think about what the
shellcode is doing.

**Deliverable**: A function `inject_bonus_shellcode`.

### **Challenge problem**: Other Bugs and Exploits (*)

Find any other bugs in this program that could lead to a security
vulnerability: information-disclosure, denial-of-service,
code-injection, etc.. This program has a good number of them.

You can receive a maximum of 2% extra credit on this part. .5% for each
vulnerability. However, I am the final arbiter of what constitutes a
security vulnerability versus just a bug (that isn't a vulnerability)
and my decisions are final.

**Deliverable**: `other_bugs.txt`, which describes any other bugs you
find.

## Deliverables

_Note_: Deliverables will be accepted in no other format than those
listed here. Specifically: if you write code that technically works,
but does not fit the format the testing scripts expect, you will not
receive points. Also note that *no partial credit* will be assigned
throughout the course as a matter of policy, unless otherwise noted
explicitly.

Part 0: Writing in C / Assembly, and using GDB
- [ ]/5 max.s, with comments
- [ ]/5 TODO

Part 1: Crash the server
- [ ]/5 stack-inside-echo.<png/jpg>
- [ ]/5 1b_server_output.txt and 1b_telnet.txt

Part 2: Scripting the attack
- [ ]/10 the function `crash_server`

Part 3: Owning control flow
- [ ]/10 the function `hello_world`

Part 4: Executing shellcode
- [ ]/10 the function `inject_execute_shellcode`

Part 5: Leak the secret from the server
- [ ]/10 the function `leak_secret`

Part 6: Protecting against the attacks
- [ ]/10 the file `server_fixed.c`, which is not susceptible to the
  attacks in parts 2-5.

Total: [ ]/60

Bonus parts:
- [ ]/+3% Reverse engineering
- [ ]/+2% Shellcoding
- [ ]/+2% Other bugs and exploits you found in the server

## Constraints and Advice (**Read This if you Get Confused**)

The solution to this project doesn't involve very much code. But it's
still tricky. You have to carefully think about the location of
variables as they get placed in the stack, heap, etc.. As you work
through this project, it's *crucial* to understand the layout of the
program (stack, heap, instructions, etc..). When I wrote out the
solutions to this project, I did so using both my whiteboard and GDB
(attached to the process).

- The program will not work when environment variables change, or if
  command-line arguments are passed in. I will not change the
  environment variables when running your program, and will not pass
  in any additional command-line arguments. We will see how to deal
  with this in subsequent lectures.

- Do **not** modify `server.c`, you risk addresses of functions being
  different. For part six, make a *copy* (as stated in that part).

- When trying to determine the locations of variables, be sure that
  you connect GDB to a *running process*. If you run the app under
  GDB, the location of the stack will be different because environment
  variable differences between GDB and the running process. See this
  page for details:
  http://www.mathyvanhoef.com/2012/11/common-pitfalls-when-writing-exploits.html

- http://dirac.org/linux/gdb/06-Debugging_A_Running_Process.php

- Use the program `objdump`, which will help you disassemble the
  file. For example, if you run `objdump -S fs_nsp_nnx >out`, you can
  then open up the file `out` and find out where `handle_connection`
  is written to examine its source.

- (Hex to decimal calculator, useful for calculating ranges of things)
  https://www.rapidtables.com/convert/number/hex-to-decimal.html?x=78

- (How to modify memory using GDB)
  https://stackoverflow.com/questions/3305164/how-to-modify-memory-contents-using-gdb

- (How to print memory using GDB)
  https://sourceware.org/gdb/onlinedocs/gdb/Memory.html


