# Security Guard at IITGN

Overview
--------

In this project, you will implement a *secure log* to describe the *state
of an institute*: the guests and employees who have entered and left,
and persons that are in campus in different buildings or rooms. The log will be used by *two
programs*. One program, `logappend`, will append new information to this file,
and the other, `logread`, will read from the file and display the state of the institute according to a given query over the log.  Both programs will
use an authentication token, supplied as a command-line argument, to
authenticate each other. Specifications for these two programs and the security model are described in more
detail below.

Deliverables
------------
You should submit:  

+ Your implementation, including all your code files and your makefile. Even though we will have access to your git repo (details below), you will submit a "final" version by creating a tag on it.
+ A **design document** (PDF) in which you describe your overall system design in sufficient detail for a reader to understand your approach without reading the source code directly. This must include a description of the format of your log file. 

Programs
--------
Your team will design a log format and implement both `logappend` and
`logread` to use it. Each program's description is linked below.

 * The [`logappend`](LOGAPPEND.html) program appends data to a log 
 * The [`logread`](LOGREAD.html) program reads and queries data from the log 

`logread` contains a number of features that are optional. If you do not implement an optional feature, be sure to **print `unimplemented` to standard output**. 

Look at the page of [examples](EXAMPLES.html) for examples of using the `logappend` and `logread` tools together. 

Security Model
--------------
The system as a whole must guarantee the privacy and integrity of the log in
the presence of an adversary that does not know the authentication token. This token
is used by both the `logappend` and `logread` tools, specified on the command
line. *Without knowledge of the token* an attacker should *not* be able to:

* Query the logs via `logread` or otherwise learn facts
  about the names of guests, employees, room numbers, or times by
  inspecting the log itself
* Modify the log via `logappend`. 
* Fool `logread` or `logappend` into accepting a bogus file. In
  particular, modifications made to the log by means other than correct use of `logappend` should be detected by (subsequent calls to) `logread` or `logappend` when the correct token is supplied

Build Phase
-----------
Each team should initialize a git repository on [github](https://github.com/) and share it with us. 
**You MUST NOT make your repository public; doing so will be treated as a violation of honor code.**

Create a directory named `build` in the top-level directory of your repository and commit your code into that 
folder. 

To score a submission, we will invoke `make` in the `build`
directory of your submission. The only requirement on `make` are that it 
must function without internet connectivity, it must return within a few minutes, 
and it must build from source (committing binaries only is not acceptable). 

Once make finishes, `logread` and `logappend` should be executable 
files within the `build` directory. An automated system will invoke them with a 
variety of options and measure their responses. 
**The executables must be able to be run from any working directory.** 

