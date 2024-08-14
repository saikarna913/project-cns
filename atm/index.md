Programming Problem: ATM Protocol
=================================

Summary
-------

Students will implement an ATM communication protocol.
 There will be two programs.
 One program, called `atm`, will allow bank customers to withdraw and
deposit money from their account.
 The other program, called `bank`, will run as a server that keeps
track of customer balances.

Security Model
--------------

`atm` and `bank` must be implemented such that only a customer with a
correct _card file_ can learn or modify the balance of their account,
and only in an appropriate way (e.g., they may not withdraw more money
than they have).
 In addition, an `atm` may only communicate with a `bank` if it and
the bank agree on an _auth file_, which they use to mutually
authenticate. 
The _auth file_ will be shared between the `bank` and `atm` via a 
trusted channel unavailable to the attacker, and is used to set up
secure communications.

Since the ATM client is communicating with the bank server over the
network, it is possible that there is a "man in the middle" that can
observe and change the messages, or insert new messages.
 A "man in the middle" attacker can view all traffic transmitted 
between the `atm` and the `bank`. 
The "man in the middle" may send messages to either the atm
or the bank. 

The source code for `atm` and `bank` will be available to attackers,
but not the auth file. The card file may be available in some cases,
depending on the kind of attack.

Requirements
--------

The specification details for each program are linked below.

- [Bank Server](bank.md)
- [ATM Client](atm.md)

Here are some general requirements that apply to both `atm` and `bank`
programs.

### Valid Inputs

Any command-line input that is not valid according to the rules below
should result with a return value of 255 from the invoked program and
nothing should be output to ***stdout*** .

- Command line arguments must be [POSIX
  compliant](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html)
  and each argument cannot exceed 4096 characters (with additional
  restrictions below).
  In particular, this allows command arguments specified
  as "-i 4000" to be provided without the space as "-i4000" or with
  extra spaces as in "-i &nbsp;&nbsp;&nbsp; 4000".
  Arguments may appear in any order. You should not implement `--`, 
  which is optional for POSIX compliance. You should implement guideline
  5 (ex. `atm -ga ray` is valid).

- Numeric inputs are positive and provided in decimal without any
 leading 0's (should match __/(0|[1-9][0-9]*)/__).
 Thus "42" is a valid input number but the octal "052" or hexadecimal
  "0x2a" are not.
 Any reference to "**number**" below refers to this input specification.
  
- Balances and currency amounts are specified as a **number** indicating a
  whole amount and a fractional input separated by a period.
  The fractional input is in decimal and is always two digits and thus
  *can include a leading 0* (should match **/[0-9]{2}/**).
 The interpretation of the fractional amount *v* is that of having
  value equal to *v*/100 of a whole amount (akin to cents and dollars
  in US currency). 
  Command line input amounts are bounded from 0.00 to 4294967295.99 inclusively but an account may accrue any non-negative balance over multiple transactions.
<!---  The whole part should be representable as a 32-bit unsigned integer
  (0 though 4,294,967,295).--->

<!---
- Command-line integer inputs are non-negative, should be storable in
  an unsigned 32 bit integer, and may have leading zeros [pm: this is
  bad as a leading zero usually means octal, can we get rid of this
  possibility?]. The length of an integer on the command line is
  between 1 and 4096 characters. **/[0-9]{1,4096}/**
  --->
  
- File names are restricted to underscores, hyphens, dots, digits,
  and lowercase alphabetical characters (each character should match
  **/[_\\-\\.0-9a-z]/**).
  File names are to be between 1 and 127 characters long. The special
  file names "." and ".." are not allowed.
  
- Account names are restricted to same characters as file names but
  they are inclusively between 1 and 122 characters of length, and "." and ".." are
  valid account names. 

- IP addresses are restricted to IPv4 32-bit addresses and are
  provided on the command line in dotted decimal notation, i.e., four
  **numbers** between 0 and 255 separated by periods.

- Ports are specified as **numbers** between 1024 and 65535
  inclusively.

### Outputs

- Anything printed to **stderr** will be ignored (e.g., so detailed error
  messages could be printed there, if desired).
  
- All JSON output is printed on a single line and is followed by a
  newline.

- JSON outputs must show numbers (including potentially unbounded account balances) with full precision. 

- Newlines are '\n' -- the ASCII character with code decimal 10.

- Both programs should **explicitly flush stdout** after every line
  printed.

- Successful exits should return exit code 0.

### Errors

#### Protocol Error
  
- If an error is detected in the protocol's communication, `atm`
  should exit with return code `63`, while `bank` should print
  "`protocol_error`" to stdout (followed by a newline) and roll back
  (i.e., undo any changes made by) the current transaction.

- A timeout occurs if the other program does not respond within 10
  seconds.
  If the atm observes the timeout, it should exit with return code
  `63`, while if the bank observes it, it should print
  "`protocol_error`" to stdout (followed by a newline) and rollback
  the current transaction.
  The non-observing party need not do anything in particular.

- If `atm` cannot connect to the bank, it should exit with return code `63`.

#### Other Errors

- All other errors, specified throughout this document or
  unrecoverable errors not explicitly discussed, should prompt the
  program to exit with return code `255`.
  
Changes and Updates
-------

There will inevitably be changes to the specification 
during the semester as unclear assumptions and mistakes
on our part are uncovered. We apologize in advance!

All changes will be summarized at the top of this page. 

Build-it Round Submission
-------------------------

Each build-it team should
initialize a git repository on [github](https://github.com/) and share it 
with us. Create a directory 
named `build` in the top-level directory of this repository and commit your code into that folder. 
(Beware making your repository public, or others might be able to see it!)

To score a submission, we will first invoke `make` in the `build`
directory of your submission. The only requirement on `make` is that it 
must function without internet connectivity, and that it must return within 
a few minutes. Moreover, it must be the case that your software is
actually built, through initiation of make, from source (not including
libraries you might use). Submitting binaries (only) is not acceptable.

Once make finishes, `atm` and `bank` should be executable 
files within the `build` directory. We will invoke them with a 
variety of options and measure their responses. 
The executables must be able to be run from any working directory. 
If your executables are bash scripts, you may find the following [resource](http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in) helpful. 

Examples
--------

Here is an example of how to use `atm` and `bank`. 
First, do some setup and run `bank`.

	$ mkdir bankdir; mv bank bankdir/; cd bankdir/; ./bank -s bank.auth &; cd ..
	created

Now set up the atm. 

	$ mkdir atmdir; cp bankdir/bank.auth atmdir/; mv atm atmdir/; cd atmdir

Create an account 'bob' with balance Rs. 1000.00 (There are two outputs because one is from the `bank` which is running in the same shell).

	$ ./atm -s bank.auth -c bob.card -a bob -n 1000.00
	{"account":"bob","initial_balance":1000}
	{"account":"bob","initial_balance":1000}

Deposit Rs. 100.

	$ ./atm -c bob.card -a bob -d 100.00
	{"account":"bob","deposit":100}
	{"account":"bob","deposit":100}

Withdraw Rs. 63.10.

	$ ./atm -c bob.card -a bob -w 63.10
	{"account":"bob","withdraw":63.1}
	{"account":"bob","withdraw":63.1}

Attempt to withdraw Rs. 2000, which fails since 'bob' does not have a sufficient balance.

	$ ./atm -c bob.card -a bob -w 2000.00
	$ echo $?
	255

Attempt to create another account 'bob', which fails since the account 'bob' already exists.

	$ ./atm -a bob -n 2000.00
	$ echo $?
	255

Create an account 'alice' with balance Rs. 1500.

	$ ./atm -a alice -n 1500.00
	{"account":"alice","initial_balance":1500}
	{"account":"alice","initial_balance":1500}

Bob attempts to access alice's balance with his card, which fails.

	$ ./atm -a alice -c bob.card -g
	$ echo $?
	255

### A note on concurrent transactions 

In principle, the bank could accept transaction requests from multiple ATMs concurrently, if it chose to---there is no requirement that it must. 
If it does, the order that these transactions take effect is non-deterministic, but atomic. 
For example, if ATM #1 requested a deposit of Rs. 50 to Bob's account and ATM #2 requested a withdrawal of Rs. 25 from Bob's account, those two requests could take effect in either order, but when they complete Bob should always be Rs. 25 richer. 
Note that an atomic transaction includes both changes/accesses to the balance and the corresponding I/O. 
As such, the order of any printed statements about events must match the order the events actually took place.

Tests are sequences of synchronous ATM commands. During the break-it round, tests also involve a "man in the middle" (MITM) which could introduce concurrency (see the description of the attacker model), but the MITM will never have direct access to the card file or auth file, so its ability to initiate concurrent transactions is more limited than the ATM.
