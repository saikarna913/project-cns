[Back](atm.md)

bank
====

    bank [-p <port>] [-s <auth-file>]

`bank` is a server than simulates a bank, whose job is to keep track
of the balance of its customers.
 It will receive communications from `atm` clients on the specified
 TCP port. 
 Example interactions with `bank` and the `atm` are given at the bottom
of the [main page](index.md).

On startup, `bank` will generate a auth file with the specified name.
Existing auth files are not valid for new runs of `bank` -- if the
specified file already exists, `bank` should exit with return code
255.
 Once the auth file is written completely, `bank` prints `"created"`
(followed by a newline) to stdout.
 `bank` will not change the auth file once `"created"` has been
printed.

If an invalid command-line option is provided, the bank program should
exit with return value 255.
 
After startup, `bank` will wait to receive transaction requests from
clients; these transactions and how the bank should respond are
described in the `atm` specification.
 After every transaction, `bank` prints a JSON-encoded summary of the
transaction to stdout, followed by a newline (this summary is also
described in the `atm` spec). 
`bank` should bind to any host. 

The `bank` program will run and serve requests until it receives a
SIGTERM signal, at which point it should exit cleanly.
 `bank` will continue running no matter what data its connected
clients might send; i.e., invalid data from a client should not cause
the server to exit and thereby deny access to other clients.

The bank program will not write to any private files to keep state
between multiple runs of the program.

### Options

There are two optional parameters. They can appear in any order.
 Any invocation of the bank that does not follow the command-line
specification outlined above should result only with the return code of 255
from the bank. I.e., invocations with duplicated or non-specified parameters are
 considered an error.

- `-p <port>` The port that `bank` should listen on.
 The default is `3000`.

- `-s <auth-file>` The name of the auth file.
 If not supplied, defaults to "`bank.auth`".
