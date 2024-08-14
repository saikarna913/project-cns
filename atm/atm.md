[Back](index.md)

atm
===

    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -n <balance>
    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -d <amount>
    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -w <amount>
    atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -g

`atm` is a client program that simulates an ATM by providing a
mechanism for customers to interact with their bank accounts stored on
the `bank` server.
 `atm` allows customers to create new accounts, deposit money,
withdraw funds, and check their balances. In all cases, these
functions are achieved via communiations with the bank.
 `atm` cannot store any state or write to any files except the
`card-file`. The `card-file` can be viewed as the "pin code" for one's
account; there is one card file per account. 
Card files are created when `atm` is invoked with `-n` to create a new
account; otherwise, card files are only read, and not modified.

Any invocation of the `atm` which does not follow the four enumerated
possibilities above should exit with return code 255 (printing nothing).
Noncompliance includes a missing account or mode of operation and duplicated
parameters. Note that parameters may be specified in any order.

### Required Parameter

- `-a <account>` The customer's account name. 
(The format for the account is given on the [main page](index.md).)

### Optional Parameters

- `-s <auth-file>` The authentication file that `bank` creates for the
  atm.
 If `-s` is not specified, the default filename is "`bank.auth`" (in the
  current working directory).
 If the specified file cannot be opened or is invalid, the atm exits with a return
  code of 255.

- `-i <ip-address>` The IP address that `bank` is running on.
 The default value is "`127.0.0.1`".

- `-p <port>` The TCP port that `bank` is listening on.
 The default is `3000`.

- `-c <card-file>` The customer's atm card file.
 The default value is the account name prepended to "`.card`"
  ("`<account>.card`").
 For example, if the account name was `55555`, the default card file
  is "`55555.card`".

### Modes of Operation

In addition to the account name, an invocation must provide a "mode of
operation". Each of the above 4 invocations uses one such mode; these
are enumerated below. 

- `-n <balance>` Create a new account with the given balance.
 The account must be unique (ie, the account must not already exist).
 The balance must be greater than or equal to `10.00`.
 The given card file must not already exist.
 If any of these conditions do not hold, `atm` exits with a return
  code of 255.
 On success, both `atm` and `bank` print the account and initial
  balance to standard output, encoded as JSON. 
 The account name is a JSON string with key `"account"`, and the initial balance is a JSON number with key `"initial_balance"` (Example:
  `{"account":"55555","initial_balance":10.00}`).
 In addition, `atm` creates the card file for the new account (think
 of this as like an auto-generated pin).
  
- `-d <amount>` Deposit the amount of money specified.
 The amount must be greater than `0.00`.
 The specified account must exist, and the card file must be
 associated with the given account  (i.e., it
 must be the same file produced by `atm` when the account was created).
 If any of these conditions do not hold, `atm` exits with a return
  code of 255.
 On success, both `atm` and `bank` print the account and deposit
  amount to standard output, encoded as JSON.
 The account name is a JSON string with key `"account"`, and the
  deposit amount is a JSON number with key `"deposit"` (Example:
  `{"account":"55555","deposit":20.00}`).
  
- `-w <amount>` Withdraw the amount of money specified.
 The amount must be greater than `0.00`, and the remaining balance must be
  nonnegative.
 The card file must be associated with the specified account (i.e., it
 must be the same file produced by `atm` when the account was created).
 The ATM exits with a return code of 255 if any of these conditions
  are not true.
 On success, both `atm` and `bank` print the account and withdraw
  amount to standard output, encoded as JSON.
 The account name is a JSON string with key `"account"`, and the
  withdraw amount is a JSON number with key `"withdraw"` (Example:
  `{"account":"55555","withdraw":15.00}`).
  
- `-g` Get the current balance of the account.
 The specified account must exist, and the card file must be
 associated with the account.
 Otherwise, `atm` exits with a return code of 255.
 On success, both `atm` and `bank` print the account and balance to
  stdout, encoded as JSON.
 The account name is a JSON string with key `"account"`, and the
  balance is a JSON number with key `"balance"` (Example:
  `{"account":"55555","balance":43.63}`).
