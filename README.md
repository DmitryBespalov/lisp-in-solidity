# LISP in Solidity

**RESEARCH CODE. DO NOT USE IN PRODUCTION.**

## Motivation

**TLDR;** I wanted to create a DSL in Solidity and so created a LISP (subset) interpeter as a proof of concept.

I wanted to solve a problem that some crypto traders have: having a Gnosis Safe Multisig, they want to limit the transactions possible for a certain owner.
For example, if a newbie trader joins the multisig, they would have permission to only interact with a certain contract and to make a certain kind of transactions and put limits on the parameters.

This felt as a good problem for a domain-speific language. Traders would specify the restrictions (or policies) for the multisig contract, and then the policies would be followed on the contract level.

Currently implemented (Oct 2021) multisig functionality would be expressed with something like

```
N out of M owners
```

Then, other types of policies could be implemented if the DSL allow boolean logic

```
(signer IN owners) OR (signer IS 0x1234..3456)
```

The language interpreter would receive the environment from the host contract that would provide access to the current values of `owners`, and `signer` variable would be a special variable existing during singature check.

Then, we could also define a format for pattern-matching the call data (contract interactions) for a specific contract with something like this:

```
to == 0x1234...3456 
AND
tx.data MATCHES
    swap(
        from[address]: ANY,
        value[uin256]: 0...1500,
        to[address]: ANY,
        value[uint256]: 0...3975
    )
```

However, building this in Solidity with my (very basic) skills in this language seemed as a complicated task. Therefore, I decided to build a proof-of-concept first for an easier language and selected LISP.

I have used https://norvig.com/lispy.html as a blueprint and ported the python functionality to Solidity.

So there it is, a subset of LISP, implemented in Solidity.

## How to Use
See `scaffold-eth-README.md` to learn how to start chain, server, and deploy the contracts.

You can try out these expressions.

Arithmetic with uint256 integers (+, -, *, /)

```
(+ 1 1)
```

Conditional, number copmarisons and boolean operators (or, and, not)

```
(if (or (> 1 2) (< 3 4)) 1 0)
```

Variable definitions

```
(begin (define a 3) (+ a 2))
```

Making lists and testing for membership

```
(begin (define L (list 1 2 3)) (member 1 L))
```

Please note, most operations (except `list`) support 2 arguments only.

If you input incorrect syntax or a function not found, the app will crash :(

## Viery short overview.
It is a recursive descent parser.

The interpreter takes input string, parses it into tokens, builds expression (AST) from the tokens, and then evaluates the expression recursively.

The output from the evaluation is a Solidity struct representing a terminal expression (number, boolean, or a string). No user-formatting is implemented now.

## Notes
* I expect this to be extremely gas inefficient, no gas optimizations were made or designed in.
* This is in no way unit tested or audited. Only debugged manually for the happy case.
* Modified the `src/components/Contract/index.jsx` to show only single `interpret` function for simple UI.

## Going further
* See if this flies with gas limit gas costs.
* Make the interpreter embeddable in other contracts.
  * Integrate with the Gnosis Safe.
* Implement the call data matching
* Try out more human-readable syntax than LISP

# License
See the LICENSE file.

# Contributors

- Thanks to [Austin Griffith](https://github.com/austintgriffith) and others for building [scaffold-eth](https://github.com/scaffold-eth/scaffold-eth) that I used as a template do this experiment in.
- [Dmitry Bespalov](https://github.com/DmitryBespalov), [Twitter](https://twitter.com/@_DmitryBespalov)
