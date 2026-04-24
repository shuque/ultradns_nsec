# Analysis of UltraDNS Minimally Covering NSEC Algorithm

## Character Alphabet

From the decrement observations, we can deduce the character set used by
UltraDNS's epsilon function. The key evidence is which characters map to
the same predecessor when decremented:

| Queried last char | Predecessor last char | ASCII gap |
|---|---|---|
| a (0x61) | \_ (0x5F) | skips \` (0x60) |
| \_ (0x5F) | 9 (0x39) | skips : ; < = > ? @ A-Z \[ \\ \] ^ (0x3A-0x5E) |
| 0 (0x30) | - (0x2D) | skips . / (0x2E-0x2F) |
| - (0x2D) | ! (0x21) | skips " # $ % & ' ( ) \* + , (0x22-0x2C) |
| \~ (0x7E) | z (0x7A) | skips { \| } (0x7B-0x7D) |

All characters between consecutive alphabet members decrement to the same
predecessor. For example:
- b", b#, b\*, b+, b, all have predecessor `\~.b!\~` (all chars 0x22-0x2C -> !)
- b/, b. would have predecessor `\~.b-\~` (chars 0x2E-0x2F -> -)
- b:, b;, b@, b^ all have predecessor `\~.b9\~` (chars 0x3A-0x5E -> 9)
- b\`, has predecessor `\~.b_\~` (char 0x60 -> \_)
- b{, b|, b} all have predecessor `\~.bz\~` (chars 0x7B-0x7D -> z)

### Deduced Alphabet (ordered)

```
! - 0 1 2 3 4 5 6 7 8 9 _ a b c d e f g h i j k l m n o p q r s t u v w x y z ~
```

In hex: 0x21, 0x2D, 0x30-0x39, 0x5F, 0x61-0x7A, 0x7E

This is essentially: `!`, `-`, digits `0-9`, `_`, lowercase letters `a-z`, `~`

Total: 40 characters

Note: DNS is case-insensitive for comparisons, so uppercase A-Z maps to
lowercase a-z. The algorithm appears to operate in the lowercased space.

## Successor Function

**For NODATA responses** (name exists, wrong type):
- The NSEC owner = the queried name itself
- The NSEC next name = queried name with `!` appended
- `!` (0x21) is the smallest character in the alphabet
- This means the NSEC range `[name, name!)` contains only `name` itself

**For NXDOMAIN responses** (name doesn't exist):
- The NSEC next name = queried name with `!` appended
- Same as NODATA

**Special cases for names with children in the zone:**

For the zone apex and empty non-terminals, simply appending `!` to the
label would not work. In DNS canonical ordering, all children of a name
sort between the name and its next sibling. So if the successor were
`ent!`, the NSEC range `[ent, ent!)` would also cover `foo.ent` (a
legitimate child that exists in the zone), effectively denying its
existence. For the zone apex there is an additional reason: appending `!`
to the apex label would produce `ultratest!.huque.com.`, which is a name
in the parent `huque.com` zone, not in `ultratest.huque.com`. NSEC records
chain names within a single zone, so the next name must remain within the
zone's authority. Even if a validator doesn't enforce a same-zone check,
producing an out-of-zone next name would be semantically incorrect.
Beyond this, `ultratest!` would also sort after all child names in the zone,
creating the same coverage problem as the ENT case.

Instead, the successor must be a child of the name, sorting after the name
but before any real children:

- Zone apex NODATA: next name = `!.ultratest.huque.com.` (child label `!`,
  the alphabet minimum, which sorts before any real child)
- Empty non-terminal (ent): next name = `\000.ent.ultratest.huque.com.`
  (a child label containing a single 0x00 byte)

The ENT case uses `\000` (the absolute DNS minimum byte) rather than `!`
(the algorithm's alphabet minimum). Using `!.ent` would have been equally
correct and consistent with the apex behavior. The use of `\000` — a
character outside the algorithm's deduced alphabet — suggests the ENT and
apex cases are likely handled by different code paths, with the ENT path
falling back to the generic DNS minimum byte rather than the algorithm's
own alphabet minimum.

**Conclusion: The successor function is always "append `!`"** for regular
names (leaf nodes). For names that have children in the zone (ENT, apex),
a child-label approach is used instead to avoid covering existing children.

## Predecessor Function

The predecessor function is more complex. For a queried name Q:

1. Take the last character of Q
2. Decrement it to the previous character in the alphabet
3. Append `~` (the maximum character in the alphabet)
4. Prepend a child label `~`

The general form for predecessor of label `L` = `~.L[0..n-2] + prev(L[n-1]) + ~`

Where `prev(c)` is the previous character in the alphabet:
- prev(a) = \_
- prev(\_) = 9
- prev(0) = -
- prev(-) = !
- prev(\~) = z
- prev(b) = a, prev(c) = b, ..., prev(z) = y
- prev(1) = 0, prev(2) = 1, ..., prev(9) = 8

**Special case when last char is `!`** (the minimum character):
When the last character is already `!` (the minimum), you can't decrement it.
Instead, the predecessor drops the last character and prepends a child label `~`:
- pred(b!) = `\~.b` (i.e., the child label `~` under parent `b`)
- pred(c!) = `\~.c`

This makes sense because in canonical DNS ordering, `~.b` (i.e., a child `~`
under `b`) sorts just before `b!` (a sibling `b!`).

### Why `~` as child label and suffix?

`~` (0x7E) is the maximum character in the alphabet. By using it:
- As a child label prefix: maximizes the name in the "children come before
  siblings" DNS canonical ordering
- As a suffix after the decremented character: pushes the name as far forward
  as possible within that position

The result is a name that sorts immediately before the queried name in
canonical order, creating the tightest possible NSEC bracket.

### Depth of predecessor

The predecessor always uses exactly ONE child label `~` prepended, and
exactly ONE `~` appended to the decremented name. The predecessor is not
padded to maximum DNS name length (except for the edge case of querying `!`
itself, which produced a max-length 0xFF-filled name).

## Wildcard Coverage NSEC

For NXDOMAIN responses, a second NSEC proves no wildcard exists at the
closest encloser. For direct children of the zone, this is always:

```
!~.ultratest.huque.com. NSEC -.ultratest.huque.com.
```

This bracket `(!~, -)` covers `*` (0x2A) which would be the wildcard label.
- `!~` = `!` + `~`, which is the maximum name starting with `!`
- `-` is the next character in the alphabet after `!`
- So this range covers everything between `!~` and `-`, which includes `*`

Note: The zone does have `*.wild.ultratest.huque.com` but that's a wildcard
under the `wild` subdomain, not at the zone apex.

### Wildcard-synthesized response (nonexist.wild)

A query for `nonexist.wild.ultratest.huque.com. A` returned a
wildcard-synthesized answer (from `*.wild.ultratest.huque.com`). The
response included an NSEC proving that no name closer than the wildcard
exists:

```
~.nonexiss~.wild.ultratest.huque.com. NSEC nonexist!.wild.ultratest.huque.com.
```

This uses the same predecessor/successor algorithm, applied within the
`wild.ultratest.huque.com` subdomain: predecessor of `nonexist` is
`~.nonexiss~` (decrement `t` to `s`, append `~`, prepend child label `~`),
and successor is `nonexist!`. This proves no exact match for
`nonexist.wild` exists, so the wildcard synthesis is valid.

### Wildcard-synthesized response at zone apex (camel)

To test whether UltraDNS applies the same algorithm at the zone apex, a
temporary `*.ultratest.huque.com` wildcard was added. A query for
`camel.ultratest.huque.com. A` returned a wildcard-synthesized answer
with this NSEC in the authority section:

```
~.camek~.ultratest.huque.com. NSEC camel!.ultratest.huque.com.
```

This is the same predecessor/successor algorithm: predecessor of `camel` is
`~.camek~` (decrement `l` to `k`, append `~`, prepend child label `~`),
and successor is `camel!`. No wildcard coverage NSEC is needed since the
wildcard exists. This confirms no special-casing at the zone apex — the
algorithm is identical to the `nonexist.wild` case under a subdomain wildcard.

## Appendix: Raw Query Data

All names below are shown as labels relative to `ultratest.huque.com`
unless otherwise noted.

### NODATA Responses

| Query (name, type) | NSEC Owner | NSEC Next | Type Bitmap |
|---|---|---|---|
| address1 AAAA | address1 | address1! | A RRSIG NSEC |
| address2 A | address2 | address2! | AAAA RRSIG NSEC |
| jaguar AAAA | jaguar | jaguar! | A RRSIG NSEC |
| yak AAAA | yak | yak! | A RRSIG NSEC |
| \_ A | \_ | \_! | TXT RRSIG NSEC |
| ultratest.huque.com AAAA | ultratest.huque.com | !.ultratest.huque.com | A NS SOA RRSIG NSEC DNSKEY CAA |
| ent A | ent | \\000.ent | RRSIG NSEC |

Note: `ent` is an empty non-terminal (has child `foo.ent` but no records
of its own). Its successor uses a `\000` child label rather than appending `!`.

### NXDOMAIN Responses — Name Coverage NSEC

Each NXDOMAIN response contains two NSECs. This table shows the NSEC that
covers the queried name (proves it doesn't exist).

| Query | Predecessor (NSEC owner) | Successor (NSEC next) | Notes |
|---|---|---|---|
| koala | `\~.koal_\~` | koala! | |
| apple | `\~.appld\~` | apple! | |
| zebra | `\~.zebr_\~` | zebra! | |
| abc | `\~.abb\~` | abc! | |
| m | `\~.l\~` | m! | single char |
| zzz | `\~.zzy\~` | zzz! | |
| ba | `\~.b_\~` | ba! | a decrements to \_ |
| bA | `\~.b_\~` | ba! | case-insensitive, same as ba |
| b0 | `\~.b-\~` | b0! | 0 decrements to - |
| b- | `\~.b!\~` | b-! | - decrements to ! |
| b\_ | `\~.b9\~` | b\_! | \_ decrements to 9 |
| b\~ | `\~.bz\~` | b\~! | \~ decrements to z |
| b! | `\~.b` | b!! | ! is minimum: drops char, uses child label |
| c! | `\~.c` | c!! | same ! minimum behavior |
| b" | `\~.b!\~` | b"! | non-alphabet char, maps to ! |
| b# | `\~.b!\~` | b#! | non-alphabet char, maps to ! |
| b\* | `\~.b!\~` | b\*! | non-alphabet char, maps to ! |
| b+ | `\~.b!\~` | b+! | non-alphabet char, maps to ! |
| b, | `\~.b!\~` | b,! | non-alphabet char, maps to ! |
| b/ | `\~.b-\~` | b/! | non-alphabet char, maps to - |
| b\` | `\~.b_\~` | b\`! | non-alphabet char, maps to \_ |
| b: | `\~.b9\~` | b:! | non-alphabet char, maps to 9 |
| b; | `\~.b9\~` | b;! | non-alphabet char, maps to 9 |
| b@ | `\~.b9\~` | b@! | non-alphabet char, maps to 9 |
| b^ | `\~.b9\~` | b^! | non-alphabet char, maps to 9 |
| b{ | `\~.bz\~` | b{! | non-alphabet char, maps to z |
| b\| | `\~.bz\~` | b\|! | non-alphabet char, maps to z |
| b} | `\~.bz\~` | b}! | non-alphabet char, maps to z |
| b1 | `\~.b0\~` | b1! | digit decrement |
| b9 | `\~.b8\~` | b9! | digit decrement |
| bz | `\~.by\~` | bz! | letter decrement |
| a | `\~._\~` | a! | single char, a decrements to \_ |
| cat | `\~.cas\~` | cat! | |
| abcdef | `\~.abcdee\~` | abcdef! | longer name |
| abcdefghij | `\~.abcdefghii\~` | abcdefghij! | longer name |
| address0 | `\~.address-\~` | address0! | 0 decrements to - |
| address1a | `\~.address1_\~` | address1a! | a decrements to \_ |
| zzzzz | `\~.zzzzy\~` | zzzzz! | |
| !a | `!_\~` | !a! | pred uses \_ (prev of a), no child label prepended |
| a.b | `_\~.b` | a!.b | multi-level: algorithm applied to first label under closest encloser b |

### NXDOMAIN Responses — Wildcard Coverage NSEC

For all NXDOMAIN queries of direct children of the zone, the wildcard
coverage NSEC was identical:

```
!~.ultratest.huque.com. NSEC -.ultratest.huque.com. RRSIG NSEC
```

This covers `*` (0x2A), proving no wildcard exists at the zone apex.

For multi-level names, the wildcard NSEC covers the appropriate closest
encloser. For example, `a.b.ultratest.huque.com` produced:

```
!~.b.ultratest.huque.com. NSEC -.b.ultratest.huque.com. RRSIG NSEC
```

### Wildcard-Synthesized Response

| Query | NSEC Owner | NSEC Next | Notes |
|---|---|---|---|
| nonexist.wild | `\~.nonexiss\~.wild` | nonexist!.wild | proves no closer match than \*.wild |
| camel (apex wildcard) | `\~.camek\~` | camel! | proves no closer match than \*.ultratest.huque.com |

### Special Case: Querying "!" Itself

Querying `!.ultratest.huque.com` produced a predecessor consisting of a
maximum-length name filled with `\255` (0xFF) bytes across multiple labels,
representing the absolute maximum possible name that sorts before `!` in
the DNS namespace. The successor was `!!`.
