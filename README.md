# Analysis of UltraDNS Minimally Covering NSEC Algorithm

## Background

UltraDNS, a commercial DNS provider, uses a variant of Minimally
Covered NSEC records in their DNSSEC implementation described in
RFC 4470 ( https://datatracker.ietf.org/doc/html/rfc4470 ). This
excercise tries to reverse engineer the UltraDNS epsilon function
used to compute the NSEC precedecessor and successor names they
use.

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

The predecessor typically uses one child label `~` prepended, but
sometimes uses **two** (i.e., `~.~.pred~` instead of `~.pred~`). This
behavior is deterministic and correlates with the queried name falling in
certain "gaps" between existing zone names.

For example, in single-character queries against `ultratest.huque.com`:
- Queries `f` through `j` produce depth-2 predecessors (these fall between
  existing names `ent` and `jaguar`)
- Queries `x` and `y` produce depth-2 predecessors (these fall between
  existing names `wild` and `yak`)
- All other queries produce depth-1 predecessors

The extra depth is not strictly required for correctness — a single `~`
child label would produce a canonically valid predecessor in all observed
cases. This may be a conservative implementation detail in UltraDNS's
online signer, possibly related to how it indexes the zone data internally.

The predecessor is not padded to maximum DNS name length (except for the
edge case of querying `!` itself, which produced a max-length 0xFF-filled
name).

## Variable-Depth Predecessor

The number of `~` child labels prepended to the predecessor base label
is not fixed — it varies depending on the zone content. The base label
computation is always the same (decrement last character, append `~`),
but the number of `~` child labels prepended equals the **subtree height
of the nearest preceding existing zone name** in DNS canonical order.

### Rule

Given a query name Q within some parent domain:

1. Find the nearest existing zone name P that precedes Q in DNS
   canonical order (at the same level within the parent).
2. Compute the subtree height of P: the length of the longest
   descendant chain rooted at P within the zone.
   - Leaf node (no children): height = 1
   - Node with children but no grandchildren: height = 2
   - Node with grandchildren: height = 3, etc.
3. Prepend that many `~` child labels to the predecessor base label.
4. If no preceding name exists (Q sorts before all names at this level),
   use height = 0 (no `~` child labels).

### Verification with ultratest2.huque.com

The zone `ultratest2.huque.com` was constructed specifically to test this
theory, with names at various subtree depths:

**Zone structure (apex level):**
- `*` (wildcard, leaf)
- `aa` (leaf)
- `corp` (TXT) → `finance.corp` (TXT) → `foo.finance.corp` (A) — height 3
- `dd` (leaf)
- `ent` (ENT) → `kk.ent` (A) — height 2
- `gg`, `jj`, `mm`, `pp`, `ss`, `vv`, `yy` (all leaves)

**Apex-level queries (wildcard-synthesized responses):**

| Query | Preceding name | Subtree height | Depth | Predecessor |
|---|---|---|---|---|
| `a` | `*` (leaf) | 1 | 1 | `\~.\_\~` |
| `ab` | `aa` (leaf) | 1 | 1 | `\~.aa\~` |
| `bb` | `aa` (leaf) | 1 | 1 | `\~.ba\~` |
| `da` | `corp` (→finance→foo) | 3 | 3 | `\~.\~.\~.d\_\~` |
| `ee` | `dd` (leaf) | 1 | 1 | `\~.ed\~` |
| `ff` | `ent` (→kk) | 2 | 2 | `\~.\~.fe\~` |
| `hh` | `gg` (leaf) | 1 | 1 | `\~.hg\~` |
| `ww` | `vv` (leaf) | 1 | 1 | `\~.wv\~` |
| `zz` | `yy` (leaf) | 1 | 1 | `\~.zy\~` |

**Subdomain-level queries (NXDOMAIN responses):**

| Query | Preceding name | Subtree height | Depth | Predecessor |
|---|---|---|---|---|
| `ab.corp` | (none) | 0 | 0 | `aa\~.corp` |
| `ga.corp` | `finance` (→foo) | 2 | 2 | `\~.\~.g\_\~.corp` |
| `ab.ent` | (none) | 0 | 0 | `aa\~.ent` |
| `zz.ent` | `kk` (leaf) | 1 | 1 | `\~.zy\~.ent` |
| `ab.finance.corp` | (none) | 0 | 0 | `aa\~.finance.corp` |
| `zz.finance.corp` | `foo` (leaf) | 1 | 1 | `\~.zy\~.finance.corp` |

### Verification with ultratest.huque.com

The original test zone confirms the same pattern:

**Zone structure (apex level):**
- `*` is not present at the apex (only under `wild`)
- `_`, `_foo` (leaves)
- `address1`, `address2` (leaves)
- `ent` (ENT) → `foo.ent` (A) — height 2
- `jaguar`, `panthro` (leaves)
- `wild` → `*.wild`, `bar.wild`, `explicit.wild` — height 2
- `yak` (leaf)

| Query | Preceding name | Subtree height | Depth | Notes |
|---|---|---|---|---|
| f–j | `ent` (→foo.ent) | 2 | 2 | between `ent` and `jaguar` |
| x–y | `wild` (→\*.wild, etc.) | 2 | 2 | between `wild` and `yak` |
| koala, m, etc. | various leaves | 1 | 1 | typical case |
| !a | (none before `*`) | 0 | 0 | sorts before all zone names |
| a.b | (none under `b`) | 0 | 0 | no children exist under `b` |

The boundary test from the original zone also confirms: `en` (depth-1,
predecessor `\~.em\~`) vs `eo` (depth-2, predecessor `\~.\~.en\~`). The
predecessor label for `en` is `em\~`, which sorts before `ent` in
canonical order — so the depth still reflects the leaf-like predecessor
`address2` or is within a safe range. For `eo`, the predecessor label
`en\~` would sort after `ent` (since `ent` < `en\~`), so the algorithm
accounts for `ent`'s subtree and uses depth-2.

### Why extra depth is not strictly required

In every observed case, a depth-1 (or even depth-0) predecessor would
produce a canonically valid NSEC. No existing zone names fall within the
tighter range. The extra depth produces a slightly narrower bracket:

```
(canonical order)
  ~.e~  <  ~.~.e~  <  f  <  f!
```

Both `[\~.e\~, f!)` and `[\~.\~.e\~, f!)` are valid — neither contains
any existing zone name.

### Rationale for Variable Depth (Speculative)

The extra depth is never required for correctness. A depth-0 predecessor
(just the base label, no `\~` child labels) always sorts after the
preceding name P and all of P's descendants in canonical order. This is
because the base label is lexicographically greater than P's label (since
the query Q > P, and the decrement only touches the last character). In
canonical ordering, the first-from-zone label comparison already decides
`base\_label > P\_label`, so all descendants of P (whose first-from-zone
label is `P\_label`) sort before even a depth-0 predecessor.

The most compelling explanation is that the depth is a **natural emergent
property of a tree traversal**. When the online signer computes the
canonical predecessor of Q, it likely:

1. Walks an internal data structure (e.g., a red-black tree or trie)
   that indexes zone names in canonical order.
2. Finds the "previous entry" by descending to the **rightmost leaf**
   under the preceding sibling node.
3. That rightmost leaf sits at a depth equal to the subtree height.
4. The `\~` child labels are generated as the traversal ascends back up
   from that leaf — one per level.

In this model, the algorithm is not explicitly computing "subtree height
of the preceding name." It is simply performing a standard "find the
previous entry in a sorted tree" operation, and the depth is how deep
that traversal naturally goes. The `\~` labels (the maximum character in
the alphabet) at each level ensure the synthetic name sorts after every
real descendant at that level, mimicking a "go right as far as possible
at each level" tree walk.

There is one theoretical scenario where extra depth could matter: if zone
names contained label bytes > 0x7E (the octet value of `\~`), then a
single `\~` child label would not be the maximum at that level, and a
real descendant could sort after it. Going deeper provides a wider safety
margin. However, UltraDNS almost certainly restricts zone names to their
defined 40-character alphabet (where `\~` is the maximum), making this a
theoretical rather than practical concern.

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
| f | `\~.\~.e\~` | f! | depth=2 predecessor (between ent and jaguar) |
| g | `\~.\~.f\~` | g! | depth=2 |
| h | `\~.\~.g\~` | h! | depth=2 |
| i | `\~.\~.h\~` | i! | depth=2 |
| j | `\~.\~.i\~` | j! | depth=2 |
| x | `\~.\~.w\~` | x! | depth=2 (between wild and yak) |
| y | `\~.\~.x\~` | y! | depth=2 |
| en | `\~.em\~` | en! | depth=1, just before boundary |
| eo | `\~.\~.en\~` | eo! | depth=2, at boundary |

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
