# Olas — Code4rena (Valid High)

**Platform:** Code4rena · **Language / VM:** Solidity / EVM · **Verdict:** Valid High

## The setup

The protocol priced against an on-chain oracle, and that oracle had a `validatePrice` function whose
whole job was to catch price manipulation. The intended design was the standard one: compare the
current spot price against a time-weighted average price (TWAP). If spot has been shoved far away from
the average, that's the signature of manipulation, and the check should reject it.

## The bug

The check built its TWAP out of the current spot price. So the "average" it compared against wasn't an
independent, time-smoothed reference at all, it was the same spot value it was supposed to be checking.
The two sides of the comparison were always equal, and the guard passed every time, including in the
exact case it existed to stop.

A manipulation guard that reads its reference from the value being manipulated protects nothing.

## The impact

Manipulate the pool to move the spot price, wait a block so the state settles, and the oracle reports
the manipulated price as valid. Anything relying on that oracle for pricing can then be drained. That's
a direct path to loss of funds, which is why it was judged High.

## How the pipeline caught it

This is exactly what the invariant-extraction and invariant-break steps are for. The named invariant
was "the manipulation check compares an independent reference against spot." Tracing where the
reference actually came from broke that invariant immediately: the reference and the spot were the same
source. The finding was anchored to the quoted lines where the TWAP was constructed, then cleared all
four validity gates, reachable, above the severity floor, not a known issue, not intended behavior, and
was submitted. Judged Valid High.
