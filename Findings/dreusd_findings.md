# dreUSD — In-band depeg extraction via a frozen redemption quote

**Sherlock · Solidity / EVM (Base) · ~Apr 2026 · public competitive contest**

## Summary

dreUSD is a USDC-backed stablecoin with an NFT-based withdrawal queue. My finding here is a value-extraction that lives entirely *inside* the protocol's own circuit breaker. The oracle's deviation band is supposed to protect the protocol from over-disbursing during a depeg, and I showed it does the opposite at the shallow end. I also did a piece of work I value at least as much as the bug: reconciling all 48 of my candidate findings against the protocol's two prior professional audits (Spearbit and Quantstamp) to separate genuine residual risk from what was already fixed or acknowledged. I submitted the depeg finding. It was ruled a duplicate and "not a vuln," and I escalated. I'll be plain about that.

## The bug

The redeem quote returns the reported oracle price with **no clamp to the $1 peg**, and the resulting USDC amount is **frozen into the withdrawal NFT with no re-check at fill**. Those two decisions compose into an in-band depeg extraction.

`dreUSDOracle.getTokenAmount` (`dreUSDOracle.sol:250-293`) validates the feed (sequencer, staleness, `answer > 0`, then `_checkDeviation`) and computes the token amount straight from the reported price (`:287-292`). `_checkDeviation` (`:407-418`) only *gates*: it reverts when the price is outside the band `$1 · [1 ∓ bps/1e4]` (default 100 bps) and otherwise lets the reported price flow into the division with no `min/max` against $1. So with USDC reported at $0.995 (an 8-dp feed → `price = 99_500_000`, inside the band) and `dreUSDAmount = 100e18`:

```
tokenAmount = (100e18 · 1e6) / (99_500_000 · 1e10) = 100_502512  // 100.502512 USDC
```

versus 100.000000 at peg — ~0.5% more USDC per dreUSD, rising toward ~1% at the $0.99 band edge.

That amount is then frozen. `requestWithdrawal` (`dreUSDManager.sol:479-503`) burns the dreUSD, calls `getTokenAmount`, and stores `usdcAmount` verbatim into the NFT via `dreWithdrawalNFT.mint` (`dreWithdrawalNFT.sol:105-121`). `fillWithdrawal` (`dreUSDManager.sol:534-592`) runs up to `withdrawalWaitingTime` (1–14 days) later, reads `position.usdcAmount`, and pays exactly that, with **no oracle call anywhere in the loop**. `requestExpressWithdrawal` freezes the quote identically (`:521`).

**Attack:** hold 100 dreUSD. During an in-band USDC depeg to ~$0.995, call `requestWithdrawal`, and the NFT locks 100.502512 USDC. Wait out the window. USDC repegs to $1.00, and the fill pays the frozen 100.502512 USDC, worth $100.50 for $100 of burned dreUSD. The user-set `minUsdcAmount` (`:499`) is only a lower bound, so it does not constrain this. The extraction is drawn from shared USDC backing and socialized onto remaining holders, and it repeats on every depeg→repeg. PoC (`test/oracle_frozen_quote.t.sol`) passes, logging `stored USDC: 100502512`, `overpay vs peg-fair: 502512`.

The design defense, and my answer, are on the record. The README says protocol-set deviation thresholds exist to *"protect the protocol from disbursing too much during a depeg event."* This is that exact protection failing at the moment it is supposed to hold. The gate rejects only out-of-band prices and passes the in-band depeg straight into the amount math. That is an unintended gap between the stated protective purpose and the implementation, not an accepted tolerance.

## Past-audit reconciliation

Separately, I reconciled my 48 integration-vector findings against the two prior audits: Spearbit/Cantina (35 findings, all fixed-and-verified) and Quantstamp (13, 11 fixed / 2 acknowledged). That meant decoding both PDFs and verifying in the current source that the Spearbit fixes are actually present, so my analysis ran against post-fix code. Every finding got a verdict: `ACK-DUP` (duplicates an acknowledged prior), `OUT-TRUST` (out of scope under the README trust model + 48h timelock), `FIX-RESIDUAL` (a gap the prior *fix* introduced or left, the best novelty), `REFINEMENT` (a sharper form of an already-fixed feature), or `NOVEL`. The strongest survivors were residual-in-fixes, and, being honest about the ranking, *not* this depeg finding. The two I rated highest were a permanent express-capacity strand that is a *side-effect of Spearbit 5.2.21's skip-not-revert fix*, and a paused-distributor `totalAssets` inflation distinct from Quantstamp's deflation-vector Medium. The depeg finding itself came out of that reconciliation graded a **REFINEMENT**: a sharper observation layered on top of Spearbit 5.1.8's *fixed* deviation gate, explicitly "bounded and partly design-accepted," one of the lower-value novels rather than a top survivor. This is the "recall vs professional prior audits" discipline. Most of the 48 correctly collapsed into already-known or out-of-scope, and the reconciliation is what isolates the few that don't, and ranks them without flattering my own leads.

## Impact & severity

**Medium.** A loss that "requires certain external conditions" (the depeg) and is relevant to the affected party: over the relevance thresholds (>0.01%, >$10) on any non-trivial redemption, and repeatable, so the Sherlock note "a 0.01% loss replayed indefinitely is a 100% loss" applies. It does not reach High, because the loss is gated on the depeg, not unconditional. And it is honestly bounded. Per-event size is capped by the deviation band, and the quote is fair *at the request instant*; the extraction is the reserve-vs-par gap realized after repeg, not risk-free arbitrage.

## Status

**Submitted as #643 → ruled a DUPLICATE of #1479 (via #2359, with a related objection in #112) and the primary ruled "not a vulnerability" as an accepted design choice → ESCALATED.** I will not dress this up. My own past-audit reconciliation had already graded this finding a *refinement* of the fixed deviation gate, bounded and partly design-accepted, so a "duplicate / not-a-vuln" ruling is consistent with where I myself ranked it. What the escalation contests is the specific reasoning, not the low tier. My escalation challenges the "not a vuln" ruling on behalf of the duplicate set. The in-band leak defeats the exact protective purpose the README states, so it is an unintended gap, not a §VII.6 no-loss design choice. It is not a §VII.16 known issue, since Spearbit 5.1.8 *added* the gate and was Fixed, and the residual no-clamp is not an acknowledged-and-unfixed prior. And likelihood is not a valid downgrade. I concede plainly what is conceded: the per-event size is band-bounded and the quote is fair at request time. Requested outcome: overturn to Medium. The honest disposition as it stands: ruled a duplicate and non-vuln, escalation pending on the merits above.
