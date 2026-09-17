# Smart-contract security

I find bugs in smart contracts with a pipeline I built. It's the same disciplined method I use to build
systems, pointed at breaking them instead. It isn't tied to one protocol type or one chain, it's
honest about what it can't prove, and it's cheap to run. Two of its findings were judged Valid High, on
Sherlock and on Code4rena.

I'd rather show the work than quote a bug count, so the two clean wins are first, then the pipeline,
then the fuller record with an honest note on how each finding was judged.

## The two Valid Highs

- **[Olas](findings/olas.md)** — Code4rena, Solidity/EVM. **Valid High.** An oracle's `validatePrice`
  was supposed to catch manipulation by checking the spot price against a TWAP, but it built the TWAP
  out of the current spot price, so the two were always equal and the check always passed. Manipulate
  the pool, wait a block, drain whatever relies on it.
- **[Current Finance](findings/current-finance.md)** — Sherlock, Sui/Move. **Valid High.** A lending
  protocol whose liquidation validated positions on the EMA price but computed collateral seizure on the
  spot price. During volatility that divergence lets a liquidator over-seize collateral or liquidate a
  healthy position.

Oracle and price-manipulation work is a strong area for me: TWAP and EMA manipulation, staleness, band
and clamp math, cross-price scaling. That's an example of the method working, not the limit of it.
Point it at a different kind of protocol and it holds.

## The pipeline

Two pieces work together: a pipeline that surfaces candidate bugs, and a validity pass that decides,
honestly, which ones are real.

**Audit Pipeline v3, a 17-step protocol-agnostic pipeline.** It's coverage-driven, not lead-driven. It
doesn't stop when it runs out of ideas, it stops when every value-carrying and sponsor-flagged surface
has been exercised by a running harness and gated. A "no findings" result that rests only on reading is
treated as untested, not safe. The steps run from a target profile (language, runtime, tooling) through
codebase and privilege mapping, mental-model decomposition, threat modeling, deep adversarial
per-model reading where every finding is anchored to a quoted file and line, cross-model integration,
invariant extraction, invariant-break attempts, state-space exploration, cross-contract analysis,
attacker-goal chaining, a scope gate that reconciles against prior audits, overlooked-lead recovery,
a proof-of-concept with differential math fuzzing, the report, and a coverage gate. Each step names its
own input and output files. Mapping is routed to a cheaper model, the adversarial reasoning to a
stronger one. It adapts to the VM from the step-zero profile, so the same process runs on EVM/Solidity,
Solana/Anchor, Move/Sui, Cosmos and ZK.

**The validity funnel.** A separate reusable pass that kills weak candidates before anything is
submitted, with the reasoning left on the record. A finding has to clear four independent gates:

1. Is it reachable under the protocol's actual trust model.
2. Does it clear the severity floor.
3. Is it already a known issue.
4. Is it just intended behavior.

Fail any one and it's dead, and talking up the impact doesn't bring it back. A chained attack inherits
its weakest link. The arbiter is always the exact README and acknowledgment text, never a paraphrase.
When I get something wrong, the retraction stays in the notes instead of being quietly deleted.

## What the record shows

I don't have a wall of contest wins and I won't pretend to. Here is what I have.

**The two Highs above**, judged Valid High on Sherlock and Code4rena.

**It re-finds what paid auditors found.** On protocols already reviewed by firms like Spearbit and
Quantstamp, the pipeline turned up the same bugs on its own, and dug past the patches to new ones
sitting inside the fixes. On dreUSD I lined 48 of my findings up against the prior Spearbit and
Quantstamp reports. The strongest single signal: recent findings it surfaced in a few hours matched
vulnerabilities the protocol's earlier professional audits had taken up to a month to find. In a
contest, the code is audited by other firms before it ever reaches the public round, so re-finding
those bugs fast is a real benchmark against paid work.

**It's cheap.** A protocol takes a few days, longer for a large codebase, running on a $20/month plan.
The slow part is the plan's rate limit, not the method. More compute just makes it faster.

**No protocol-type limit observed.** It has worked on every protocol I've tried it on.

The fuller record below is honest process work, not all clean wins. I show it because it demonstrates
the method, including the parts where the method killed my own findings.

- **[Chainlink Payment Abstraction](findings/chainlink_payment_abstraction_findings.md)** — Code4rena,
  EVM. Two zero-role chains that stall settlement, visible only by composing findings across models.
  Self-rated, unreconciled, unjudged.
- **[Monetrix](findings/montrix_findings.md)** — Code4rena, EVM/Hyperliquid. Every public entry point
  traced backward through every auth gate, plus a stale-registry asymmetry that freezes yield
  settlement.
- **[Morpho Midnight](findings/morpho_findings.md)** — Cantina, EVM. An opcode-level DoS and
  creator-config Highs, and a cross-contract reentrancy I debunked with my own proof-of-concept.
- **[dreUSD](findings/dreusd_findings.md)** — Sherlock, EVM/Base. In-band depeg extraction, plus the
  48-finding reconciliation against prior Spearbit and Quantstamp audits. Submitted, ruled a duplicate,
  escalated.
- **[Confidence Pools](findings/confidence_pools_findings.md)** — Cyfrin/CodeHawks, EVM. A zero-submit.
  Every chain I built broke on a real guard, and I kept the ledger showing where each one died.

Full index: [findings/README.md](findings/README.md).

## Where I've worked

Independent smart-contract security researcher, 2024 to date. Public competitive audits on Sherlock
(Current Finance, Fluid DEX v2, Metric OMM, dreUSD, OpenCover), Code4rena (Olas, Monetrix, Chainlink
Payment Abstraction, Jupiter Lend, Intuition, LayerZero, Kinetic, Injective), Cantina (Morpho Midnight,
Symbiotic, Revert Lend, Royco), and Cyfrin/CodeHawks (BattleChain Confidence Pools). Private
engagements, named with permission but findings kept under NDA, on HackenProof (0xMarkets, Darts RWA,
tokenize.it, Sui, Overlayer, Zynk) and direct bounty work (Notional, sBTC, Twyne, Zest, Exponent).

## Elsewhere

- How the method is built: [../method/README.md](../method/README.md)
- The systems I build: [../trading/README.md](../trading/README.md)
- GitHub: https://github.com/divine2099
- Email: kelbottumm@gmail.com
- Telegram: https://t.me/Hatesky06
