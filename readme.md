# Smart Contract Security Researcher

I'm Jamike. I audit smart contracts. The core of what I do is a methodology, an
AI-assisted audit process I built over the past year, and it isn't tied to one kind of
protocol or one chain. I've run it across six languages and six competitive platforms:
lending, AMMs, RWA, restaking, bridges, oracles, stablecoins, whatever the protocol
happens to be. If you're not sure it holds up on your kind of system, hand me one and
I'll show you.

I'd rather show you the work than quote a bug count, so the findings are up top, each
with an honest note on how it got judged.

## Findings

Recent work. Every one is a real contest finding. Where a finding was a duplicate, or
lost an escalation, or where I chose not to submit at all, I say so.

| Protocol | Platform | Language / VM | What I found |
|---|---|---|---|
| [**Chainlink Payment Abstraction**](Findings/chainlink_payment_abstraction_findings.md) | Code4rena | Solidity · EVM | Two zero-role chains, an oracle-freeze DoS and a mempool-blocking monopoly, that stall settlement. A composition-level argument the model-by-model view can't see. Self-rated, unreconciled and unjudged. |
| [**Monetrix**](Findings/montrix_findings.md) | Code4rena | Solidity · EVM (Hyperliquid) | Every public entry point traced backward through every auth gate, and a stale-registry asymmetry that permanently freezes yield settlement. |
| [**Morpho Midnight**](Findings/morpho_findings.md) | Cantina | Solidity · EVM | Scope verification and cross-audit dedup, plus a reentrancy finding I *debunked* with my own PoC. |
| [**dreUSD**](Findings/dreusd_findings.md) | Sherlock | Solidity · EVM (Base) | In-band depeg extraction through a frozen redemption quote, plus a 48-finding reconciliation against prior Spearbit and Quantstamp audits. Submitted, ruled a duplicate, escalated. |
| [**Confidence Pools**](Findings/confidence_pools_findings.md) | Cyfrin / CodeHawks | Solidity · EVM | A zero-submit. Every attack chain I built broke on a real guard, and I kept the ledger showing where each one died. |

Full index: [Findings/README.md](Findings/README.md).

## How I work

Most audit output is noise. Bugs that look real until you check them against the
trust model, and then fall apart. My process is built to catch that before anything
gets submitted.

A finding has to clear four checks. Is it actually reachable. Does it clear the
severity bar. Is it already a known issue. Is it just intended behavior. Fail any one
and it's dead, and no amount of talking up the impact brings it back. I'd rather kill
a weak finding and write down why than ship it and hope.

I also don't trust "looks clean" when it comes from reading. If I tell you a piece of
code is safe, it's because a harness ran against it. And when I get something wrong, I
leave the retraction in the notes instead of quietly deleting it.

The pipeline itself stays private. If you're building AI tooling for audits, I'm glad
to walk you through how it's put together.

## What the record shows

I don't have a wall of contest wins, and I won't pretend otherwise. What I have is
this.

The process re-finds what paid auditors found. On dreUSD I lined up 48 of my findings
against the earlier Spearbit and Quantstamp reports. On Morpho I checked mine against
three prior professional reviews. Where a protocol had already been audited by firms
like those, my pipeline turned up the same bugs on its own. It also digs past their
patches and finds new bugs sitting inside the fixes.

A lot of what got marked "invalid" wasn't wrong. It was ruled out on a contest rule,
a duplicate or a severity floor or a scope call, not because the bug wasn't real.

And it's cheap. A protocol takes a few days, a bit longer when the codebase is large,
running on a $20/month plan. The slow part is the plan's rate limit, not the method.
More compute just makes it faster.

## Where I've worked

Public competitive audits, on Sherlock (Fluid DEX v2, Metric OMM, dreUSD,
OpenCover, Current Finance), Code4rena (Olas, Monetrix, Chainlink Payment Abstraction,
Jupiter Lend, Intuition, LayerZero, Kinetic, Injective), Cantina (Morpho Midnight,
Symbiotic, Revert Lend, Royco), and Cyfrin/CodeHawks (BattleChain Confidence Pools).

Private engagements, named with permission but with all findings kept under NDA, on
HackenProof (0xMarkets, Darts RWA, tokenize.it, Sui, Overlayer, Zynk) and direct
bounty work (Notional, sBTC, Twyne, Zest, Exponent).

## Elsewhere

- Résumé: [resume.md](resume.md)
- Code4rena: https://code4rena.com/@white-fox02
- Sherlock: https://audits.sherlock.xyz/watson/eat-the-sky
- GitHub: https://github.com/divine2099
