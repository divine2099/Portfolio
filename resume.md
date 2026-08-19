# Jamike Divine

**Smart contract security researcher across EVM and non-EVM chains. I build and run an AI-assisted audit methodology that isn't tied to any one protocol type.**

[kelbottumm@gmail.com](mailto:kelbottumm@gmail.com) · Code4rena [@white-fox02](https://code4rena.com/@white-fox02) · Sherlock [@eat-the-sky](https://audits.sherlock.xyz/watson/eat-the-sky) · GitHub [@divine2099](https://github.com/divine2099)

---

## Summary

I audit smart contracts, and the heart of what I do is a methodology I built over the
past year. It's an AI-assisted audit process, and it doesn't depend on the protocol
type or the chain. I've run it across EVM, Sui, Solana, Soroban, Cosmos and Stacks, on
everything from lending and AMMs to RWA, restaking and bridges. What sets it apart is
that it kills its own false positives before a judge ever sees them. If anyone doubts
it generalizes, give me a protocol and I'll show you. I want to either help a team
build AI tooling for security review, or find bugs in production protocols.

## What I do well

The methodology is the main thing, and it re-targets from a single profile of the
target, so the same process works whether it's EVM, a Solana program, a Move package
or a ZK circuit. It runs from a threat model through per-model reading, invariant
extraction, state-space work, chained attacks, and a scope-gated report where
everything is backed by a PoC. It's execution-driven, so I don't trust a "no findings"
until a harness has actually run. And it's honest about what it can't prove. I retract
my own findings on the record.

Oracle and price manipulation is one area I'm particularly strong in: TWAP and EMA
manipulation, staleness, band and clamp math, cross-price scaling. But that's an
example of the method at work, not the limit of it. Point it at a different kind of
protocol and it holds.

I write real PoCs in Foundry, Anchor and Go. On targets that Spearbit- and
Quantstamp-grade firms had already audited, my process reproduced their findings on
its own, running on a $20/month plan.

## Selected findings (public contests)

Full reports are in the portfolio. These are recent, and I state honestly how each was
judged.

- **Chainlink Payment Abstraction** (Code4rena, EVM). Two zero-role chains that stall
  settlement, visible only when you compose findings across models. Self-rated,
  unreconciled.
- **Monetrix** (Code4rena, EVM/Hyperliquid). Full backward reachability map of every
  public entry point, and a permanent yield-settlement freeze.
- **Morpho Midnight** (Cantina, EVM). Scope verification and cross-audit dedup. I
  caught a wrong mapping of my own and debunked a reentrancy finding by PoC.
- **dreUSD** (Sherlock, EVM/Base). In-band depeg extraction, plus a 48-finding
  reconciliation against prior Spearbit and Quantstamp audits. Submitted, ruled a
  duplicate, escalated.
- **Confidence Pools** (Cyfrin/CodeHawks, EVM). A zero-submit. Every chain I built
  broke on a real guard, and I kept the ledger to show it.

## Technical

Languages and VMs: Solidity (EVM), Move (Sui), Rust (Solana/Anchor, Soroban), Go
(Cosmos), Clarity (Stacks).

Tooling: Foundry for PoCs and invariant/differential fuzzing, Anchor and bankrun on
Solana, Go test harnesses on Cosmos, a self-built AI-assisted review pipeline, and
git-based reproducible PoCs.

Domains: AMMs and DEXs, lending and RWA, oracles and price providers, vaults,
restaking, cross-chain messaging, perps, stablecoins, yield.

## Experience

**Independent smart contract security researcher**

Competitive and private audits across EVM and non-EVM chains: Sherlock, Code4rena,
Cantina, Cyfrin/CodeHawks, HackenProof, and direct bounty work. Built the audit
process from scratch and used it on 20+ protocols across six languages.

## Beyond auditing — Polaris Omega

I don't only break systems, I build them. Polaris Omega is a cross-chain market-making and
arbitrage system I wrote in Rust, on my own, across Base, Arbitrum, Optimism and Ethereum:
Kalman + Avellaneda-Stoikov pricing, flash-funded profit-or-revert execution, a gas-tuned
on-chain executor, and a risk layer of circuit breakers, position limits and segregated
inventory. Same discipline as the audits, venues pinned to their deployed commit and checked
against live bytecode. Built and tested in simulation, private repo. Walkthrough:
[polaris-omega.md](polaris-omega.md).
