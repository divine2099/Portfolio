# Polaris Omega

Polaris Omega is a cross-chain market-making and arbitrage system I built in Rust, on my own,
across Base, Arbitrum, Optimism and Ethereum. The repo is private, so this is the walkthrough.
It's built and tested in simulation, not run live with real money.

I'm writing it the way I'd explain it on a call: what it does, the parts that turned out to be
hard, and where I was wrong before I was right.

## What it is

Capital sits pre-positioned on each chain and gets rebalanced synthetically, so no bridge is ever
in the critical path. Trades are flash-funded and either turn a profit or revert, so a bad fill
costs gas, not principal. Pricing runs on a Kalman filter with an Avellaneda-Stoikov spread and
inventory model. The whole thing runs co-resident with the node as a Reth execution extension, with
a revm-based simulator, so a candidate trade is priced against real chain state before it's ever sent.

## The parts that were actually hard

**Making fees comparable.** Every venue quotes fees differently, Uniswap V4 one way, Curve another,
Camelot in pips, some in Q64.96, some in 18-decimal fixed point. One break-even engine folds the
quoted fee, gas and priority into a single minimum-edge threshold, so venues compete on real cost,
not the headline number.

**A trap the docs hide.** I pin every venue to its deployed commit and check it against the live
bytecode. That's how I caught Camelot's directional fees living only on a non-`main` branch, anyone
pricing from `main` would have it wrong. That one finding is the reason I stopped trusting docs on
anything that touches money and started reading each venue from what's actually deployed.

**One adapter was the wrong idea.** My first plan was a single, pattern-based DEX adapter meant to
cover every venue. I built enough of it to test that assumption, and it didn't hold: the venues
differ in ways that matter down to the wei, and a generic layer quietly mis-prices them. I tore it
out and rebuilt around deep per-protocol integration. More work, but it's the difference between a
number that looks right and one that is right.

**A profitable system that still bleeds.** This is the one that surprised me most. A system can be
profitable on every single trade and still lose capital, because every trade keeps reusing the same
pot of money, gas included, and nothing is ever set aside. So I split inventory into three buckets,
principal, realized profit, and a gas reserve, and sweep profit above a threshold out to a separate
wallet. The gas reserve refills itself from profits based on recent spend, and trading stops when
the reserve runs low, not when the balance finally hits zero.

**Signing wasn't as fast as I assumed.** I'd budgeted sub-millisecond for 2-of-2 MPC signing. When I
actually measured it, it was 5 to 25 milliseconds over gRPC to the policy server. Rather than pretend
otherwise, I retired that target and rebuilt the latency budget around the real number, which changed
how much of the work I push ahead of time into simulation instead of the hot path.

**L1 and L2 are different games.** On L1 you sit in a public mempool and bid through PBS bundle
auctions (Flashbots, bloXroute). The L2s don't work like that at all: one sequencer, no public
pending pool, so there's nothing to sandwich. The competition there is latency and tips, plus
Arbitrum's Timeboost express-lane auction. Once that clicked, the execution strategy split cleanly by
layer instead of trying to be one thing everywhere.

**A gas-tuned executor (Quark).** No persistent storage, a compact opcode dispatch in an assembly
loop, calldata squeezed down hard, all run through throwaway CREATE2 pods that deploy, execute, sweep
and self-destruct (post-Dencun EIP-6780 behavior handled). One honest open thread: my measured
pod-lifecycle gas came in well above my first target, so it's flagged as something to resolve before
any live use, not quietly ignored.

## How I built it solo

I don't build autonomous agents, and I don't really trust them to run loose. What I do is build a
disciplined system around Claude and work inside it: my own rules, a staged pipeline (research,
architecture, planning, build, simulation), reusable skills for each subsystem, and hooks that keep
it in line. The gates are simple, no code without a plan, no plan without research, no claim without
a way to check it.

The spine of it is an assumptions ledger. Every claim the design leans on, a performance number, an
API's behavior, a fee, a chain quirk, gets written down with a concrete way to prove it wrong and a
status. 73 of them. When one turns out false it doesn't just get patched locally, it propagates back
through the architecture. Several of the stories above, the single-adapter idea, the signing timing,
the capital buckets, are ledger entries that flipped from "assumed" to "wrong" and forced a redesign.
That's the whole point: I'd rather find the wrong assumption myself, on my own machine, than have the
market find it for me.

## Where it stands

- Solo, private repo.
- 21 crates across 6 layers. Green workspace, 272 unit tests passing at the last build. Foundry
  contracts passing with a gas baseline.
- Tested in simulation with wei-exact fork sims per venue. Not run live.

Happy to walk through any of it on a call.
