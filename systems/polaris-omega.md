# Polaris Omega

Polaris Omega is a cross-chain market-making and arbitrage system I built in Rust, on my
own, across Base, Arbitrum, Optimism and Ethereum. It's a personal project and the repo is
private, so this is the walkthrough. It's built and tested in simulation, not run live with
real money.

## What it is

Capital sits pre-positioned on each chain and gets rebalanced synthetically, so no bridge is
ever in the critical path. Trades are flash-funded and either turn a profit or revert, so a
bad fill costs gas, not principal. Pricing runs on a Kalman filter with an Avellaneda-Stoikov
spread and inventory model. It runs co-resident with the node as a Reth execution extension,
with a revm-based simulator so candidate trades are priced against real state before they're
sent.

## What's in it

**Fees, made comparable.** Every venue quotes fees differently, Uniswap V4 one way, Curve
another, Camelot in pips, some in Q64.96, some in 18-decimal fixed point. One break-even
engine folds the quoted fee, gas and priority into a single minimum-edge threshold, so venues
compare on real cost, not the headline number.

**A trap the docs hide.** I pin every venue to its deployed commit and check it against the
live bytecode. That's how I caught Camelot's directional fees living only on a non-`main`
branch, anyone pricing from `main` would have it wrong.

**A gas-tuned executor (Quark).** No persistent storage, a 4-bit opcode dispatch in an
assembly loop, calldata squeezed to 1-byte venue indices and 3-byte amounts, run through
throwaway CREATE2 pods that deploy, execute, sweep and self-destruct (post-Dencun EIP-6780
behavior handled).

**Flash funding by real fee math.** The cheapest source wins, Balancer's zero fee first,
then Aave's premium, then Uniswap, all composed profit-or-revert.

**Risk that keeps the book alive.** Circuit breakers on drawdown, skew, gas, lag and
timeout. Capital-tier position limits. An island mode for when a chain goes bad. Inventory
split into buckets, principal, realized P&L, gas reserve. Keys behind 2-of-2 MPC signing.

**Per-chain edge.** L1 goes through PBS bundle auctions (Flashbots, bloXroute); the L2s
don't. Base and Optimism order on priority fee, Arbitrum is FCFS with the Timeboost express
lane, and flashblocks stream ~200ms sub-blocks. The strategy shifts on each one.

## How I built it solo

I designed an AI-assisted pipeline to do the heavy lifting, staged from research through
architecture, planning, build and simulation, with hard gates: no code without a plan, no
plan without research, no claim without a way to check it.

What keeps it honest is a ledger of every assumption, 73 of them, each with a way to prove it
wrong and a status. When one turns out false it propagates through the design instead of
quietly rotting. That happened for real: I assumed a single pattern-based approach could
cover all DEXs, tested it, found it didn't hold, and rebuilt around deep per-protocol
integration.

## Where it stands

- Solo, private repo.
- 21 crates across 6 layers. Green workspace, 272 unit tests passing at the last build.
  Foundry contracts passing with a gas baseline.
- Tested in simulation with wei-exact fork sims per venue. Not run live.

Happy to walk through any of it on a call.
