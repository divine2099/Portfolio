# Systems I build

I don't only break systems, I build them, in Rust, at the source level, with the same
discipline as the audit work: read the source, trust the bytecode over the docs, prove
every claim with a harness.

## Polaris Omega

A cross-chain market-making and arbitrage system I wrote in Rust, solo, across Base,
Arbitrum, Optimism and Ethereum. Kalman-filtered pricing with an Avellaneda-Stoikov
spread and inventory model, flash-funded execution that turns a profit or reverts, a
gas-tuned on-chain executor, and a risk layer of circuit breakers, position limits and
segregated inventory. Every venue is pinned to its deployed commit and checked against
live bytecode. Built and tested in simulation, private repo.

Full walkthrough: [polaris-omega.md](polaris-omega.md).
