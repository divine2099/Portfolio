# Systems I build

I don't only break systems, I build them. Two large ones, both produced with the
[method](../method/README.md), both built and validated but not run live with real money. Same
discipline as the audit work: read the source, trust the bytecode over the docs, prove every claim
with a harness, and write down every assumption with a way to prove it wrong.

## Polaris Omega — cross-chain market-making and arbitrage (Rust)

A cross-chain market-making and arbitrage system I wrote in Rust, solo, across Base, Arbitrum, Optimism
and Ethereum. It runs co-resident with the node as a reth execution extension with a revm simulator, so
a candidate trade is priced against real chain state before it's ever sent. Kalman-filtered pricing
with an Avellaneda-Stoikov spread and inventory model, one break-even engine that normalizes every
venue's fees into a single minimum-edge threshold, flash-funded execution that turns a profit or
reverts, and a risk layer of circuit breakers, capital-tier limits and segregated inventory. 21 crates,
272 unit tests passing, a Foundry-tested Solidity executor. Built and validated in simulation with
wei-exact fork sims.

[Full walkthrough →](polaris-omega.md)

## model_blueprint — quant-ML trading system (Python)

A Python-first quantitative-ML system built on López de Prado's *Advances in Financial Machine
Learning* plus 2025-2026 state-of-the-art. The MVP inner-shell funnel is code-complete and audited:
51 modules, 427 tests at 100% line and branch coverage on every module, validated on its own honesty
harness. Not run live. The whole thing is built around one belief, that the default outcome of any
well-meaning quant effort is to fool yourself, so the leakage-free validation harness is built and
trusted before any strategy result is believed.

[Full walkthrough →](model-blueprint.md)

## Elsewhere

- How the method is built: [../method/README.md](../method/README.md)
- The security work: [../security/README.md](../security/README.md)
- GitHub: https://github.com/divine2099
