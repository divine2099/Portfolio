# Jamike Divine

I audit smart contracts, and I build the systems that trade on them. The same habits run
through both: read the source, trust the bytecode over the docs, prove every claim with a
harness.

## Security research

I audit smart contracts across six languages and six competitive platforms: lending, AMMs,
RWA, restaking, bridges, oracles, stablecoins. The core is an AI-assisted audit process I
built over the past year, with a four-check gate that kills a weak finding before it gets
submitted. On protocols already reviewed by firms like Spearbit and Quantstamp, it re-found
their bugs on its own, and turned up new ones sitting inside the patches.

[Findings and how I work →](audit/README.md)

## Systems I build

Polaris Omega is a cross-chain market-making and arbitrage system I wrote in Rust, solo,
across Base, Arbitrum, Optimism and Ethereum. Kalman-filtered pricing with an
Avellaneda-Stoikov spread and inventory model, flash-funded execution that turns a profit
or reverts, and a strategy tuned to each chain's ordering rules. Built and tested in
simulation with wei-exact fork sims.

[Systems walkthrough →](systems/README.md)

## Elsewhere

- Code4rena: https://code4rena.com/@white-fox02
- Sherlock: https://audits.sherlock.xyz/watson/eat-the-sky
- GitHub: https://github.com/divine2099
- Résumé: [resume.md](resume.md)
