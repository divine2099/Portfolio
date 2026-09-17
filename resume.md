# Jamike Divine

AI Engineer · Smart-Contract Security · Quant Systems
Remote (based in Nigeria) · kelbottumm@gmail.com · Telegram t.me/Hatesky06 · GitHub github.com/divine2099

## Summary

AI engineer who builds large, correct software solo by running a disciplined system around Claude:
staged pipelines with hard gates, my own rules and skills, Python hooks that block bad commits,
subagents for isolated work, and an assumptions ledger where every claim carries a way to prove it
wrong. The same method has produced a 21-crate Rust cross-chain trading system, a 51-module Python
quant-ML system, and a smart-contract audit pipeline that has found two Valid High vulnerabilities in
public contests. Open to remote AI-engineering, security-research and quant roles.

## Skills

AI engineering: Claude Code system design (skills, rules, hooks, subagents, staged pipelines,
assumptions ledgers, knowledge vaults), MCP tools including arxiv, prompt-to-pipeline workflows.
Languages: Rust, Solidity, Python, C++ (latency-critical); reading knowledge of Move, Go, Solana.
Smart-contract security: EVM and non-EVM auditing, oracle and price-manipulation analysis, invariant
extraction, PoC development, differential and invariant fuzzing, Foundry, Anchor.
DeFi: Uniswap V4, Balancer V3, Curve, Aerodrome, Camelot, Aave V3, deBridge, flash loans, atomic
arbitrage, AMM and concentrated-liquidity pricing math.
Systems and infra: reth (ExEx, MDBX), revm, tokio, alloy, openraft, tonic/gRPC, MPC signing.
Quant/ML: Kalman filtering, Avellaneda-Stoikov, the López de Prado stack (information bars, fractional
differentiation, triple-barrier and meta-labeling, purged CV, CPCV, Deflated Sharpe, HRP, GBDT
ensembles with LightGBM and CatBoost).

## Experience

Independent AI Engineer and Security Researcher, remote, 2024 to present
- Build a disciplined AI system around Claude (rules, staged pipelines, skills, hooks, subagents) that
  lets one person research, build, test and ship complex software without drift and fully documented.
- Built a protocol-agnostic, coverage-driven smart-contract audit pipeline plus a four-gate validity
  pass that kills weak findings before submission.
- Found two Valid High vulnerabilities using the pipeline: an oracle that built its TWAP from spot
  (Olas, Code4rena) and an inconsistent dual-source price feed (Current Finance, Sherlock).
- On protocols already reviewed by firms including Spearbit and Quantstamp, the pipeline re-found their
  bugs independently, matching in hours vulnerabilities the prior audits took up to a month to find.
- Competed on Sherlock, Code4rena, Cantina and Cyfrin/CodeHawks, plus private engagements under NDA.

## Projects

Polaris Omega — cross-chain market-making and arbitrage system (Rust, solo), 2025 to present
- 21-crate Rust workspace across Base, Arbitrum, Optimism and Ethereum; runs as a reth execution
  extension with a revm simulator. 272 unit tests passing; Foundry-tested Solidity executor.
- Kalman-filter and Avellaneda-Stoikov pricing; one break-even engine normalizing venue fees into a
  single minimum-edge threshold; flash-funded profit-or-revert execution; circuit breakers, capital
  tiers, segregated inventory, 2-of-2 MPC signing.
- Built and validated in simulation with wei-exact fork sims. Not run live.

model_blueprint — quant-ML trading system (Python, Rust runtime, C++ decoders)
- 51 modules; 427 tests at 100% line and branch coverage; built on the López de Prado stack with a
  leakage-free validation harness (purged/embargo CV, CPCV, Deflated Sharpe, PBO, PSR).
- Honesty-harness-first design: the validation harness is built and trusted before any strategy result.
  Code-complete and audited MVP. Not run live.

## Education

BSc, Biochemistry, University of Nigeria, Nsukka. Self-taught in security, systems, DeFi, quant and
AI-assisted engineering.
