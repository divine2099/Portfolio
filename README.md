# Jamike Divine

I'm an AI engineer. What that means for me is concrete: I build a disciplined system around Claude,
my own rules, staged pipelines, skills, hooks and subagents, and I use it to research, build, test and
ship large, correct software without drift and with everything documented. One person, systems that
would normally take a team.

I've pointed that same method at three things.

## How I build — the method

Not ad-hoc prompting, and not autonomous agents. A staged pipeline with hard gates (no code without a
plan, no plan without research, no claim without a verifier), an assumptions ledger that forces every
claim to carry a way to prove it wrong, hooks that block bad commits, and subagents for isolated
fan-out work. It's the same engine behind everything below.

[How I build →](method/README.md)

## Security — finding bugs with it

I turned the method into an audit pipeline: protocol-agnostic, coverage-driven, and honest about what
it can't prove. It found two Valid Highs, one on Sherlock and one on Code4rena, and on protocols
already reviewed by professional firms it re-found their bugs on its own, in hours instead of the weeks
the original audits took.

[The audit pipeline and findings →](security/README.md)

## Trading systems — building with it

Two large systems the method produced, both built and validated but not run live:

- **Polaris Omega**, a cross-chain market-making and arbitrage system in Rust, 21 crates across Base,
  Arbitrum, Optimism and Ethereum, 272 tests.
- **model_blueprint**, a Python-first quant-ML system, 51 modules, 427 tests at 100% line and branch
  coverage, built on the López de Prado stack with a leakage-free validation harness.

[The systems walkthrough →](trading/README.md)

## Elsewhere

- Résumé: [resume.md](resume.md)
- GitHub: https://github.com/divine2099
- Email: kelbottumm@gmail.com
- Telegram: https://t.me/Hatesky06
