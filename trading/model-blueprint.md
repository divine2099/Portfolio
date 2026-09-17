# model_blueprint

model_blueprint is a quantitative-ML trading system I built in Python, with a Rust runtime and C++
decoders where latency mattered. The repo is private, so this is the walkthrough. It's built on Marcos
López de Prado's *Advances in Financial Machine Learning* plus current state-of-the-art from 2025 and
2026. The MVP inner-shell funnel is code-complete and audited. It is not run live, no live trading and
no real capital.

I'll explain it the way I'd explain it on a call: the one belief the whole thing is built around, the
pipeline, and what's actually done versus what isn't.

## The belief it's built around

The default outcome of any well-meaning quant effort is to fool yourself. A backtest that looks great
is the expected result of trying hard, not evidence of an edge. So the order of work is backwards from
how most people do it. I built and stress-tested the validation and honesty harness first, and only
then let it judge any strategy. Nothing gets to claim it works until the harness that would catch a lie
has already been trusted.

That's not just a principle here, it's enforced. A pre-commit hook blocks a commit that reports a
Sharpe with no Deflated Sharpe next to it, and blocks a file that does math but cites nothing from the
knowledge vault.

## The pipeline

The inner shell is a funnel, each stage feeding the next:

- **Information-driven bars.** Sample by information, not by the clock.
- **Fractional differentiation.** Make the series stationary while keeping as much memory as possible.
- **Cost-aware triple-barrier labeling.** Label outcomes against profit-taking, stop-loss and time
  barriers, with trading costs folded in.
- **A leakage-free validation harness.** Purged and embargoed cross-validation, combinatorial purged CV
  (CPCV), the Deflated Sharpe ratio, the probability of backtest overfitting (PBO), and the
  probabilistic Sharpe ratio (PSR). This is the piece that's built and trusted first.
- **Symbolic / genetic-program alpha mining.** Search for candidate signals.
- **HRP clustering.** Hierarchical risk parity to structure the book without inverting a noisy
  covariance matrix.
- **A GBDT ensemble.** LightGBM and CatBoost with monotone constraints and calibrated outputs.
- **Non-linear meta-label bet sizing.** A second layer that sizes the bet, rather than just calling
  direction.
- **A fill simulator**, then a deterministic outer shell in Rust, then shadow training.

## The research behind it

The stage-one research swept every modeling topic in the system using the arxiv MCP and a dedicated
research subagent, reading the actual papers before anything was built. That's the knowledge-vault rule
at work: no formula in the code comes from memory, each one is cited from a source that was read.

## Where it stands

- 51 Python modules. 427 tests, 100% line and branch coverage on every module.
- Validated on the honesty harness.
- MVP inner-shell funnel code-complete and audited.
- Not run live. No live trading, no real capital.

Happy to walk through any of it on a call.
