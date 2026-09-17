# How I build

The thing I actually do is build a disciplined system around Claude and work inside it. Not ad-hoc
prompting, and not autonomous agents left to run loose. A person drives it. The system is a set of
rules, staged pipelines, skills, hooks and subagents that let one engineer research, design, build,
test and ship large, correct software without drift, with everything written down and traceable.

The point of every mechanism below is the same: stop me from fooling myself, and make sure what comes
out is correct and documented, not a pile of code that looks right. The method doesn't care what it's
building. It produced a 21-crate Rust cross-chain trading system, a 51-module Python quant-ML system,
and the audit pipeline I find bugs with. Same method, three very different domains.

## The gates

Nothing starts until the thing before it exists.

- No code without a plan.
- No plan without research.
- No claim without a verifier.

A build runs through ordered stages and a stage can't open until the prior artifact is on disk:
research, then library and crate evaluation, then architecture, then a component index, then config
design, then implementation plans, then test plans, then the build, then validation, then a
per-component audit, then integration, then simulation, then deploy. If the research note for a stage
isn't written, the stage doesn't run.

## The mechanisms

**Skills.** Per-stage and per-subsystem quality standards, loaded only when they're needed. A large
build carries around twenty of them. The right conventions and constraints sit in front of the model
at the moment they matter, instead of hoping it remembers a rule from an hour ago.

**Rules.** The stage-order gates, coding conventions and subsystem constraints, written as rules the
work has to pass, not suggestions.

**Hooks.** Python hooks that enforce discipline instead of just describing it. On the quant system, a
pre-commit hook blocks a commit if a file does math but cites nothing from the knowledge vault, or if
it reports a Sharpe with no Deflated Sharpe next to it. A session-start hook prints where we stopped
last time, so every session resumes oriented instead of guessing. Hooks fail open: a bug in a hook
never wedges the work.

**Subagents.** Isolated-context agents for fan-out work, each with one job and its own clean context:
a research agent that reads papers and source, a library deep-diver, a component auditor that reviews
one built component alone so it can't wave through a problem because it wrote the code.

**The assumptions ledger.** This is the spine. Every claim the design leans on, a performance number,
an API's behavior, a fee, a chain quirk, gets written down with a concrete way to prove it wrong and a
status: assumed, verified, or falsified. Assumptions are re-checked on purpose, and when one turns out
false it's retracted on the record, then propagated back through the architecture instead of patched
locally. On the trading system, 69 of these were tracked. Several of them flipped from "assumed" to
"wrong" and forced real redesigns. I'd rather find the wrong assumption on my own machine than have
the market or an attacker find it for me.

**Filesystem is the source of truth.** The real structural truth lives in per-component mapping files
on disk, not in the chat history. Knowledge is written down and retrieved on demand, so nothing
important depends on what happens to still be in a context window.

**The knowledge vault, no math from memory.** Every formula in the code is cited from a knowledge
entry. Generating a formula from memory is treated as a defect, not a shortcut. If the code prices
something, the source of that math is written down and linked.

**Slash commands.** The routine moves are commands: run a stage on a component, print status, audit a
component, promote work forward. Same operation every time, no improvising the process.

**Carry-forward.** On a redesign, prior work is repointed, never deleted. Nothing verified gets thrown
away because the shape changed.

## What this is not

I want to be straight about the edges of it. This isn't machine-learning research. I'm not training
models from scratch or writing papers. And the deliverable is the method and the systems it builds,
not a hosted product with users and uptime. What it is: a way for one person to build big, correct,
fully documented systems, fast, and to know which parts are proven and which parts aren't.

## What it has built

- **[The audit pipeline](../security/README.md)** — the method turned into a security workflow that
  finds vulnerabilities fast. Two Valid Highs on Sherlock and Code4rena came out of it.
- **[Polaris Omega](../trading/polaris-omega.md)** — a 21-crate Rust cross-chain market-making and
  arbitrage system, 272 tests, built and validated in simulation.
- **[model_blueprint](../trading/model-blueprint.md)** — a Python-first quant-ML system, 51 modules,
  427 tests at 100% line and branch coverage, validated on its own honesty harness.
