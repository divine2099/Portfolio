# Security Findings — Jamike Divine

Competitive-audit findings I've distilled into focused write-ups. Each opens with how I actually came at the work, then gives the mechanism, honest severity gating, and a plainly-stated disposition. No inflated awards. Duplicates, rejected escalations, and disciplined zero-submits are called out as exactly that. All are public competitive contests (Sherlock, Code4rena, Cantina, and Cyfrin/CodeHawks), public after judging.

| Protocol | Platform | Language/VM | Focus | Report |
|---|---|---|---|---|
| Chainlink Payment Abstraction | Code4rena | Solidity / EVM | Two zero-role external chains (oracle-freeze DoS + mempool-blocking) that stall the settlement pipeline; chained findings the model-by-model view can't see | [chainlink_payment_abstraction_findings.md](chainlink_payment_abstraction_findings.md) |
| Monetrix | Code4rena | Solidity / EVM (Hyperliquid) | External-reachability map of a Hyperliquid yield-layer vault; every public entry point traced through its authorization barriers | [montrix_findings.md](montrix_findings.md) |
| Morpho Midnight | Cantina | Solidity / EVM | Fixed-rate lending review; a High opcode-level DoS (non-Osaka `clz` reverts brick health checks, liquidations and bad-debt realization protocol-wide), creator-config Highs (oracle / blocking `liquidatorGate` / isolation-crossing fee-on-transfer), and a self-debunked cross-contract reentrancy | [morpho_findings.md](morpho_findings.md) |
| dreUSD | Sherlock | Solidity / EVM (Base) | In-band depeg extraction via a frozen redemption quote, plus a 48-finding reconciliation against prior Spearbit + Quantstamp audits; submitted, ruled duplicate, escalated | [dreusd_findings.md](dreusd_findings.md) |
| Confidence Pools | Cyfrin / CodeHawks | Solidity / EVM | A disciplined zero-submit — every attack chain built broke on a real guard; the honest negative and the Blocked Compositions ledger | [confidence_pools_findings.md](confidence_pools_findings.md) |
