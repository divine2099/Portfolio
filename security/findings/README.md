# Findings

Recent contest work. The two Valid Highs are first. Everything after them is honest process work, and
where a finding was self-rated, ruled a duplicate, lost an escalation, or where I chose not to submit
at all, it says so. Verdicts here are never dressed up.

## Valid Highs

| Protocol | Platform | Language / VM | What I found |
|---|---|---|---|
| [**Olas**](olas.md) | Code4rena | Solidity · EVM | A manipulation guard that built its TWAP from the current spot price, so the check always passed. Manipulate, wait a block, drain. **Valid High.** |
| [**Current Finance**](current-finance.md) | Sherlock | Sui · Move | Liquidation validated on the EMA price but seized collateral at the spot price; the divergence lets a liquidator over-seize or liquidate a healthy position. **Valid High.** |

## The fuller record (honest verdicts)

| Protocol | Platform | Language / VM | What I found | Verdict |
|---|---|---|---|---|
| [**Chainlink Payment Abstraction**](chainlink_payment_abstraction_findings.md) | Code4rena | Solidity · EVM | Two zero-role chains that stall settlement, visible only by composing findings across models. | Self-rated, unreconciled, unjudged |
| [**Monetrix**](montrix_findings.md) | Code4rena | Solidity · EVM (Hyperliquid) | Every public entry point traced backward through every auth gate; a stale-registry asymmetry that permanently freezes yield settlement. | Submitted |
| [**Morpho Midnight**](morpho_findings.md) | Cantina | Solidity · EVM | An opcode-level DoS (High) plus creator-config Highs; and a cross-contract reentrancy I debunked with my own PoC. | Submitted; one self-debunked |
| [**dreUSD**](dreusd_findings.md) | Sherlock | Solidity · EVM (Base) | In-band depeg extraction, plus a 48-finding reconciliation against prior Spearbit and Quantstamp audits. | Ruled a duplicate, escalated |
| [**Confidence Pools**](confidence_pools_findings.md) | Cyfrin / CodeHawks | Solidity · EVM | Every attack chain I built broke on a real guard; I kept the ledger showing where each one died. | Zero-submit (by choice) |

Back to [the security overview](../README.md).
