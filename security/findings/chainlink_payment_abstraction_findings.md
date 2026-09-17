# Chainlink Payment Abstraction — Two zero-role external chains that stall settlement

**Code4rena · Solidity / EVM · ~Mar 2026 · public competitive contest**

## Summary

This was the most exhaustive audit I have run. Thirteen non-overlapping mental models over a fee-auction plus CoW-settlement pipeline, each with its own state-space and property set, then a top-down pass that maps attack chains back onto the vulnerabilities the model-by-model view produces. That structure surfaces two findings *no single model can see*, because each is a chain: an unprivileged, no-role actor stalling the whole settlement pipeline from outside the contract's trust model. I call them Chain G (Oracle-Freeze DoS) and Chain H2 (Mempool-Blocking). I self-rated both around Critical. These are self-authored, self-rated write-ups from the research corpus. The source records no external judged outcome, so I state them as my own assessment.

## The bug

The RBAC matrix here is genuinely tight. Thirteen roles across three tiers, and in the deployed config most operational roles (`SWAPPER`, `AUCTION_BIDDER`, `PRICE_ADMIN`, `ORDER_MANAGER`) are granted to *contracts* (`WorkflowRouter`, the auction), not humans. Both chains matter because they bypass that matrix: neither needs any on-chain role. They attack the external dependencies the on-chain logic strictly trusts.

**Chain G — Oracle-Freeze DoS.** Every bid flows through a strict staleness check with no fallback. `AuctionBidder.bid` (`src/AuctionBidder.sol:65-92`) delegates to `BaseAuction.bid` (`src/BaseAuction.sol:410-458`), which fetches price with validation on:

```solidity
// BaseAuction.sol:429 — withValidation = true
(uint256 assetPrice,,) = _getAssetPrice(asset, true);
```

`PriceManager._getAssetPrice` (`src/PriceManager.sol:372-419`) tries Chainlink Data Streams, falls back to the Data Feed, then hard-reverts on staleness (with validation on):

```solidity
// PriceManager.sol:414
if (isStale) { revert Errors.StaleFeedData(); }
```

Both price sources ride the same Chainlink DON. An attacker who DDoSes the DON (Chain G estimates ~$500–$2,000/hour) stops updates on *both* channels at once. Once `updatedAt` falls behind `block.timestamp - stalenessThreshold` (default ~300s), every `bid()` reverts with `StaleFeedData()`. The same validation is invoked in settlement/upkeep, so the freeze doesn't just block new bids. It stalls the pipeline, with no internal recovery, because the protocol has no emergency price path. There's also an economic kicker: competition elimination. The attacker monitors recovery and lands the first bid after the oracle resumes.

**Chain H2 — Mempool-Blocking.** The auction is first-valid-bid-wins with no second-price or pro-rata mechanism (`DutchAuction._bid`: `require(auction.bidder == address(0), "Already bid")`, winner-take-all). That makes bid inclusion itself the attack surface. The most viable variant, H2A (front-running monopoly), needs only MEV infra (~$500–$5k/month): monitor the mempool, detect competitors' `bid()` txs, and front-run with higher priority to win every high-value auction. Other variants trade cost for selectivity: spam-flooding block space (H2B), revert-bombing (H2C), builder collusion (H2D). H2A is notable for being *legal* (MEV is tolerated) where Chain G's DDoS is not.

Both are documented with full attack-flow diagrams, cost-benefit analysis, detection signals, and mitigations (emergency/multi-oracle fallback and a staleness grace period for G; commit-reveal or batch/Vickrey auction for H2).

## Impact & severity

Self-rated **Critical** for each on availability grounds: complete or auction-selective stalling of the settlement pipeline, funds locked in active auctions, and systematic competition elimination that converts the DoS into direct economic extraction. Two honest caveats. Both are infrastructure-level, not a bug in a specific line of Solidity but a missing defense against a trusted dependency failing. And the "Critical" rests on the protocol having *no* fallback; the mitigation is architectural (add an emergency oracle / degradation mode; add commit-reveal or batch auctions). Contest severity for infrastructure/DoS findings is frequently contested, and I flag that here rather than assume it.

These are worth surfacing because of the composition point. **G and H2 are synergistic**: freeze the oracle to block all bidders, then front-run the instant it recovers. Neither is visible model-by-model. The oracle-fallback model sees a staleness revert. The auction model sees first-bid-wins. Only chaining them shows a no-role actor with a guaranteed auction monopoly. That chained view is what these two findings are about.

## Status

**Self-authored / self-rated (Critical), from the research corpus. Unreconciled and unjudged.** I want to be precise about where the Critical comes from, because my own model-by-model pass does not say it. In that pass (the per-model integration view), the constituent pieces are rated **Low**. The dual-oracle staleness cascade is logged as *Low / mitigated*: the `withValidation` revert is treated as the SP-7 stale-price protection working as designed. Mempool front-running appears only as a *Low / operational* pause-front-running note. So the **Critical** rating is my *composition-level* reinterpretation, written up in the dedicated chain files (`attack_chain_g_oracle_freeze_dos.md`, `attack_chain_h2_mempool_blocking.md`) on top of the top-down `attack_chains_no_trusted_role.md` mapping. It reads the same staleness revert as an availability DoS with no fallback rather than a safety check firing. That corpus records **no external judged disposition and no reconciliation against the README or past audits** (there was no scope-gate / prior-art pass run here at all), so I present these strictly as my own assessment, not an awarded, confirmed, or reconciled result. The value I claim is methodological: an exhaustive model-by-model sweep that then *composes* its own outputs into zero-role chains the individual models cannot express. The honest caveat is that the Critical severity is my chained argument, not the model-by-model rating and not a judge's.
