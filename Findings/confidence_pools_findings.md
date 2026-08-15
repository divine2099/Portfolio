# Confidence Pools — A disciplined zero-submit

**Cyfrin / CodeHawks · Solidity / EVM · ~Jul 2026 · public competitive contest**

## Summary

Not every audit ends with a finding, and this one is here precisely because it didn't. Confidence Pools is a Safe-Harbor staking protocol. Stakers back an on-chain agreement, and a moderator plus an external attack registry decide whether the pool SURVIVED, EXPIRED, or was CORRUPTED. I built every high-value attack chain I could assemble against it, and every one broke on a real guard. The most severe genuine issue I could stand behind was a Low. The value of this write-up is the honest negative: I looked hard, and here is exactly where each chain died. That falsification discipline, refusing to submit chains I had already proven un-assemblable, is what I want to show, not a shortfall.

## What I built and why nothing shipped

The codebase is heavily latched and its trust boundaries are tight. My composition pass over the model-by-model findings (76 properties HOLDS, 1 BROKEN, 2 UNCERTAIN) reached a blunt headline: **no composition promotes anything to High/Critical, and there is no in-model chain that drains staker *principal*.** Every principal-loss path requires a trusted-role failure (an absent or hostile moderator), and every such path is explicitly design-accepted in the project's own 13-section DESIGN.md.

**The one thing worth reporting** was `registry_observation_risk_window-EXT-1` (Low): if a pool's active-risk interval passes with *zero* interaction, `riskWindowStart` is never armed, so at resolution `_bonusShare` (`ConfidencePool.sol:699`) pays zero and `sweepUnclaimedBonus` (`:474`) routes the whole bonus pool to the sponsor's `recoveryAddress`. It is the sole BROKEN invariant (`P-registry_observation_risk_window-9`) and needs no role, token assumption, or misconfig. Pure permissionless timing. But DESIGN §5 documents the exact behavior verbatim ("`_bonusShare` pays zero, so the bonus pool sweeps to `recoveryAddress`"), §7 reaffirms the pay-zero destination as intentional, and §9 gives the fairness rationale (an open withdraw hatch for the whole pre-attack window). Under the contest's own severity criteria, an explicitly-considered-and-accepted design decision is by-design → drop, not a downgraded finding. Escalating it means arguing the design itself is wrong, which is a design opinion, not a vulnerability.

**The Blocked Compositions ledger** is the real deliverable: the High/Critical chains I deliberately assembled and the exact latch that severs each:

- **BC-1 — Redirect staker principal to an attacker EOA (target Critical).** Breaks at `flagOutcome:322` (`onlyModerator` + requires registry `== CORRUPTED` + a non-extendable good-faith timestamp). No untrusted path names the attacker; needs moderator collusion on a *genuine* breach, outside the live-adversary model.
- **BC-2 — Re-flag a resolved pool to reroute funds after value moved (target High).** Breaks at `claimExpired:549`, which sets `claimsStarted = true` *before* returning, so a follow-up `flagOutcome` reverts `OutcomeAlreadySet`.
- **BC-3 — Accumulator desync via stake→risk-open→withdraw (target High).** Breaks at `withdraw:290`: its own `_observePoolState` arms `riskWindowStart` under active-risk and the gate then reverts, so `withdraw` only completes while `riskWindowStart == 0`, where the per-user subtraction is the exact inverse of the global. The desync state is unreachable.
- **BC-4 — Over-draw bonus past snapshot via clamp-detector spoofing (target High).** Breaks at `stake:244`, which clamps *before* every add (and `nonReentrant` blocks a hook from interleaving), so a mixed un-clamped position is never constructed; `mulDiv` rounds down; `claimedBonus ≤ snapshotTotalBonus` holds.
- **BC-5 — Donation across the snapshot/live boundary to pull reserved funds (target Medium).** Breaks at `sweepUnclaimedBonus:482-492`, which reserves stake + owed bonus before sweeping only excess, with CORRUPTED sweeps outcome-partitioned from it.
- **BC-6 — Bounty over-claim / partial-payout re-entry (target High).** Breaks at `claimAttackerBounty:442`: `payout = min(remaining, freeBalance)` + monotone `bountyClaimed += payout` + `nonReentrant`; donations cap, never raise, the payout.

The handful of chains that *did* materialize (G13-1 sweeping principal on an out-of-scope breach with a 180-day-absent moderator; G5-1 an absurd-supply allowlisted token overflow-bricking resolution) each top out at Low/Info and each require an accepted trust-model precondition (moderator dereliction or an owner allowlist error) that the composition cannot remove.

## Impact & severity

Maximum genuine issue: **Low** (the observation-timing bonus redirect), and even that is design-accepted. No principal-loss chain exists inside the live-adversary model. The scope-gate pass (`unreported_findings.md`) walked all 11 integration-vector findings and all 6 chains against DESIGN.md / README / severity criteria and gated every one out: by a documented token assumption, a trusted-role default, an explicit by-design acceptance, or a severity-rule disqualifier.

## Status

**Disciplined zero-submit.** Zero submittable findings after the scope gate; the target ships with a DESIGN.md written to pre-empt exactly this finding surface, and my independent analysis confirmed it (76 HOLDS, 1 BROKEN, 2 UNCERTAIN; the BROKEN and both UNCERTAIN each explicitly documented as intentional or excluded). My recommendation to myself was: do not submit. I record it here as a strength. The same rigor that finds a live double-spend elsewhere is what lets me say, with receipts, that here there was nothing to find.
