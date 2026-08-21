# Findings Report — Monetrix Protocol

## Trust model — actors and entry points

The protocol has five privilege classes. Reachability analysis must be measured against this hierarchy:

| Class | Access path | Delay |
|---|---|---|
| **External attacker** | Any EOA / contract — no role | none |
| **OPERATOR** | bot key holding `OPERATOR` role | none (instant) |
| **GUARDIAN** | multisig holding `GUARDIAN` role | none (pause is instant) |
| **GOVERNOR** | timelock holding `GOVERNOR` role | 24h queue |
| **UPGRADER** | timelock holding `UPGRADER` role | 48h queue |

**Externally callable entry points** (no role required):

| Function | Contract | Pause guards | Reentrancy guard |
|---|---|---|---|
| `deposit(uint256)` | `MonetrixVault` | Vault `whenNotPaused` | `nonReentrant` |
| `requestRedeem(uint256)` | `MonetrixVault` | Vault `whenNotPaused`, `requireWired` | `nonReentrant` |
| `claimRedeem(uint256)` | `MonetrixVault` | Vault `whenNotPaused`, `requireWired` | `nonReentrant` |
| `deposit(uint256, address)` | `sUSDM` | sUSDM `whenNotPaused` | `nonReentrant` |
| `mint(uint256, address)` | `sUSDM` | sUSDM `whenNotPaused` | `nonReentrant` |
| `cooldownShares(uint256)` | `sUSDM` | sUSDM `whenNotPaused` | `nonReentrant` |
| `cooldownAssets(uint256)` | `sUSDM` | sUSDM `whenNotPaused` | `nonReentrant` |
| `claimUnstake(uint256)` | `sUSDM` | sUSDM `whenNotPaused` | `nonReentrant` |
| `deposit(uint256)` | `InsuranceFund` | none | none |
| `transfer/approve/transferFrom` | USDM, sUSDM | own `_paused` | n/a |

Every other state-mutating function gates on `onlyOperator`, `onlyGovernor`, `onlyGuardian`, or `onlyUpgrader`.

---

## PART 1 — EXTERNALLY EXPLOITABLE VULNERABILITIES

These vectors can be reached via the public entry points listed above without requiring any role. Each one is traced backward from the unsafe primitive to confirm reachability.

### EX1 — Pending-redemption USDM occupies TVL cap

**Sink:** `MonetrixVault.deposit` L176 — `require(usdm.totalSupply() + amount <= maxTVL)`.

**Backward trace from sink to attacker:**
1. `usdm.totalSupply()` includes USDM held by Vault during pending redemption. USDM is not burned at `requestRedeem` — only at `claimRedeem`.
2. Any external user holding USDM can call `requestRedeem(X)` (public, only modifiers are `nonReentrant + whenNotPaused + requireWired` — all reachable).
3. The USDM transfer to Vault leaves `totalSupply` unchanged; the TVL bookkeeping treats it as still in circulation.
4. At capacity, an attacker who owns USDM can repeatedly request redemption to inflate the count seen by `deposit`, blocking other users for the cooldown period (`config.redeemCooldown`, default 3 days).

**Reachability:** **YES — externally reachable.** No privileged role required; only requirement is owning USDM (acquired via `deposit` or open market).

**Cost:** attacker's USDM is locked in Vault for the cooldown window. After cooldown they can claim it back, paying only gas + opportunity cost for the locked duration. They can recycle: deposit → request → claim → deposit → request to keep TVL saturated.

**Severity: MEDIUM** — DoS on issuance, no theft. Mitigation requires `maxTVL` increase (24h GOVERNOR action) or accepting that pending redemptions count toward cap.

---

### EX2 — sUSDM front-run yield injection

**Sink:** `sUSDM.injectYield(amount)` — increases `totalAssets` without minting shares; rate ratio rises proportionally to the depositor's `shares / totalSupply`.

**Backward trace:**
1. `injectYield` is `onlyVault` — direct call gated.
2. But it is invoked synchronously from `MonetrixVault.distributeYield`, which is `onlyOperator` — operator submits the tx publicly via mempool.
3. Any external observer of the mempool can race a `sUSDM.deposit(X, attacker)` (public, `nonReentrant + whenNotPaused`) ahead of the operator's `distributeYield`.
4. Their share post-injection earns yield proportional to `X / (oldSupply + X)`.

**Reachability:** **YES — externally reachable.** No role; uses standard mempool front-running.

**Magnitude:** bounded — attacker captures only their proportional slice, not the full yield. Front-runner depositing X into a pool of size S captures `X / (S + X)` of yield. Over many cycles this is a real if small extraction. Confirmed by test `test_attack_frontRunYieldInjection`.

**Severity: LOW** — yield dilution, not theft. Standard MEV; private mempool / encrypted submission would mitigate.

---

### EX3 — sUSDM donation inflation attack

**Sink:** ERC4626 share/asset rounding at first deposit when `totalSupply == 0`.

**Backward trace:**
1. First depositor mints `X` shares for `X` USDM.
2. Attacker (could be the first depositor) calls `usdm.transfer(sUSDM, Y)` directly, inflating `totalAssets` without minting shares.
3. Subsequent depositor's `previewDeposit(small)` rounds to 0 shares; their USDM is captured by the donor's existing shares.

**Reachability:** **YES — externally reachable** for any sUSDM with low TVL.

**Mitigation in place:** OZ ERC4626 v5 `_decimalsOffset() = 6` provides 10⁶ virtual share offset. To fully dilute a 1-wei first deposit, the attacker must donate ≥ 10⁶ USDM (~$1) — economically meaningful but not impossible. Once TVL grows past ~10⁶ USDM, the offset becomes irrelevant.

**Severity: LOW** — partially mitigated; high attack cost relative to expected gain. Confirmed by `test_attack_donationToSUSDM` and `test_attack_firstDepositorInflation`.

---

### EX4 — Permissionless `InsuranceFund.deposit` griefing

**Sink:** `InsuranceFund.deposit(uint256)` — permissionless, no role check, no cap.

**Backward trace:**
1. `deposit` requires only `amount > 0` and standard USDC allowance.
2. Anyone can call with `amount = 1` repeatedly, bloating `totalDeposited` and emitting `Deposited` events.

**Reachability:** **YES — externally reachable.**

**Impact:** off-chain tooling event-log noise, attacker pays gas. No on-chain effect on protocol funds (donated USDC strengthens the reserve).

**Severity: NEGLIGIBLE.**

---

### EX5 — Counter inflation via direct ERC20 transfer

**Sink:** `usdc.transfer(InsuranceFund, X)` — bypasses `deposit()` entirely.

**Backward trace:**
1. Anyone holding USDC can transfer to the InsuranceFund address.
2. `usdc.balanceOf(InsuranceFund)` increases without `totalDeposited` updating.
3. The invariant `B = D − W + X` (where X = direct donations) skews; `totalDeposited − totalWithdrawn < balance` permanently.

**Reachability:** **YES — externally reachable. By design.**

**Impact:** accounting drift, no fund safety effect. Same pattern applies to `RedeemEscrow` (helps shortfall) and `Vault USDC balance` (helps backing). Direct donations always benefit the protocol.

**Severity: INFO.**

---

### EX6 — Pending-USDM lockup via `setRedeemEscrow` migration race

**Sink:** Existing pending claims hit the new escrow which has zero balance + zero `totalOwed`.

**Backward trace:**
1. The migration is GOVERNOR-only via 24h timelock — **not externally reachable to trigger.**
2. **However:** during the 24h window an external attacker who learns of the queued migration via on-chain events or off-chain leak can submit `requestRedeem(largeAmount)` — public function — knowing their claim will hit a broken escrow.
3. Once the migration executes, every pending claim including the attacker's reverts at `payOut` due to insufficient escrow USDC.

**Externally exploitable component:** the ability for any user to lock USDM in the queue via `requestRedeem` during the timelock window — combined with the governance hazard — produces a **denial-of-service amplification**. The attacker doesn't profit, but they can flood the queue with their own USDM during the window, magnifying the post-migration breakage.

**Severity: LOW–MEDIUM** — primarily a governance hazard; external participation only amplifies the impact. Better classified as **CR-9** below (privileged-only).

---

### EX7 — Cross-contract reentrancy via USDM hooks (theoretical, not currently reachable)

**Sink:** `MonetrixVault` operator paths (`executeHedge`, `closeHedge`, `repairHedge`, `depositToHLP`, `supplyToBlp`, `withdrawFromBlp`, `keeperBridge`, `bridgePrincipalFromL1`, `bridgeYieldFromL1`, `fundRedemptions`, `reclaimFromRedeemEscrow`) — **none carry `nonReentrant`**.

**Backward trace:**
1. Operator paths invoke `ActionEncoder.send*` → `ICoreWriter.sendRawAction` (state-changing external call) and/or `usdc.safeTransferFrom`/`safeTransfer`.
2. Both targets are **assumed non-callback** (USDC = Circle USDC = no hooks; CoreWriter = HL system contract).
3. **For an external attacker:** none of these functions is reachable without OPERATOR.

**Conclusion:** Currently **NOT externally exploitable** — but the architectural assumption is structural, not enforced. If HL upgrades CoreWriter to a callback-capable contract, operator paths become reentrancy surfaces. Documented as a latent risk across the operator-side call paths.

**Severity: NOT EXPLOITABLE TODAY** — listed for completeness; downgrade to **CR-12** pending HL behavior.

---

### EX8 — `claimRedeem` cross-contract call chain

**Sink:** `claimRedeem` → `usdm.burn` → USDM `_update` → `RedeemEscrow.payOut` → `usdc.safeTransfer`.

**Backward trace for reentrancy:**
1. Vault's `claimRedeem` is `nonReentrant + whenNotPaused`. Caller is owner of request.
2. CEI-compliant: `delete redeemRequests[id]` and `_removeUserRedeemId` happen **before** any external call.
3. External calls: `usdm.burn(amount)` — USDM token has no callback; `_update whenNotPaused` is pure storage. No reentry path.
4. Then `escrow.payOut(msg.sender, amount)` → escrow internally calls `usdc.safeTransfer(recipient, amount)`. USDC is Circle USDC — no callback. No reentry path.

**Conclusion:** **NOT exploitable.** CEI ordering + `nonReentrant` + non-callback ERC20 close the surface.

---

### EX9 — Empty-vault yield reroute bypass — PREVENTED

**Sink:** `sUSDM.injectYield` reverts on `totalSupply == 0`; without protection, accumulated yield in YieldEscrow would distribute to a single 1-wei staker.

**Status:** explicitly mitigated at two layers:
1. `Vault.distributeYield` reroutes `userShare → 0` and adds it to `foundationShare` when `susdm.totalSupply() == 0`.
2. `sUSDM.injectYield` itself reverts if `totalSupply() > 0` is false.

**Reachability:** No — symmetric defense closes the inflation attack vector.

---

## Reentrancy across contract boundaries — comprehensive review

The protocol's external-call topology, traced for all callback opportunities:

### Vault ↔ Token contracts

| Caller → Callee | Direction | Callback risk | Mitigation |
|---|---|---|---|
| `Vault.deposit` → `usdc.safeTransferFrom` | EVM ERC20 | None (Circle USDC has no hooks) | `nonReentrant` on Vault |
| `Vault.deposit` → `usdm.mint` → `_update` | EVM ERC20 | None (no transfer hooks) | `nonReentrant` |
| `Vault.requestRedeem` → `usdm.safeTransferFrom` | EVM ERC20 | None | `nonReentrant` |
| `Vault.requestRedeem` → `escrow.addObligation` | Cross-contract | Escrow only writes own state, no callback | `nonReentrant` |
| `Vault.claimRedeem` → `usdm.burn` → `_update` | EVM ERC20 | None | `nonReentrant` + CEI |
| `Vault.claimRedeem` → `escrow.payOut` → `usdc.safeTransfer` | Cross-contract | None (Circle USDC) | `nonReentrant` + CEI |
| `Vault.distributeYield` → `usdm.mint` → `forceApprove` → `susdm.injectYield` → `usdm.safeTransferFrom(Vault, susdm, X)` | Cross-contract round-trip | USDM `_update` is pure storage; sUSDM `injectYield` has `nonReentrant` | `nonReentrant` on Vault + sUSDM |
| `Vault.distributeYield` → `forceApprove(insuranceFund)` → `insuranceFund.deposit` → `usdc.safeTransferFrom` | Cross-contract | InsuranceFund's `deposit` is non-CEI but USDC has no callback | `nonReentrant` on Vault |
| `Vault.distributeYield` → `usdc.safeTransfer(foundation, X)` | Out-of-protocol | If `foundation` is a contract with malicious `receive()` that re-enters, **Vault is `nonReentrant`** | `nonReentrant` |

### sUSDM ↔ sUSDMEscrow

| Caller → Callee | Direction | Callback risk | Mitigation |
|---|---|---|---|
| `sUSDM.cooldownShares` → `escrow.deposit` → `usdc.safeTransferFrom(sUSDM, escrow, X)` | Cross-contract | None | `nonReentrant` on sUSDM |
| `sUSDM.claimUnstake` → `escrow.release` → `usdm.safeTransfer(user, X)` | Cross-contract | None | `nonReentrant` + CEI |

### Vault ↔ Accountant ↔ Precompiles

| Caller → Callee | Direction | Callback risk | Mitigation |
|---|---|---|---|
| `Vault.executeHedge` → `Accountant.notifyVaultSupply` | Cross-contract | Accountant only writes own state | none needed |
| `Vault.supplyToBlp` → `Accountant.notifyVaultSupply` | Cross-contract | Same | none needed |
| `Vault.settle` → `Accountant.settleDailyPnL` → `_readL1Backing` → 42× precompile staticcalls | Read-only | Staticcalls cannot mutate state | none needed |

### Vault ↔ HyperCore CoreWriter

| Caller → Callee | Type | Callback risk | Mitigation |
|---|---|---|---|
| Operator functions → `ICoreWriter.sendRawAction(bytes)` | State-changing external call | **Architectural assumption: non-callback** | None — relies on HL system contract behavior |

**Cross-boundary reentrancy summary:**

- **All public/permissionless entry points** carry `nonReentrant`. External attackers cannot reenter via the public surface.
- **All Vault user-facing flows** (deposit, requestRedeem, claimRedeem) are CEI-compliant for state writes, and use non-callback ERC20s (USDC, USDM, sUSDM) for transfers.
- **The only architectural reentrancy assumption** is `ICoreWriter.sendRawAction` — load-bearing, not enforced. If HL ever changes CoreWriter behavior, **all operator-side functions** become reentrancy-vulnerable. This is the single most important latent surface (covered as **CR-12**).
- The cross-contract call chain `Vault → USDM → sUSDM → escrow` for yield injection is atomic within one transaction and protected by `nonReentrant` on both Vault and sUSDM.

**Verdict:** No externally exploitable reentrancy in the current contract set. The CoreWriter assumption is the only structural risk.

---

## Flash loan attack surfaces

A flash loan attack requires a function whose security depends on **balances or state being stable within a block**. Surveying every public and operator entry point:

| Function | Reads balance/state mid-call? | Flash-loan exploitable? |
|---|---|---|
| `Vault.deposit` | Reads `usdm.totalSupply()` for TVL cap | **No** — 1:1 USDC→USDM, no rate, no oracle. Flash-loaning USDC to deposit just gives back the same USDM. |
| `Vault.requestRedeem` | None except own struct state | **No** — fixed 1:1 lock |
| `Vault.claimRedeem` | Reads `escrow.balance()` for sufficiency | **No** — claim is bounded by `req.usdmAmount` set at request time, not by current state |
| `sUSDM.deposit` | Reads `totalAssets()`, `totalSupply()` for share computation | **Yes — donation-style flash inflation** |
| `sUSDM.cooldownShares` | Reads same | Snapshot at request — flash loan can manipulate the snapshot |
| `sUSDM.cooldownAssets` | Reads same with `previewWithdraw` (rounds up) | Same surface |
| `sUSDM.claimUnstake` | None — reads stored `req.usdmAmount` | **No** — claim amount is fixed at request time |
| `InsuranceFund.deposit` | None | **No** — no price logic |
| `Vault.settle` (operator) | Reads `Accountant.distributableSurplus()` | **Possibly via L1 oracle manipulation** — see oracle section |
| `Vault.distributeYield` (operator) | Reads `YieldEscrow.balance()` and config BPS | **No** — drains full balance per-call |
| `Vault.executeHedge` (operator) | None affecting price | **No** at EVM layer; L1 limit-order prices are operator-supplied |

### FL1 — sUSDM share-rate manipulation via flash-deposited USDM

**Sink:** sUSDM `previewDeposit(assets) = (assets * (totalSupply + 10^6)) / (totalAssets + 1)` for first depositor or low-TVL window.

**Mechanism:**
1. Attacker flash-loans USDM (e.g., from a future USDM-supporting AMM).
2. Calls `usdm.transfer(susdm, hugeY)` to inflate `totalAssets` without minting shares.
3. A subsequent victim call to `sUSDM.deposit(small)` mints near-zero shares.
4. Attacker withdraws via cooldown — but `cooldown` is time-locked; attacker cannot extract value within the same block.

**Backward trace for external reachability:**
1. `sUSDM.deposit/mint/cooldownShares/cooldownAssets/claimUnstake` are public.
2. The `cooldown*` functions snapshot `currentRate = totalAssets * 1e18 / supply` for off-chain audit but the **claim payout uses `req.usdmAmount` set at request time**.
3. Critically: `cooldownShares` stores `usdmAmount = convertToAssets(shares)` — value computed using the inflated `totalAssets` if attacker just donated.
4. The attacker needs to (a) inflate `totalAssets` via donation, (b) `cooldownShares(theirShares)`, and (c) wait `unstakeCooldown` (≥ 1 minute, default 3 days) before claiming. The donation and the cooldown are visible in the same block — but the claim is in a later block.

**Conclusion:** **Flash loans cannot extract value within a single transaction** because `claimUnstake` requires `block.timestamp >= cooldownEnd` (minimum 1-minute cooldown enforced by Config). A flash loan that must be repaid within the originating tx cannot survive the cooldown wait.

Donation inflation against new depositors (see EX3) is realisable without flash loans — the attacker uses their own capital and donates to dilute first depositor. Flash loans add nothing.

**Severity: NOT EXPLOITABLE (cooldown blocks single-tx round-trip).**

### FL2 — Backing read manipulation around `Vault.settle` (operator-only entry, but L1 oracle exposure)

**Sink:** `Accountant.distributableSurplus()` computes `surplus - shortfall`, where `surplus = totalBackingSigned - totalSupply`.

**Mechanism for an attacker without OPERATOR:**
1. The attacker cannot directly call `settle` — gated.
2. But they can manipulate inputs to gate-3 (`distributableSurplus`):
   - `usdm.totalSupply()` — pump or dump via deposits/redemptions in the same block as the operator's tx.
   - `usdc.balanceOf(Vault)` — flash-loan USDC into Vault by donating, then donate-out via... wait, no out-path exists for an attacker. Donations to Vault are one-way.
   - L1 spot/perp oracle reads — outside the Vault's ability to manipulate atomically.

**Backward trace:**
1. The operator submits `settle(proposedYield)` — visible in mempool.
2. Attacker can sandwich with a `deposit(largeAmount)` before to inflate totalSupply slightly, reducing surplus. **But this hurts the protocol, not the attacker** (they pay USDC for USDM at 1:1, no gain).
3. The reverse direction (deposit before to enable bigger yield) doesn't help: more deposit ≠ more surplus, since deposit adds 1 USDC backing per 1 USDM minted (net surplus contribution = 0).

**Conclusion:** No flash-loan-extractable value via settlement gates from the public surface.

### FL3 — Backing pollution via USDC donation to Vault

**Sink:** `Accountant.totalBackingSigned()` reads `usdc.balanceOf(Vault)`.

**Mechanism:**
1. Attacker flash-loans USDC, transfers to Vault (donation), waits for operator's `settle`, removes USDC.
2. **Problem:** there is no path for the attacker to remove USDC from Vault. `Vault.deposit` only moves it in. `claimRedeem` only pays from `RedeemEscrow`. No external "withdraw" from Vault USDC balance exists.
3. Therefore the donation is permanent and benefits the protocol, not the attacker.

**Conclusion:** **NOT EXPLOITABLE.** Donations to Vault USDC balance are one-way deposits; no flash-loan round-trip possible.

### Summary — flash loan surface

The protocol is **not externally vulnerable to flash loan attacks** because:

1. **All public withdrawal paths require time delays.** `claimRedeem` requires `redeemCooldown` (default 3 days) since `requestRedeem`. `claimUnstake` requires `unstakeCooldown` (default 3 days) since `cooldownShares/Assets`. Both have minimum 1-minute floor. No same-block round-trip is possible.
2. **No mark-to-market liquidation exists in the public surface.** The protocol does not allow external liquidation of any position. Hedge close, BLP withdraw, HLP withdraw are all OPERATOR-only.
3. **The deposit/redeem peg is 1:1 fixed.** No price-derived rate is computed at deposit or redeem time. USDM is not algorithmic.
4. **sUSDM rate is gradient.** sUSDM's exchange rate updates on `injectYield` (operator) or donations. An attacker can donate to inflate, but extraction via `cooldown* + claimUnstake` requires waiting through cooldown.
5. **No oracle-priced public function.** None of `deposit`, `requestRedeem`, `claimRedeem`, `sUSDM.deposit`, `claimUnstake`, `InsuranceFund.deposit` consult an oracle or external price feed.

Flash loan classes that **do not apply**: AMM rate manipulation, lending-protocol liquidation, rebase-token snapshot gaming, governance vote inflation. None of these surfaces exist in Monetrix.

---

## Oracle / price feed manipulation surfaces

The protocol reads three categories of external prices, all from HyperCore precompiles via `PrecompileReader`:

| Precompile | Function | Reads | Used by |
|---|---|---|---|
| `0x807` | `oraclePx(perpIndex)` | Perp asset oracle price (uint64) | `_readL1Backing` for spot notional via perp oracle |
| `0x808` | `spotPx(spotAssetId)` | Spot oracle price | **Not used in production** (only in tests) |
| `0x802` | `vaultEquity(account, vault)` | HLP equity at face value | `Vault.withdrawFromHLP`, `Accountant._readHlpEquity` |
| `0x80F` | `accountValueSigned(user)` | Perp account value (signed int64) | `Accountant._readPerpAccountValueSigned` |
| `0x801`, `0x811` | `spotBalance`, `suppliedBalance` | Token balance + supplied | Backing reads |
| `0x80a`, `0x80C` | `perpAssetInfo`, `tokenInfo` | Decimal metadata | TokenMath conversion |

### O1 — Perp oracle (`0x807`) manipulation cascading to `distributableSurplus`

**Sink:** `Accountant._readL1Backing` — for each whitelisted asset, multiplies spot/supplied balance by `oraclePx(perpIndex)` to compute USD notional.

**Backward trace from an external attacker:**
1. The Vault's settle/distribute pipeline reads oracle prices through `Accountant.distributableSurplus()`, called only by operator's `settle` or `bridgeYieldFromL1`.
2. **No public function calls `oraclePx` directly to make a state-affecting decision.**
3. `Vault.deposit`, `requestRedeem`, `claimRedeem` do NOT read oracles. They use direct ERC20 transfers and stored USDM amounts.
4. `sUSDM.deposit/cooldown*/claim*` do NOT read oracles. They use ERC4626 share/asset math against own balance.

**Conclusion:** Oracle manipulation **cannot be exploited via any public function**. The only on-chain surface is the operator's settle/yield-distribution pipeline. Even if HL's perp oracle for a thin-market perp could be temporarily skewed:
- The attacker cannot extract value through any user-facing path.
- The operator's settle would either succeed (with skewed yield) or revert (gate 3 fails). In either case, the attacker has no path to receive the yield.
- The yield, if declared, flows to sUSDM stakers (not the attacker, unless they staked) and to insurance/foundation addresses.

**The oracle DoS surface** is real (zero-price reverts halt yield pipeline) but not externally exploitable for theft.

**Severity: NOT EXTERNALLY EXPLOITABLE** for theft. **Liveness impact** (yield pipeline DoS) requires HL-level oracle outage, outside protocol's control.

### O2 — HLP equity (`0x802`) manipulation

**Sink:** `Accountant._readHlpEquity()` reads `vaultEquity.equity` at face value.

**Backward trace:**
1. HLP equity feeds into `totalBackingSigned`. If HL's HLP NAV computation can be manipulated (e.g., through HLP-internal trading by the attacker), the attacker can inflate the protocol's reported backing.
2. **From the public surface:** there is no path that pays the attacker based on inflated backing. `Vault.deposit` is 1:1. `claimRedeem` pays from `RedeemEscrow` not from backing total. sUSDM yield distribution flows to existing stakers proportionally.
3. To extract value, the attacker would need to be a sUSDM staker before the inflated `settle`, which is an OPERATOR action. Then the inflated yield gets distributed to all stakers including the attacker — but only proportional to their stake.

**Conclusion:** Possible value extraction via sUSDM front-running combined with HLP NAV inflation is **bounded by the attacker's pre-existing sUSDM stake**. To meaningfully profit they must hold a large fraction of sUSDM, in which case they're a major LP, and the attack cost (manipulating HLP) likely exceeds the gain.

**Severity: LOW** — high attack cost, bounded payoff.

### O3 — Token decimal metadata (`0x80a`, `0x80C`) DoS

**Sink:** `_assetDecimals` reads `weiDecimals`, `szDecimals`. If `weiDecimals - szDecimals > 77`, `TokenMath.spotNotionalUsdcFromPerpPx` reverts at `10 ** (weiDec - szDec)` overflow.

**Backward trace:**
1. Decimal values come from HL token metadata, set by HL token deployers — **not by the protocol**.
2. To poison a token, the metadata must be live on HL. The protocol's exposure occurs when `Config.addTradeableAsset` whitelists this token. **Whitelist is GOVERNOR-only with 24h timelock.**
3. Even after whitelist, the early-return `if (bal.total == 0) return 0` in `PrecompileReader.spotNotionalUsdcFromPerp` means the DoS triggers only if the Vault holds the token. Holdings come from `executeHedge` / `supplyToBlp` (operator-only).
4. **External attacker cannot induce the protocol to hold a malicious token without GOVERNOR + OPERATOR cooperation.**

**Conclusion:** DoS surface exists but **gated entirely by privileged actions**. Not externally reachable.

**Severity: NOT EXTERNALLY EXPLOITABLE** — listed as **CR-3** (config risk).

### Oracle manipulation summary

The protocol's oracle reads are **structurally insulated from external attackers**:

- All oracle-sensitive functions (`settle`, `distributeYield`, hedge ops, bridge ops, HLP/BLP ops) require OPERATOR or GOVERNOR.
- All public functions (deposit, redeem, sUSDM stake/unstake, InsuranceFund deposit) operate on stored amounts or 1:1 conversions — **no oracle reads**.
- Even if oracle prices are manipulable on HL, the value-extraction paths are time-delayed (cooldowns) or governance-gated.

The **liveness risk** from oracle outages (zero-price revert halts yield pipeline) is real but not value-extractive.

---

## PART 2 — PRIVILEGED-ONLY CONFIGURATION RISKS

These vectors are **not externally exploitable** because every reachable path requires a role grant. They are documented as configuration / governance risks for completeness.

### CR-1 — `setMaxTVL(0)` silently uncaps deposits (GOVERNOR)

`MonetrixConfig.setMaxTVL` accepts 0; `Vault.deposit` interprets `maxTVL == 0` as "uncapped". A single GOVERNOR call (24h timelock) removes the TVL cap entirely with no separate "disabled" flag.

### CR-2 — `setYieldBps(0, 0)` routes 100% yield to foundation (GOVERNOR)

GOVERNOR can zero both `userYieldBps` and `insuranceYieldBps`, sending all yield to `foundation`. Combined with `setFoundation(attackerAddr)` (also GOVERNOR), this is a yield-diversion attack with 24h delay.

### CR-3 — Adversarial token whitelist halts yield pipeline (GOVERNOR)

GOVERNOR-whitelisted token with `weiDecimals - szDecimals > 77` causes `TokenMath.spotNotionalUsdcFromPerpPx` to revert via `10**N` overflow. Once Vault holds any balance, every backing read reverts → settle/distribute halted. Recovery requires `removeTradeableAsset` (24h).

### CR-4 — `removeTradeableAsset` orphans open hedge positions (GOVERNOR)

If GOVERNOR removes a perp from whitelist while Vault holds an open hedge, `closeHedge`/`repairHedge` revert (whitelist check fails). Recovery: re-add (24h) or `emergencyRawAction` (24h).

### CR-5 — `emergencyRawAction(bytes)` complete L1 fund drain (GOVERNOR — **CRITICAL**)

```
Vault.emergencyRawAction(data) onlyGovernor
  → ICoreWriter.sendRawAction(data)
```

**No validation. No size cap. No type check. Bypasses both pause flags. Bypasses `requireWired`.** Can dispatch any L1 action including full USDC withdrawal from Vault's L1 account. **24h timelock is the only protection.** This is the single highest-trust function in the protocol. Mitigation depends on multi-sig governor + community monitoring of timelock queue.

### CR-6 — Permanent freeze via GUARDIAN compromise (GUARDIAN — **CRITICAL**)

GUARDIAN can set all four pause flags (`Vault._paused`, `Vault.operatorPaused`, `USDM._paused`, `sUSDM._paused`) instantly with no timelock. There is no auto-resume, no governor override of guardian-set pauses. In NUCLEAR state users cannot exit (`claimRedeem` blocked); the only recovery is UPGRADER (48h) or GUARDIAN cooperation.

### CR-7 — USDM pause as single-flag near-total kill (GUARDIAN — **HIGH**)

`USDM.pause()` alone blocks: `deposit` (mint), `claimRedeem` (burn), `distributeYield` (mint), and all peer-to-peer USDM transfers. Vault is technically still unpaused but no user-facing flow can complete. A single GUARDIAN call (instant) creates this state.

### CR-8 — `setVault` one-time misconfiguration (GOVERNOR)

`USDM.setVault(addr)` and `sUSDM.setVault(addr)` are one-time, irreversible. Setting to a wrong address (e.g., EOA) gives that address mint authority on USDM (catastrophic) or yield-injection on sUSDM. Recovery requires UPGRADER (48h) + reinitializer.

### CR-9 — `setRedeemEscrow` / `setYieldEscrow` migration hazard (GOVERNOR — **HIGH**)

Neither setter has a `balance == 0` precondition. Swapping while old escrow holds USDC orphans those funds. Pending redemption claims would hit the new (empty) escrow — **all pending claims revert** until manual migration. The same pattern applies to both escrow setters.

### CR-10 — `setEscrow` malicious binding drain (GOVERNOR — **HIGH**)

`sUSDM.setEscrow(addr)` is one-time, validates `addr.sUSDM() == this` and `addr.usdm() == asset()` — but a malicious contract can spoof these getters. Once bound, sUSDM grants `forceApprove(escrow, type(uint256).max)`. Malicious escrow then calls `usdm.transferFrom(sUSDM, attacker, max)` to drain all sUSDM USDM. **One-time semantics mean post-binding, the only recovery is UPGRADER (48h).**

### CR-11 — `setMultisigVault` capture (GOVERNOR)

`Vault.setMultisigVault(addr) + setMultisigVaultEnabled(true)` (2× 24h timelock) routes `keeperBridge(BridgeTarget.Multisig)` USDC to the configured multisig address. If GOVERNOR is compromised and routes to attacker-controlled L1 account, future bridges flow to the attacker.

### CR-12 — CoreWriter callback assumption (architectural)

If HyperCore's CoreWriter (`0x3333...3333`) ever upgrades to support callbacks, all operator-side functions (no `nonReentrant`) become reentrancy-vulnerable. The protocol architecturally assumes CoreWriter is non-callback; this is **not enforced on-chain**. Mitigation requires Vault upgrade (48h UPGRADER) to add `nonReentrant` modifiers to operator paths.

### CR-13 — Registry-asymmetry settlement DoS (OPERATOR-triggerable — **HIGH**)

Operator action triggers but no compromise required. `closeHedge` and `withdrawFromBlp` do **not** call `Accountant.removeSuppliedEntry`. After a full close/withdraw, the registry entry persists. If HL deactivates the 0x811 slot, every subsequent `_readL1Backing` reverts via strict-read semantics — the entire yield pipeline (`settle`, `distributeYield`, `bridgeYieldFromL1`) halts. Recovery requires OPERATOR to call `removeSuppliedEntry(...)` for each stale entry. **This is the most operationally dangerous non-malicious failure mode in the protocol.**

### CR-14 — `outstandingL1Principal` counter drift (structural)

The counter is not synchronized with L1 reality. L1 events that consume USDC (hedge use, BLP supply, liquidation) do not decrement it. After enough drift, `bridgePrincipalFromL1` may have an `amount <= outstandingL1Principal` cap that exceeds actual L1 balance — `_sendL1Bridge` would then revert at the L1 sufficiency check.

### CR-15 — Silent L1 wire-format mismatch (structural)

`ACTION_VERSION = 1` is hardcoded. If HL bumps wire format to v2, every dispatched L1 action is silently dropped on L1: EVM transaction succeeds, events emitted, counters decremented, but USDC never arrives. **No on-chain detection mechanism exists.** Recovery requires UPGRADER (48h) to update the constant.

### CR-16 — `coreDepositWallet` immutable post-init (structural)

No setter exists for `coreDepositWallet`. If HL bridge endpoint changes, every `keeperBridge` call dispatches to a stale address. Recovery requires UPGRADER (48h) replacement of Vault implementation.

### CR-17 — `__Governed_init` ACL hot-swap via reinitializer (UPGRADER — **CRITICAL**)

`MonetrixGovernedUpgradeable.__Governed_init` carries `onlyInitializing`, allowing call from `reinitializer(n)` for any future `n`. A malicious UPGRADER (48h) can deploy an implementation with a reinitializer that points `acl` to an attacker ACL contract — every subsequent role check authenticates against the malicious registry, bypassing all role gates simultaneously.

### CR-18 — DEFAULT_ADMIN_ROLE renunciation deadlock (structural)

Bootstrap renunciation is procedural. If deployer renounces DEFAULT_ADMIN_ROLE on the ACL before timelock holds it, no further role grants/revokes are possible — the protocol enters permanent configuration freeze. No on-chain recovery exists.

### CR-19 — Insurance Fund drain (GOVERNOR)

`InsuranceFund.withdraw(to, amount, reason)` has no per-call cap, no rate limit, no recipient whitelist. A single GOVERNOR tx (24h timelock) can drain the entire reserve.

### CR-20 — `emergencyBridgePrincipalFromL1` exceeds redemption cap (GOVERNOR)

The emergency path bounds amount only by `outstandingL1Principal` — **does not cap by `redemptionShortfall`**. Governor can pull back the entire outstanding principal even when redemption shortfall is zero, leaving L1 unable to fund hedges. Bypasses both pause flags. Emits the same `PrincipalBridgedFromL1` event as the operator path — emergency vs normal indistinguishable to off-chain observers.

### CR-21 — `setHlpDepositEnabled` instant operator toggle (OPERATOR)

`Vault.setHlpDepositEnabled(bool)` is OPERATOR-callable with **no timelock**. Compromised operator can freeze HLP deposits instantly. Reversible by same operator, so impact is bounded by `pauseOperator` (GUARDIAN, instant).

### CR-22 — `withdrawFromBlp(token, 0)` "max withdraw" trap (OPERATOR)

`l1Amount = 0` is HL's "withdraw max" sentinel. `Vault.withdrawFromBlp` does **not** validate `l1Amount > 0`. Operator passing 0 (intending "skip" or "no-op") drains the entire BLP position for that token. Same trap inherits from `ActionEncoder.sendWithdrawSupply`.

### CR-23 — `notifyVaultSupply` / `removeSuppliedEntry` no-timelock (OPERATOR)

`removeSuppliedEntry` is operator-callable with no timelock. Compromised operator can drain the registry, inflating `distributableSurplus` (since the supplied notionals no longer count against… wait, removed entries reduce backing, lowering surplus). Verified: removal can only **reduce** measured backing — no drain vector. No malicious-removal advantage.

### CR-24 — `setConfig` mutable hot-swap on sUSDM/Accountant (GOVERNOR)

Unlike `setVault`/`setEscrow` (one-time), `sUSDM.setConfig` and `Accountant.setConfig` are repeatedly mutable. Hot-swapping config mid-operation can change `unstakeCooldown`, `maxYieldPerInjection`, `redeemEscrow`, `tradeableAssets[]` — affecting in-flight calls and downstream invariants. 24h timelock; emits no event on `sUSDM.setConfig`.

---

## CRITICAL FINDINGS — RANKED

Combining external exploitability with severity:

| Rank | ID | Severity | Externally exploitable? | Action gate | Description |
|---|---|---|---|---|---|
| 1 | CR-5 | CRITICAL | No (GOVERNOR + 24h) | Multisig governor | `emergencyRawAction` complete L1 drain |
| 2 | CR-6 | CRITICAL | No (GUARDIAN, instant) | Multisig guardian | Permanent freeze via NUCLEAR pause |
| 3 | CR-17 | CRITICAL | No (UPGRADER + 48h) | Multisig upgrader | ACL hot-swap via reinitializer |
| 4 | CR-13 | HIGH | OPERATOR-triggerable as side-effect | Off-chain operator monitoring | Registry asymmetry → settlement DoS |
| 5 | CR-7 | HIGH | No (GUARDIAN, instant) | Guardian pause | USDM pause = near-total kill |
| 6 | CR-9 | HIGH | No (GOVERNOR + 24h) | Governor migration discipline | Escrow setter no balance precondition |
| 7 | CR-10 | HIGH | No (GOVERNOR + 24h) | Source-code review of escrow | Malicious escrow infinite-approval drain |
| 8 | CR-15 | HIGH | No (HL protocol, structural) | HL coordination | Silent L1 wire-format mismatch |
| 9 | EX1 | MEDIUM | **Yes** | — | Pending-redemption USDM occupies TVL cap |
| 10 | CR-2 | MEDIUM | No (GOVERNOR + 24h) | Governor multi-sig | 100% yield to foundation |
| 11 | CR-3 | MEDIUM | No (GOVERNOR + 24h) | Off-chain decimal vetting | Adversarial token decimals |
| 12 | CR-19 | MEDIUM | No (GOVERNOR + 24h) | Governor multi-sig | Insurance fund drain |
| 13 | CR-20 | MEDIUM | No (GOVERNOR + 24h) | Governor discipline | Emergency bridge bypasses shortfall cap |
| 14 | CR-22 | MEDIUM | No (OPERATOR) | Operator code review | `withdrawFromBlp(token, 0)` max trap |
| 15 | EX2 | LOW | **Yes** | — | sUSDM yield front-run dilution |
| 16 | EX3 | LOW | **Yes** | — | sUSDM first-depositor donation inflation |
| 17 | CR-12 | LOW (today) | Latent | HL behavior | CoreWriter callback assumption |
| 18 | CR-14 | LOW | No (structural) | Operator monitoring | OLP counter drift |
| 19 | EX4, EX5 | NEGLIGIBLE | **Yes** | — | Insurance event/counter griefing |

---

## EXTERNALLY EXPLOITABLE — final list

After tracing every public/permissionless entry point through every authorization barrier:

| ID | Severity | Description | Public surface |
|---|---|---|---|
| **EX1** | MEDIUM | Pending-redemption USDM occupies TVL cap | `Vault.requestRedeem` |
| **EX2** | LOW | sUSDM front-run yield injection (MEV) | `sUSDM.deposit` |
| **EX3** | LOW | sUSDM first-depositor donation inflation (partially mitigated by 10⁶ offset) | `sUSDM.deposit` + `usdm.transfer` |
| **EX4** | NEGLIGIBLE | InsuranceFund deposit-event griefing | `InsuranceFund.deposit` |
| **EX5** | INFO | Direct ERC20 transfer to InsuranceFund inflates balance vs counter | `usdc.transfer` |

**Reentrancy across contract boundaries:** none externally exploitable. All public entry points carry `nonReentrant`; all cross-contract chains are CEI-compliant or use non-callback ERC20s. The only latent surface (CR-12, CoreWriter callback assumption) is not currently triggerable.

**Flash loan attack surfaces:** none. All withdrawal paths are time-locked (cooldowns ≥ 1 minute, default 3 days). The protocol has no oracle-priced public function and no public liquidation path. Same-block round-trip extraction is structurally impossible.

**Oracle / price feed manipulation:** no public function reads an oracle to make a state-affecting decision. All oracle-sensitive logic (`settle`, `distributeYield`, hedge / HLP / BLP / bridge) requires OPERATOR or GOVERNOR. Oracle manipulation can produce liveness DoS (yield pipeline halts on zero-price reverts) but not value extraction by an external attacker.

---

## RECOMMENDATIONS

### Externally exploitable (close attacker-reachable gaps)

1. **EX1:** Either exclude pending-redemption USDM from the TVL cap (read `usdm.totalSupply() - usdm.balanceOf(Vault)`) or document that operators must monitor and adjust `maxTVL` for queue depth.
2. **EX2:** Document the front-running surface; consider private mempool submission for `distributeYield` if yield front-running becomes economically meaningful.
3. **EX3:** Already partially mitigated by `_decimalsOffset = 6`. Consider seeding sUSDM with a permanent dust deposit at deployment to definitively close first-depositor inflation.

### Privileged-only (governance & operational discipline)

4. **CR-9:** Add a `require(IYieldEscrow(yieldEscrow).balance() == 0)` precondition to `setYieldEscrow`. Same for `setRedeemEscrow` (require `getAllPendingRequestCount() == 0` or similar).
5. **CR-13:** Require `closeHedge` to call `Accountant.removeSuppliedEntry(spotToken)` once L1 supplied balance is zero. Or at minimum, add an off-chain alerting hook on `HedgeClosed` to drive registry cleanup.
6. **CR-22:** Add `require(l1Amount > 0)` to `Vault.withdrawFromBlp` (and `sendWithdrawSupply` if backward-compatibility allows).
7. **CR-12:** Add `nonReentrant` to all operator-side Vault functions (`executeHedge`, `closeHedge`, `repairHedge`, `depositToHLP`, `withdrawFromHLP`, `supplyToBlp`, `withdrawFromBlp`, `keeperBridge`, `bridgePrincipalFromL1`, `bridgeYieldFromL1`, `fundRedemptions`, `reclaimFromRedeemEscrow`). Defense-in-depth against future HL CoreWriter changes.
8. **CR-5:** No code remediation possible (the function is by design unconstrained). Operational mitigation: high-threshold multi-sig governor, public timelock monitoring, automated alerts on emergency-action queue.
9. **CR-20:** Emit a distinct `EmergencyPrincipalBridgedFromL1` event from the emergency path so off-chain monitors can distinguish it from the operator path.
10. **CR-15:** Add an `expectedActionVersion` view function on a sentinel contract that returns the current ACTION_VERSION; off-chain monitor can compare against HL's documented version to detect drift.

---

## Conclusion

Monetrix's externally reachable attack surface is small. Across the full contract set, only five public entry points exist (`Vault.deposit`, `requestRedeem`, `claimRedeem`, the sUSDM ERC4626 surface, and `InsuranceFund.deposit`), and they are systematically protected by:

- `nonReentrant` on every public mutator
- 1:1 fixed-rate conversions (no oracle reads)
- Time-locked withdrawal paths (≥ 1 minute cooldown floors)
- CEI-compliant state ordering
- Non-callback ERC20s (USDC, USDM, sUSDM)

The genuinely externally exploitable issues (EX1–EX5) are all **liveness/MEV/griefing** in nature — none enable theft.

The protocol's risk concentration is overwhelmingly in the **privileged classes**: GOVERNOR (CR-5 emergency raw action, CR-9/CR-10 escrow setters, CR-19 insurance drain), GUARDIAN (CR-6 permanent pause, CR-7 USDM kill), and UPGRADER (CR-17 ACL hot-swap). Each is gated by 24h or 48h timelocks except GUARDIAN pause, which is intentionally instant. The protocol's safety ultimately depends on multi-sig hygiene and timelock-queue monitoring at every privileged role.

The single most operationally dangerous non-malicious failure mode is **CR-13** (registry asymmetry → settlement DoS), which can be triggered by routine operator behavior (`closeHedge` / `withdrawFromBlp` without registry cleanup) and halts the entire yield pipeline until manually resolved.
