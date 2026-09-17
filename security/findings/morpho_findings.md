# Findings report — Morpho Midnight

## Classification convention (read first)

The three top-level sections partition findings by **who must act and whom it harms**:

- **Externally Exploitable** — reachable by an attacker holding **no trust grant** (unauthenticated caller, flash-borrower, searcher, taker, borrower, lender, liquidator, callback contract) against the **shared system or honest markets**, *or* a deployment-conditional protocol-wide hazard. These cross the market-isolation boundary or hit the shared protocol/revenue.
- **Privileged-Only Configuration Risks** — require one of the four admin keys (`roleSetter`, `feeSetter`, `feeClaimer`, `tickSpacingSetter`). Blast radius is bounded to the fee/tick subsystem (no admin path touches user principal; no pause/upgrade).
- **Trusted Role Operational Risks** — harm flows through an entity the victim **opted into**: a market creator's chosen `oracle`/`enterGate`/`liquidatorGate`/`rcfThreshold`/token, or an authorized delegate. Market creation is permissionless, so the *trigger* is reachable by anyone — but the *harm* is contained to users who chose to interact with that market/delegate. Each entry states this in its reachability verdict.

Market-id / CREATE2 fork identity produced no actionable finding: the frozen-`INITIAL_CHAIN_ID` vs live-`block.chainid` split is *protective* against cross-fork signature replay. The post-fork "same id = two ledgers" is an operational caveat, not an exploit. Signature malleability is benign everywhere (no signature-keyed nonce in `EcrecoverRatifier`; per-authorizer nonce in `EcrecoverAuthorizer`).

---

## Externally Exploitable Vulnerabilities

### arithmetic_rounding / collateral_management / bad_debt_socialization

**arithmetic_rounding-EXT-1 — Off-Osaka (and pre-Cancun/Shanghai) opcode floor bricks health, liquidation, and bad-debt realization protocol-wide**
- Entry point: `UtilsLib.msb` (`UtilsLib.sol:54-58`, `res := sub(255, clz(bitmap))`), reached from `isHealthy` (`Midnight.sol:951`) and the `liquidate` valuation loop (`Midnight.sol:608`); also the transient lock `tload/tstore` (`UtilsLib.sol:74-88`) and the SSTORE2 `PUSH0` prefix (`IdLib.sol:23`).
- Call-chain trace: `withdrawCollateral` (`Midnight.sol:549`) → `isHealthy` (`:568→944`) → `msb` (`:951`) → `clz`; `liquidate` (`:581`) → loop (`:607`) → `msb` (`:608`) → `clz`; `take` seller-health (`:476`) → `isHealthy` → `msb`. On any non-Osaka EVM `clz` is an invalid opcode (it reverts the frame — it does not silently miscompute).
- Auth gates traversed: none specific — `isHealthy`/`liquidate` are permissionless or behind the standard user gate; the failure is universal once a borrower has activated collateral and `debt > 0`.
- Reachability & verdict: **Not attacker-triggered** but a genuine, protocol-wide deployment hazard. Every collateralized health check, every collateral withdrawal by an indebted borrower, all liquidations, and all bad-debt realization revert; bad debt becomes permanently unrealizable. Highest-confidence "real" issue. HOLDS on Osaka; BROKEN on any chain that has not activated Osaka/Cancun/Shanghai. Ethereum mainnet shipped `CLZ` at the Fusaka activation (2025-12-03), so the live exposure is **L2 / alt-EVM deployment**, which still lags (e.g. Optimism's "Fusaka readiness" is explicitly *not* Fusaka adoption on L2) — Midnight is permissionless EVM code deployable on any such chain.
- PoC: `test/fuzz/OsakaClzDepPoC.t.sol` (4/4 PASS on osaka) — PUSH-aware scan confirms the `CLZ` opcode `0x1e` is present in deployed `Midnight` code, and `isHealthy`/`liquidate` execute the `msb`→`clz` bitmap loop for a `debt>0` collateralized borrower while a zero-debt position short-circuits past it. The literal pre-Osaka revert is not reproducible in-suite (runner pinned to `evm_version="osaka"`; `solc` rejects the `clz` builtin for lower targets, so the project won't compile down) — the PoC proves presence + reachability of the Osaka-only opcode on the risk paths.
- Severity: **High** (deployment-conditional).
- Tags: `[OSAKA-DEP]` `[DOS]`.

**bad_debt_socialization-EXT-1 — Front-run socialization to escape slashing**
- Entry point: `withdraw` (`Midnight.sol:481`, escape) racing the eager `lossFactor` ratchet in `liquidate` (`Midnight.sol:626-641`).
- Call-chain trace: a lender observes a pending liquidation that will realize `badDebt` → front-runs `withdraw(market, own credit, self, self)` → `_updatePosition` (`:485`) slashes their credit at the *current* (pre-realization) `lossFactor` (`:805-806`) → they exit at par (`:493-499`) → the subsequent `liquidate` ratchets `lossFactor` (`:631`) over the *remaining* lenders only. Realization is permissionless and fires even with `seizedAssets == repaidUnits == 0` (the seize/repay block at `:643` is skipped), so any third party can time the bump.
- Auth gates traversed: `withdraw` `:482` (`onBehalf == msg.sender`, self); `liquidate` `:597` `liquidatorGate` (only if the market sets one).
- Reachability & verdict: **Externally exploitable** by any lender in **any market, including honest ones** — this is not creator-scoped. The full `badDebt` is still socialized; only its *distribution* shifts onto slower lenders (fairness, not solvency).
- Severity: **Medium**.
- Tags: `[LOSS-SOCIALIZATION]` `[WITHDRAWABLE-RACE]`.

**bad_debt_socialization-EXT-2 — Division-by-zero DoS of bad-debt realization (`_totalUnits == 0` while `badDebt > 0`)**
- Entry point: `liquidate` `lossFactor` ratchet `Midnight.sol:632` (`mulDivDown(..., _totalUnits)` with no local `require(_totalUnits > 0)`).
- Call-chain trace: `liquidate` (`:581`) → `NotBorrower` `:596` (`debt > 0`) → valuation loop → `badDebt > 0` branch (`:626`) → `:632` divides by `_totalUnits`. Safety today rests entirely on the **cross-function** invariant `totalUnits ≥ outstanding debt > 0`, which is maintained only by `take`'s `MarketLossFactorMaxedOut` guard (`:349`) draining all liquidatable positions before brick. `liquidate` itself has **no** maxed-out guard. A second collateralized borrower surviving a partial brick — or any future path minting debt while `lossFactor == max` — yields `_totalUnits == 0` → revert → bad debt unrealizable.
- Auth gates traversed: `liquidate` `:597` `liquidatorGate`; otherwise permissionless.
- Reachability & verdict: **UNCERTAIN** — the multi-borrower partial-brick corner cannot be discharged by inspection. Recommend an explicit `require(_totalUnits > 0)` at `:632` and a Certora invariant `totalUnits ≥ outstanding debt`.
- Dynamic verification: fuzzing the total-units-positive invariant (single-borrower, 128,000 calls) **PASS**, plus a dedicated multi-borrower run (`test/fuzz/MultiBorrowerBrickInvariant.t.sol`, 2 borrowers / disjoint collateral, 18,000 calls + an active probe that crashes a still-indebted borrower's oracle and attempts a `(0,0)` realization every check, failing on `Panic(0x12)`) **PASS** — corner never reached, realization never panicked. Structural reason surfaced: a realization reduces `totalUnits` and the realized borrower's `debt` by the same `badDebt` (`:628`/`:634`), and a second healthy borrower's matching credit is never wiped, so `totalUnits ≥ Σ outstanding debt > 0` is preserved. Strong evidence; not a proof (the `lossFactor→max`-with-survivor path is bounded by the price floor) — UNCERTAIN stands pending the Certora invariant + defensive `require(_totalUnits > 0)`.
- Severity: **Medium** (liveness; conditional).
- Tags: `[DOS]` `[LOSS-SOCIALIZATION]`.

### callbacks_reentrancy / credit_debt_accounting

**callbacks_reentrancy-EXT-1 — Reentrant `repay` against commingled loan-token backing**
- Entry point: `repay` (`Midnight.sol:502`) — effect-before-interaction: `withdrawable += units` (`:509`) precedes `onRepay` (`:514`) precedes the token pull (`:520`).
- Call-chain trace: a callback contract calls `repay(market, units, onBehalf=self, callback)` → `:508` `debt -= units`, `:509` `withdrawable += units` (pool now inflated, **unfunded**) → `onRepay` (`:514`) re-enters `withdraw(market2, ...)` for a market sharing the same loan token → `withdraw` `:494` `withdrawable -= units`, `:499` `safeTransfer` **succeeds if the contract already holds enough from commingled buckets** (`withdrawable`/`claimableSettlementFee`/`continuousFeeCredit` of *other* markets in the same token) → outer `:520` pull refills. There is **no global reentrancy guard**; the only lock is the take-seller transient lock, which does not cover this path.
- Auth gates traversed: `repay` `:505` (self); `withdraw` `:482` (self). No further gate.
- Reachability & verdict: externally reachable by any user; the reentrancy itself is real, but the *net-extraction* question (two in-flight repays; reentrant-on-transfer token) is **resolved as no-drain** by the dynamic verification below. Hardening fix: **pull-before-credit** (move `:520` before `:509`).
- Dynamic verification: **resolved — no drain across three vectors**. A reentrant-repay fuzz (20k) plus three PoCs: `CallbacksReentrancyPoC::testFuzz_reentrantRepayNoNetDrain` (single reentrant repay, 5k), `CallbacksReentrancyTokenPoC::testFuzz_reentrantTokenNoNetDrain` (reentrant-on-transfer loan token re-entering from inside the repay pull, 3k), and `CallbacksReentrancyPoC::testFuzz_twoInFlightRepaysNoNetDrain` (two interleaved in-flight repays, 3k). Each confirms the reentrancy is **reachable** (no global guard) but `balanceOf(token,midnight) ≥ Σ withdrawable` **always held**. Conservation reason: every `withdrawable += x` is matched by a `+x` pull and every `withdraw −= y` by a `−y` transfer-out; reentrancy reorders but cannot break the identity. The only way to break it is an amount-mismatch token (fee-on-transfer/rebasing), which is the separate `token_safety-TRUSTED-1` and drains with or without reentrancy.
- Severity: **Low / Informational** — reachable reentrancy with **no demonstrated path to loss** (missing-guard / defense-in-depth), **not** Medium. *(Was flagged "High if confirmed / UNCERTAIN"; downgraded after the PoCs above.)* Fix remains **pull-before-credit** (move `:520` before `:509`) as hardening.
- Tags: `[REENTRANCY]` `[ISOLATION-CROSSING]`.

**callbacks_reentrancy-EXT-2 — Read-only reentrancy: inflated/unfunded view state during callbacks**
- Entry point: the same callback windows as EXT-1 — `repay` `onRepay` (`Midnight.sol:514`) and `liquidate` `onLiquidate` (`:698`).
- Call-chain trace: in `repay`, `withdrawable += units` (`:509`) and `debt -= units` (`:508`) are applied **before** `onRepay` (`:514`) and before the funding pull (`:520`); a contract re-entered during `onRepay` that reads `withdrawable(id)` (`:903`) or `totalUnits(id)` (`:891`) observes an **inflated, unfunded** value. In `liquidate`, `lossFactor` (`:631`) and `withdrawable` (`:675`) are mutated before the collateral send (`:696`) and the repay pull (`:717`), so `lossFactor(id)`/`isHealthy(...)` read mid-callback are mid-mutation.
- Auth gates traversed: none beyond EXT-1's self-gates; the read path is permissionless (`external view`).
- Reachability & verdict: **no in-scope consumer** reads these views mid-callback, and `creditOf`/`pendingFee`/`lossFactor` are *documented* not-up-to-date (NatSpec `Midnight.sol:171`); use `updatePositionView`. The surface matters only to **external integrators** that naively trust Midnight's live getters inside a Midnight callback. No fund loss within scope. Same hardening as EXT-1 (pull-before-credit at `:509`/`:520`) collapses the window.
- Severity: **Informational**.
- Tags: `[REENTRANCY]` `[READ-ONLY-REENTRANCY]`. (Sibling of `callbacks_reentrancy-EXT-1`.)

**credit_debt_accounting-EXT-1 — First-come `withdrawable` par-redemption race**
- Entry point: `withdraw` (`Midnight.sol:481`); the finite par pool is funded by `repay` (`:509`) and `liquidate` (`:675`).
- Call-chain trace: whenever a `repay`/liquidation funds `withdrawable`, a searcher/lender race to `withdraw` first (`:493-499`, par 1:1, no maturity gate); or buy a resting `price < 1` sell offer via `take` and instantly `withdraw` at par. The fee claimer competes for the same pool.
- Auth gates traversed: `withdraw` `:482` (self).
- Reachability & verdict: **Externally reachable**; acknowledged ordering/MEV (NatSpec `Midnight.sol:27-29`). Each withdraw is fully backed (absent the fee-on-transfer break), so it is not a solvency violation — a value-timing game.
- Severity: **Low** (by-design MEV).
- Tags: `[WITHDRAWABLE-RACE]`.

### settlement_fee

**settlement_fee-EXT-1 — Sub-unit settlement-fee evasion on cheap-gas chains**
- Entry point: `take` fee accrual `Midnight.sol:418` (`claimableSettlementFee += buyerAssets − sellerAssets`), spread `:363-364`.
- Call-chain trace: the attacker controls maker address `M` and a yes-ratifier `R` (sets `isAuthorized[M][R]=true` via `:731`; `R.isRatified` returns `CALLBACK_SUCCESS`). From a distinct taker address `T`, calls `take` with small `units` such that `units·fee/WAD < 1`. Gates: `:346` taker auth (`T == msg.sender`) ✓; `:354` `SelfTake` requires `M != T` (two addresses) ✓; `:355` `isAuthorized[M][R]` ✓; `:356` ratifier ✓. Then `buyerAssets − sellerAssets` (difference of two same-direction `mulDiv` products, **no defined rounding direction** — NatSpec `:113-114`) rounds to **0** at `:418`, while full `units` of credit/debt are minted (`:408-417`). Repeat to fill a large position fee-free.
- Auth gates traversed: `:346` taker (self), `:355-356` ratifier (attacker-owned). No protocol role needed.
- Reachability & verdict: **Externally exploitable** by any user on a low-gas chain; steals **protocol revenue** (a shared surface), not user funds. Negligible on mainnet (gas dominates). Fix: round the collected spread up, or fee on `units`.
- Severity: **Low / Medium** (chain-dependent).
- Tags: `[ROUNDING]` `[FEE-EVASION]`.

### continuous_fee

**continuous_fee-EXT-1 — Continuous-fee dust avoidance via frequent `updatePosition` / dust positions**
- Entry point: `updatePosition` (`Midnight.sol:823`, **permissionless**) → `_updatePosition` → accrual `:814-815` (`mulDivDown`).
- Call-chain trace: any caller invokes `updatePosition(market, victimOrSelf)` every block (or holds a tiny credit position); each interval `fee = postSlashPendingFee · mulDivDown(Δt, maturity − lastAccrual)` floors to **0** → `continuousFeeCredit` (`:846`) never grows → the continuous fee is permanently under-collected.
- Auth gates traversed: **none** — `updatePosition` has no role/delegation check.
- Reachability & verdict: **Externally reachable**; only *under*-collects protocol revenue and rounds in the lender's favor (analysis confirms it cannot harm the target). Pure protocol-revenue leak.
- Severity: **Low**.
- Tags: `[ROUNDING]` `[FEE-EVASION]`.

### liquidation

**liquidation-EXT-1 — Post-maturity LIF-ramp timing + flash-funded maximal seizure**
- Entry point: `liquidate` LIF ramp `Midnight.sol:645-646`; `flashLoan` (`:737`) inside `onLiquidate`.
- Call-chain trace: post-maturity, a liquidator waits until `now ≥ maturity + TIME_TO_MAX_LIF` so `lif = min(maxLif, …) = maxLif` (`:646`) → `flashLoan([loanToken],[amt],cb)` (`:737`) → in `onFlashLoan` calls `liquidate(...)` funding `repaidUnits` at `:717` → repays the flash loan from seized collateral delivered at `:696`. The take-seller transient lock is `take`-local and does not interfere.
- Auth gates traversed: `liquidate` `:597` `liquidatorGate` (if any); `flashLoan` `:737` none; `:595` mode mutex; `:620-624` liquidatability.
- Reachability & verdict: **Externally reachable**; this is the **intended incentive design** (MEV). Early liquidators receive `lif ≈ 1`; late liquidators capture `maxLif`. The borrower is "over-paid against" only within the sanctioned ramp; rounding is against the liquidator (`:650-652`).
- Severity: **Low / Informational** (by design).
- Tags: `[FLASH]` `[LIF-RAMP]`.

### periphery_bundler

**periphery_bundler-EXT-1 — Asset-target bundle: strict equality (rounding-DoS debunked; no-partial-fill griefing on a skipped offer)**
- Entry point: `MidnightBundles.sol:224` / `:303` (`require(filledBuyerAssets == targetFilledBuyerAssets, OutOfOffers())` — strict equality).
- Call-chain trace: an asset-target flow sizes each take via `TakeAmountsLib.buyerAssetsToUnits` (`TakeAmountsLib.sol:29`, `mulDivUp`); core `take` re-derives `buyerAssets` with its own rounding (`Midnight.sol:363-364`). If the inverse↔forward round-trip is off by a wei, or the `feeSetter` changes the settlement fee between sizing and execution, or a gate / expiry makes an earlier take fail (silently skipped in the `try/catch`, `MidnightBundles.sol:79-85`), the loop never reaches exact equality and reverts `OutOfOffers` despite available liquidity.
- Auth gates traversed: `MidnightBundles.sol:60` (`taker == msg.sender || isAuthorized[taker][bundler]`); the taker must have authorized the bundler on core.
- Reachability & verdict: **two parts, separated by PoC** (`test/fuzz/BundlerConvergenceDoS.t.sol`):
  - *(rounding convergence — DEBUNKED)* The "off-by-a-wei → `OutOfOffers` despite liquidity" claim **does not reproduce**. `testFuzz_assetTargetConverges` (30,000 runs, **valid** ticks ÷`DEFAULT_TICK_SPACING`) always converges — the per-leg `ceil(units*buyerPrice/WAD)` rounds the residual *back up* to the exact target. The apparent counterexample was a `TickNotAccessible` artifact (fuzzing non-multiple-of-4 ticks = invalid offers, not a bug). → **Informational / withdrawn.**
  - *(no partial fill — REAL)* `test_skippedOfferBricksAssetTargetBundle`: strict equality means **no graceful partial fill** — if any single offer in the path is un-takeable (expired / gate / fee change, silently skipped at `MidnightBundles.sol:79-85`), the whole asset-target bundle reverts `OutOfOffers` and the taker receives **nothing**, even though a takeable offer alone delivered part. Periphery-only, no fund loss; griefable liveness; very likely an already-acknowledged bundler behavior.
- Severity: **Low** (no-partial-fill griefing); the rounding-DoS sub-claim is **Informational/withdrawn**.
- Tags: `[DOS]`. *(rounding part debunked by PoC.)*

### tick_price_bridge

**tick_price_bridge-EXT-1 — Non-monotone tick curve inverts periphery pricing**
- Entry point: `TickLib.priceToTick` (`TickLib.sol:56-68`); the binary search assumes `tickToPrice` is non-decreasing in `tick`.
- Call-chain trace: periphery sizing (`TakeAmountsLib`/bundler) calls `priceToTick`; if a rounding artifact at a `wExp` `q`-boundary (`TickLib.sol:29-39`) inverts two adjacent ticks, the search can return a tick whose `tickToPrice` is *below* the requested price → a mis-sized periphery take. Monotonicity is asserted only by the hand-chosen `offset` constant, not enforced in-contract.
- Auth gates traversed: n/a (pure math). Core `take` uses `tickToPrice` *directly* with a known tick, so it is unaffected.
- Reachability & verdict: **UNCERTAIN, periphery-only** blast radius. Keep the Certora `TickLibWrapper` monotonicity proof in CI; fuzz adjacent-tick ordering across all `q`-boundaries.
- Dynamic verification: a tick-monotonicity fuzz (`test/fuzz/TickCurveInvariant.t.sol`, 50,000 runs of adjacency/window/range/inverse-round-trip) **PASS** — no inversion found. Strong evidence; the `[0, MAX_TICK]=[0,5820]` domain is small enough to *exhaustively* enumerate for a definitive proof.
- Severity: **Low**.
- Tags: `[ROUNDING]`.

### groups_oco

**groups_oco-EXT-1 — Exhausted-offer callback firing via 0-increment take**
- Entry point: `take` consumed accounting `Midnight.sol:366-373`; callbacks `:445`/`:458`.
- Call-chain trace: an asset-capped offer at `price < 1` can be "taken" for `units` whose asset increment rounds to 0 → `consumed += 0 ≤ cap` (`:368-369`) passes even when the offer is nominally exhausted → `onBuy`/`onSell` (`:445`/`:458`) still fire. A maker's callback logic that treats cap-exhaustion as a kill-switch is wrong.
- Auth gates traversed: `:346` taker auth; `:355-356` ratifier (maker authorized the ratifier and offer).
- Reachability & verdict: **Externally reachable** by any taker against any maker who relies on cap-exhaustion to stop callbacks; units are conserved, so no value is created — a callback-author assumption hazard, documented (NatSpec `:93`).
- Severity: **Low** (callback-author footgun).
- Tags: `[HOOK]`-adjacent / callback-assumption.

---

## Privileged-Only Configuration Risks

All four roles are unguarded single-address slots set in the constructor (`roleSetter = msg.sender`, `Midnight.sol:204`) with **no timelock, no multisig, no two-step transfer**. Their aggregate blast radius is bounded to fee configuration (within `maxSettlementFee`/`MAX_CONTINUOUS_FEE` caps), fee claiming (bounded by the buckets + `withdrawable`), tick refinement (monotone-down only), and role reassignment. **No admin function touches user positions, collateral, or `withdrawable`, and there is no pause/upgrade.**

### admin_roles

**admin_roles-PRIV-1 — Compromised `roleSetter` reassigns `feeClaimer` to itself and drains the fee pool in one transaction**
- Entry point: `setFeeClaimer` (`Midnight.sol:236`), `claimSettlementFee` (`:305`), `claimContinuousFee` (`:312`), batched via `multicall` (`:211`).
- Call-chain trace: `roleSetter` → `multicall([ setFeeClaimer(self) , claimSettlementFee(token, claimableSettlementFee[token], self) , claimContinuousFee(market, continuousFeeCredit, self) ])`. `multicall`'s `delegatecall` (`:213`) preserves `msg.sender`, so the `OnlyRoleSetter` (`:237`) and `OnlyFeeClaimer` (`:306/:315`) checks all pass for the same key.
- Auth gates traversed: `:225/:237` `OnlyRoleSetter`; `:306/:315` `OnlyFeeClaimer` (now self).
- Reachability & verdict: requires the **`roleSetter` key**. Bounded to accrued protocol fees (`claimableSettlementFee` + `continuousFeeCredit`, each capped by `withdrawable` backing at `:318-320`). **Cannot** reach user principal/collateral or alter immutable market params.
- Severity: **Medium** (bounded fee theft).
- Tags: `[ADMIN-KEY]`.

**admin_roles-PRIV-2 — `setRoleSetter(0)` permanently bricks role management (no zero-check, no two-step)**
- Entry point: `setRoleSetter` (`Midnight.sol:224-228`).
- Call-chain trace: `roleSetter` calls `setRoleSetter(0)` (or a typo'd / hostile address) → `roleSetter = 0` (`:226`, no zero-check) → `OnlyRoleSetter` can never pass again → no future `feeSetter`/`feeClaimer`/`tickSpacingSetter` can be appointed; if `feeClaimer` was also `0`, accrued fees become permanently unclaimable.
- Auth gates traversed: `:225` `OnlyRoleSetter`.
- Reachability & verdict: requires the `roleSetter` key; **irreversible**. Fat-finger or hostile renouncement. Recommend a two-step transfer + explicit `renounce`.
- Severity: **Medium** (operational footgun).
- Tags: `[ADMIN-KEY]`.

### settlement_fee

**settlement_fee-PRIV-1 — `feeSetter` reprices pending takers / implicitly cancels low-price offers via mid-life fee change**
- Entry point: `setMarketSettlementFee` (`Midnight.sol:258`) / `setDefaultSettlementFee` (`:277`); effect at `take` price computation (`:360-361`).
- Call-chain trace: `feeSetter` raises a market's settlement fee (or installs a non-monotone schedule — each breakpoint is capped independently, no monotonicity enforced, `:262`) between an offer's signing and its `take`. At take time `sellerPrice = offerPrice − fee` (`:361`) **underflows and reverts** for buy offers with `offerPrice < newFee` → those offers are implicitly cancelled; other takers pay a different spread than quoted. Composes with front-running.
- Auth gates traversed: `:260` `OnlyFeeSetter`.
- Reachability & verdict: requires the **`feeSetter` key**. Bounded by per-index caps (`maxSettlementFee`). Griefing / repricing surface; takers should pass a max-fee guard via a wrapper (NatSpec `:329`).
- Severity: **Medium** (griefing).
- Tags: `[ADMIN-KEY]`.

### continuous_fee

**continuous_fee-PRIV-1 — `feeSetter` raises continuous fee, inflating new lenders' locked-in `pendingFee`**
- Entry point: `setMarketContinuousFee` (`Midnight.sol:287`); effect at `take` `:386` (`buyerPendingFeeIncrease` reads the *current* `continuousFee`).
- Call-chain trace: `feeSetter` raises `continuousFee` between a buy offer's signing and its take → the maker/lender's locked-in `pendingFee` on the new credit is computed at the higher rate (`:385-386`). Existing positions are unaffected (rate is snapshot in their `pendingFee`).
- Auth gates traversed: `:289` `OnlyFeeSetter`.
- Reachability & verdict: requires the `feeSetter` key. Bounded by `MAX_CONTINUOUS_FEE` (1%/yr) and applies only to *new* credit. Minor "fee changed under me" surface.
- Severity: **Low**.
- Tags: `[ADMIN-KEY]`.

### admin_roles (tick)

**admin_roles-PRIV-3 — `tickSpacingSetter` unlocks ticks between resting offers**
- Entry point: `setMarketTickSpacing` (`Midnight.sol:249-256`).
- Call-chain trace: `tickSpacingSetter` refines spacing (`:252` requires `current % new == 0`, divisor-only) → finer ticks between existing resting offers become accessible → subsequent takers can fill at price levels the resting makers did not anticipate when quoting on the coarse grid.
- Auth gates traversed: `:250` `OnlyTickSpacingSetter`.
- Reachability & verdict: requires the `tickSpacingSetter` key. **Monotone-decrease only** — cannot coarsen or strand resting offers; worst case is finer-grid fills.
- Severity: **Low** (bounded).
- Tags: `[ADMIN-KEY]`.

---

## Trusted Role Operational Risks

Triggered by a market creator and the components they supply — `oracle`, `enterGate`/`liquidatorGate`, loan/collateral token — or by an authorized delegate. Market creation is permissionless (`touchMarket`, `Midnight.sol:755`), and `oracle`, gate addresses, `rcfThreshold`, loan token and collateral oracles are **not validated for safety** at creation, only for authenticity (id-binding). The harm is contained to users who **opt in** to that market/delegate; isolation-crossing exceptions are flagged.

### health_valuation

**health_valuation-TRUSTED-1 — Manipulable/malicious oracle controls borrower solvency**
- Entry point: `isHealthy` oracle read `Midnight.sol:953` (`IOracle(collateralParam.oracle).price()`); same read in `liquidate` (`:610`).
- Call-chain trace: a market creator creates a market with an attacker-controlled (or manipulable) `oracle` (no staleness/sanity bound). A manipulated **high** price inflates `maxDebt` (`:954-955`) → an unhealthy position passes `originalDebt > maxDebt` (`:622`) so liquidation is blocked and the borrower over-borrows; a manipulated **low** price deflates `maxDebt` → a healthy borrower becomes liquidatable and a liquidator calls `liquidate` (`:581`) to seize collateral at `lif`.
- Auth gates traversed: `touchMarket` (`:755`) permissionless, oracle unvalidated; `liquidate` `:597` `liquidatorGate`; `withdrawCollateral` `:556`/`take` `:346` consume `isHealthy`.
- Reachability & verdict: **Trusted-role** — the oracle is the component opt-in lenders/borrowers vetted. Permissionlessly creatable, but the **solvency of that market's users is genuinely controlled by the oracle**; blast radius is contained to the market (isolation).
- Severity: **High** (creator-scoped, within the market).
- Tags: `[ORACLE]` `[CREATOR-CONFIG]`.

**health_valuation-TRUSTED-2 — Reverting / extreme oracle bricks health, collateral withdrawal, and all liquidations for the borrower**
- Entry point: `isHealthy` `Midnight.sol:953-954`; `liquidate` loop `:610-616`.
- Call-chain trace: the oracle reverts `price()`, or returns a price so large that `collateral · price` overflows `mulDivDown` (no 512-bit intermediate, `UtilsLib.sol:29-31`). `isHealthy` reverts → `withdrawCollateral` (`:568`) and take-seller-health (`:476`) brick for an indebted borrower; in `liquidate` the **entire** loop reads every activated oracle (`:610`), so one bad oracle freezes the whole liquidation and bad debt cannot be realized.
- Auth gates traversed: as TRUSTED-1.
- Reachability & verdict: **Trusted-role** creator-scoped **liveness** DoS; market-isolated. The borrower can still be `repay`'d (no oracle on the repay path).
- Severity: **Medium**.
- Tags: `[ORACLE]` `[DOS]`.

### bad_debt_socialization

**bad_debt_socialization-TRUSTED-1 — Single oracle price drives both `maxDebt` and `badDebt` → over- or under-socialization**
- Entry point: `liquidate` loop `Midnight.sol:610` — one `price()` feeds both `maxDebt` (`:613`, health) and `badDebt` (`:614-616`, socialization).
- Call-chain trace: the oracle in a creator's market is attacker-controlled. A **low** price simultaneously makes the borrower unhealthy (`:622`) **and** inflates `badDebt` (`:614-616`) → a liquidation socialises *phantom* losses onto lenders, ratcheting `lossFactor` (`:631`) past the true loss. A **high** price → healthy + zero `badDebt` → blocks the needed liquidation. A single untrusted read corrupts both directions at once.
- Auth gates traversed: `liquidate` `:597` `liquidatorGate`; permissionless otherwise.
- Reachability & verdict: **Trusted-role** creator-scoped; opt-in lenders bear the over-socialized loss. Cross-refs health_valuation-TRUSTED-1.
- Severity: **Medium / High** (creator-scoped).
- Tags: `[ORACLE]` `[LOSS-SOCIALIZATION]`.

### liquidation

**liquidation-TRUSTED-1 — Over-liquidation via an unvalidated wide `rcfThreshold`**
- Entry point: `liquidate` RCF waiver `Midnight.sol:662-665`; `rcfThreshold` accepted unvalidated at `touchMarket` (`:755`).
- Call-chain trace: a market creator creates a market with a very large `market.rcfThreshold`. In normal mode (`lltv < WAD`), the RCF cap `repaidUnits ≤ maxRepaid` (`:659-660`) is waived whenever the residual collateral value after max-repay is `< rcfThreshold` (`:662-665`); a huge threshold makes the waiver near-always true → a liquidator over-liquidates a barely-unhealthy borrower close to 100% in one shot.
- Auth gates traversed: `liquidate` `:597` `liquidatorGate`; `:620-624` liquidatability (genuinely unhealthy required).
- Reachability & verdict: **Trusted-role** creator-scoped dial; opt-in borrowers. The position must still be unhealthy to be liquidated (`:622`); the abuse is the *amount* seized, not unjust liquidation.
- Severity: **Low / Medium**.
- Tags: `[RCF]` `[CREATOR-CONFIG]`.

### market_gates

**market_gates-TRUSTED-1 — Blocking immutable `liquidatorGate` makes borrowers un-liquidatable; lenders absorb unbounded bad debt**
- Entry point: `liquidate` gate `Midnight.sol:597-600` (`canLiquidate(msg.sender)`); gate is part of `hashMarket`, **immutable**.
- Call-chain trace: a market creator creates a market whose `liquidatorGate.canLiquidate` always reverts/returns false, then borrows against collateral in it. Every `liquidate` reverts at `:598` for **all** callers → no unhealthy borrower can be liquidated → bad debt accrues unbounded, `lossFactor` never updates (the realization branch at `:626` is unreachable). No recovery (immutable, no admin override).
- Auth gates traversed: `touchMarket` (`:755`) permissionless, gate unvalidated; the gate then blocks `liquidate` entirely.
- Reachability & verdict: **Trusted-role** creator-scoped, **High within the affected market**. A malicious creator makes themselves un-liquidatable while opt-in lenders eat the loss. Lenders must vet `liquidatorGate` before lending.
- Severity: **High** (within market).
- Tags: `[GATE-DOS]` `[CREATOR-CONFIG]`.

**market_gates-TRUSTED-2 — Blocking immutable `enterGate` permanently freezes entry (bounded)**
- Entry point: `take` gates `Midnight.sol:397-406` (`canIncreaseCredit`/`canIncreaseDebt`).
- Call-chain trace: a creator sets an `enterGate` that always reverts/returns false → all new credit/debt creation reverts at `:397-406` (when the relevant increase is non-zero) → permanent entry freeze. Can also selectively censor a chosen victim (returns false only for them).
- Auth gates traversed: `take` `:346` taker auth; `:355-356` ratifier; then the gate.
- Reachability & verdict: **Trusted-role** creator-scoped liveness, **bounded** — exits (`withdraw`/`repay`/`withdrawCollateral`) consult **no** gate, so the worst case is a wind-down-only market; no funds are forced in or trapped.
- Severity: **Low / Medium**.
- Tags: `[GATE-DOS]` `[CREATOR-CONFIG]`.

### token_safety

**token_safety-TRUSTED-1 — Fee-on-transfer / rebasing token desyncs accounting; commingled backing strands the last caller (isolation-crossing)**
- Entry point: `SafeTransferLib` (`SafeTransferLib.sol:12-34`) performs **no balance-delta check**; counters credited the requested amount at `repay` `:509`, `take` `:418`, `supplyCollateral` `:533`.
- Call-chain trace: a creator lists a fee-on-transfer/rebasing loan token. `repay(units)` credits `withdrawable += units` (`:509`) but the pull (`:520`) lands `units − fee` → `withdrawable` over-counts real backing → the last lender's `withdraw` `safeTransfer` (`:499`) reverts for lack of balance. Because `claimableSettlementFee[T]`, `continuousFeeCredit`, and every market's `withdrawable` share **one** `balanceOf(this, T)`, an over-count in one market can starve the claim/withdraw of **another market** sharing token `T` — crossing the isolation boundary. A fee-on-transfer collateral over-credits `collateral[i]` (`:533`), enabling under-collateralized borrowing.
- Auth gates traversed: `touchMarket` (`:755`) permissionless, token unvalidated; the `NoCode` check (`SafeTransferLib.sol:13`) catches only non-contract addresses.
- Reachability & verdict: **Trusted-role** creator-scoped (violates documented token assumptions, NatSpec `:133-139`), but the **commingled-bucket starvation is isolation-crossing** for any token used in ≥2 markets — the one creator-config issue whose blast radius escapes a single market.
- Severity: **High** (if such a token is used).
- Tags: `[TOKEN-ASSUMPTION]` `[ISOLATION-CROSSING]`.

**token_safety-TRUSTED-2 — Conditional-revert / blocklist token bricks all exits in that token**
- Entry point: `SafeTransferLib.sol:16-20` (revert propagates); `NoCode` (`:13`) catches only EOAs, not conditional reverters.
- Call-chain trace: a creator lists an immutable loan/collateral token that conditionally reverts on transfer to/from Midnight (e.g. a blocklist token blocking the contract). All out-transfers in that token brick: `withdraw` (`:499`), `withdrawCollateral` (`:572`), `claimSettlementFee` (`:309`), `claimContinuousFee` (`:324`), `liquidate` collateral-out (`:696`) — freezing exits denominated in it.
- Auth gates traversed: `touchMarket` permissionless, token immutable per market.
- Reachability & verdict: **Trusted-role** creator-scoped liveness; market-isolated fund lock, no recovery.
- Severity: **Medium**.
- Tags: `[TOKEN-ASSUMPTION]` `[DOS]`.

### market_lifecycle

**market_lifecycle-TRUSTED-1 — `loanToken == a collateral token` commingles two accounting buckets on one balance**
- Entry point: `touchMarket` (`Midnight.sol:759-764`) — collateral tokens are sorted/unique but never checked against the loan token.
- Call-chain trace: a market with `loanToken == collateralParams[i].token` makes one ERC-20 balance back both `withdrawable`/fee buckets **and** `collateral[i]`. Each bucket spends only its own accounting, so the balance suffices *by construction* — but there is no enforced invariant, and combined with token_safety-TRUSTED-1 (fee-on-transfer over-count) or a rounding leak, one bucket can starve the other.
- Auth gates traversed: `touchMarket` permissionless.
- Reachability & verdict: **Trusted-role** creator-scoped; unaudited corner. Safe under honest exact-amount tokens (holds by construction).
- Severity: **Low**.
- Tags: `[ISOLATION-CROSSING]` `[CREATOR-CONFIG]`.

### authorization_delegation (and its amplifications)

**authorization_delegation-TRUSTED-1 — Unscoped, transitive `isAuthorized` grant confers every on-behalf power; revocation is not recursive**
- Entry point: `setIsAuthorized` (`Midnight.sol:731-735`); the single boolean is consumed by the uniform gate at `:346/:482/:505/:527/:556/:724/:732` and by both ratifiers (`EcrecoverRatifier.sol:28/:44`, `SetterRatifier.sol:25`) and the off-chain authorizer (`EcrecoverAuthorizer.sol:34`).
- Call-chain trace: a victim grants `isAuthorized[victim][attacker]=true`. The attacker can then `withdraw` to an attacker `receiver` (`:499`), `withdrawCollateral` to itself (`:572`), redirect take proceeds via `receiverIfTakerIsSeller` (`:423/:456`), `setConsumed(group, max, victim)` to cancel offers (`:724`), `cancelRoot`/ratify on the victim's behalf (`EcrecoverRatifier.sol:28`, `SetterRatifier.sol:25`), and `setIsAuthorized(accomplice, true, victim)` (`:732`) — after which revoking the attacker does **not** revoke the accomplice (no epoch/version; `isAuthorized[victim][*]` is not enumerable).
- Auth gates traversed: the grant itself; the off-chain `EcrecoverAuthorizer` additionally requires the principal to have authorized the authorizer contract on core (`EcrecoverAuthorizer.sol:46-47` vs `Midnight.sol:732` — no first-grant bootstrap).
- Reachability & verdict: **Trusted-role** — the delegate is trusted by the victim. **Un-violable / HOLDS**, but it is the central sharp edge: every other component's trust collapses into this one boolean, and the only mitigation (authorize only purpose-scoped contracts) lives off-chain.
- Severity: **Medium** (footgun amplifier).
- Tags: `[DELEGATION]`.

The following are concrete amplifications of the above — each requires the victim's grant and is contained to the victim's own positions/offers:

**otc_order_book-TRUSTED-1 — Delegate redirects the principal's sale proceeds.** `receiverIfTakerIsSeller` is an unauthenticated `take` argument supplied by `msg.sender` (`Midnight.sol:342→:423→:456`); a delegate taking on the principal's behalf routes the principal's `sellerAssets` to a delegate-chosen address. Gate: `:346` taker auth. Severity: Low/Medium. Tags: `[DELEGATION]`.

**collateral_management-TRUSTED-1 — Delegate drains collateral to an attacker `receiver`.** `withdrawCollateral` (`Midnight.sol:556→:572`) sends to a `msg.sender`-chosen `receiver`. Gate: `:556` onBehalf auth. Severity: Low/Medium. Tags: `[DELEGATION]`.

**offer_ratification-TRUSTED-1 — Delegate cancels the maker's whole order book / signs / ratifies.** `cancelRoot` (`EcrecoverRatifier.sol:28`, one-way, batch) and `setIsRootRatified` (`SetterRatifier.sol:25`) accept `isAuthorized[maker][delegate]`; a single grant also lets the delegate sign offers as the maker (`EcrecoverRatifier.sol:44`). Severity: Low/Medium. Tags: `[DELEGATION]`.

**groups_oco-TRUSTED-1 — Delegate cancels offers via `setConsumed(max)`.** `setConsumed(group, type(uint256).max, maker)` (`Midnight.sol:724-726`) is monotone and irreversible; a delegate can cancel the maker's whole group. Gate: `:724` onBehalf auth. Severity: Low. Tags: `[DELEGATION]`.

**periphery_bundler-TRUSTED-1 — Authorized relayer skims proceeds via caller-set `referralFeePct`.** A relayer the taker authorized supplies `referralFeePct`/`referralFeeRecipient` per call (`MidnightBundles.sol:57-58`, distributed `:102/:165`), skimming up to ~100%−ε (capped only `< WAD` at `:61`). Gate: `:60` taker auth + the bundler being authorized on core. Severity: Low/Medium. Tags: `[DELEGATION]`.

---

## Cross-cutting Summary

### Priority list (by exploitability and severity)

1. **`[OSAKA-DEP]` arithmetic_rounding-EXT-1** — the single highest-confidence "real" issue: deploying on any non-Osaka/Cancun/Shanghai chain bricks all collateralized health checks, all liquidations, and bad-debt realization protocol-wide. **Gate deployment to Osaka chains** (or add a Solidity `msb` fallback). Deployment-conditional, not attacker-triggered, but protocol-fatal where it applies.
2. **`[REENTRANCY]` callbacks_reentrancy-EXT-1 — RESOLVED, Low/Info.** The non-CEI `repay` (`:509` before `:520`) with no global guard is real and reachable, but three PoCs (single reentrant repay, reentrant-on-transfer token, two in-flight repays) show **no net drain** — solvency held in every case. Downgraded from "potential High" to Low/Info; **adopt pull-before-credit** as hardening. (A drain still exists only via amount-mismatch tokens → `token_safety-TRUSTED-1`.)
3. **`[GATE-DOS]`/`[ORACLE]` token_safety / health_valuation / market_gates / bad_debt_socialization TRUSTED findings** — creator-scoped but High *within* a market; the fee-on-transfer commingled-starvation (token_safety-TRUSTED-1) additionally crosses the isolation boundary for any token shared across markets. **Surface full market params via `toMarket` in UIs; lenders must vet oracle, `liquidatorGate`, and token before entering.**
4. **`[DOS]` bad_debt_socialization-EXT-2 (UNCERTAIN)** — `liquidate` lacks a `require(_totalUnits > 0)`; the divisor's safety is a non-local cross-function invariant. **Add the local guard + a Certora invariant `totalUnits ≥ outstanding debt`.**
5. **`[FEE-EVASION]`/`[LOSS-SOCIALIZATION]`/`[WITHDRAWABLE-RACE]` economic/temporal EXT findings** — settlement-fee sub-unit evasion (cheap-gas), continuous-fee dust leak, front-runnable socialization, par-redemption race. Low–Medium, mostly by-design or revenue-only. Round fees up / fee on `units` to close the leaks.
6. **`[DELEGATION]` authorization_delegation-TRUSTED-1** — un-violable but the central amplifier; the practical risk is non-recursive revocation. **Recommend an epoch/version mass-revoke and scoped authorizations in a future version.**

### Privileged-config bullets (`[ADMIN-KEY]`)

- `roleSetter` compromise → `multicall` reassign `feeClaimer` → drain the entire accrued fee pool in one tx (PRIV-1). Bounded to fees; no path to user principal/collateral; no pause/upgrade.
- `setRoleSetter(0)` (no zero-check, no two-step) permanently bricks role management and can strand fees (PRIV-2). **Add a two-step transfer + explicit renounce.**
- `feeSetter` mid-life fee changes reprice takers / implicitly cancel low-price offers / inflate new `pendingFee` (settlement_fee-PRIV-1, continuous_fee-PRIV-1); `feeClaimer` rotation transfers the whole unclaimed pool to the successor; `tickSpacingSetter` can only refine (monotone, low-impact, PRIV-3). All bounded by caps and the no-principal-access guarantee.

### Trusted-role hazards (opt-in; contained by market isolation)

- **Oracle:** controls solvency both directions and is a liveness DoS on revert/overflow (health_valuation-TRUSTED-1/-2, bad_debt_socialization-TRUSTED-1). One read drives both `maxDebt` and `badDebt`.
- **Gates:** blocking `liquidatorGate` is High (un-liquidatable borrowers, lenders eat loss); blocking `enterGate` is bounded (wind-down only, exits always open) — market_gates-TRUSTED-1/-2.
- **Token:** fee-on-transfer/rebase desyncs every backing identity (commingled, isolation-crossing); conditional-revert bricks exits — token_safety-TRUSTED-1/-2; amplified by `loanToken == collateral` (market_lifecycle-TRUSTED-1).
- **`rcfThreshold`:** an unvalidated large value disables the recovery close factor → over-liquidation of barely-unhealthy borrowers (liquidation-TRUSTED-1).
- **Delegation:** one `isAuthorized` grant = full unscoped control of the victim's positions, collateral, offers, and re-delegation (authorization_delegation-TRUSTED-1 and its take/collateral/ratification/OCO/bundler amplifications).

### Load-bearing invariants whose breach would cascade (Certora / fuzz priorities)

1. `totalUnits > 0 whenever badDebt > 0` — the only reachable div-by-zero (`Midnight.sol:632`). **Add `require(_totalUnits > 0)`.** (bad_debt_socialization-EXT-2)
2. `withdrawable` fully token-backed + no global reentrancy guard — the `repay` non-CEI crack against commingled balances. **Verified no-drain across 3 PoC vectors; pull-before-credit recommended as hardening.** (callbacks_reentrancy-EXT-1, resolved Low/Info)
3. `maxLif · lltv < WAD²` / `1/maxLif ≥ lltv` — the creation-time `InvalidMaxLif` check (`:767-771`) is the sole guarantor of RCF-denominator positivity and badDebt-subtraction underflow-safety. **Fuzz the 9-tier × {LOW,HIGH} matrix.**
4. `tickToPrice` monotonicity — proof-dependent, periphery-only. **Keep the Certora proof in CI.** (tick_price_bridge-EXT-1)
5. credit-XOR-debt and `totalUnits = Σ credit + continuousFeeCredit` — load-bearing for health/liquidation; never asserted in-contract.

**Fuzz status:** the max-LIF/LLTV bound (exhaustive 9×2 + 50k), credit-XOR-debt, and the solvency backbone (128k calls) **PASS / corroborated**. Item 2 (reentrant `repay`) is **resolved no-drain** across three PoC vectors (single / reentrant-token / two-in-flight). Items 1 (total-units-positive, incl. multi-borrower) and 4 (tick monotonicity) ran **clean but remain open** for Certora / exhaustive proof (clean fuzz ≠ proof).

---

### Tag legend

Vulnerability-category tags used in this report:

- `[REENTRANCY]` — callbacks_reentrancy-EXT-1
- `[FLASH]` — liquidation-EXT-1
- `[ORACLE]` — health_valuation-TRUSTED-1, health_valuation-TRUSTED-2, bad_debt_socialization-TRUSTED-1
- `[ROUNDING]` — settlement_fee-EXT-1, continuous_fee-EXT-1, tick_price_bridge-EXT-1 *(periphery_bundler-EXT-1 rounding-DoS debunked by PoC — removed)*
- `[TOKEN-ASSUMPTION]` — token_safety-TRUSTED-1, token_safety-TRUSTED-2
- `[DOS]` — arithmetic_rounding-EXT-1, bad_debt_socialization-EXT-2, periphery_bundler-EXT-1, health_valuation-TRUSTED-2, market_gates-TRUSTED-1, market_gates-TRUSTED-2, token_safety-TRUSTED-2
- `[HOOK]`-adjacent (callback-author assumption) — groups_oco-EXT-1

Not applicable to this target (no findings): `[FIRST-DEPOSITOR]`/`[DONATION]` (shares are not minted from a pooled vault — credit is minted 1:1 against debt, no share-price), `[FORCE-FEED]`/`[EVM]` (no `selfdestruct`/coinbase dependence; accounting never reads `balanceOf`), `[SIG]` (malleability benign — no signature-keyed nonce in `EcrecoverRatifier`, per-authorizer nonce in `EcrecoverAuthorizer`; cross-fork replay blocked by live-`block.chainid` domains), `[PROXY]`/`[EVM]` (immutable, non-upgradeable), `[APPROVAL]`/`[EVM]` (core never approves; periphery `forceApproveMax` residual is low-risk, no inter-tx balances), `[ACCOUNT-CONFUSION]`/`[PDA]`/`[SOLANA]`, `[RESOURCE]`/`[MOVE]`, `[CIRCUIT]`/`[ZK]` (wrong VM / no ZK).

Target-specific tags:

- `[OSAKA-DEP]` — `clz`/`tload`/`tstore`/`push0` opcode dependency; off-Osaka deployment bricks the collateral loops, lock, and SSTORE2. arithmetic_rounding-EXT-1.
- `[LOSS-SOCIALIZATION]` — `lossFactor` ratchet / lazy lender slashing. bad_debt_socialization-EXT-1, bad_debt_socialization-EXT-2, bad_debt_socialization-TRUSTED-1.
- `[LIF-RAMP]` — post-maturity liquidation-incentive ramp timing game. liquidation-EXT-1.
- `[RCF]` — recovery-close-factor / `rcfThreshold` dial. liquidation-TRUSTED-1.
- `[GATE-DOS]` — immutable `enterGate`/`liquidatorGate` liveness weaponization. market_gates-TRUSTED-1, market_gates-TRUSTED-2.
- `[WITHDRAWABLE-RACE]` — first-come par-redemption of the finite `withdrawable` pool. credit_debt_accounting-EXT-1, bad_debt_socialization-EXT-1.
- `[FEE-EVASION]` — settlement-fee sub-unit rounding evasion / continuous-fee dust leak. settlement_fee-EXT-1, continuous_fee-EXT-1.
- `[DELEGATION]` — unscoped, transitive `isAuthorized`. authorization_delegation-TRUSTED-1, otc_order_book-TRUSTED-1, collateral_management-TRUSTED-1, offer_ratification-TRUSTED-1, groups_oco-TRUSTED-1, periphery_bundler-TRUSTED-1.
- `[ISOLATION-CROSSING]` — commingled per-token balance / native `flashLoan` reach across markets. callbacks_reentrancy-EXT-1, token_safety-TRUSTED-1, market_lifecycle-TRUSTED-1.
- `[CREATOR-CONFIG]` — adversarial-but-valid permissionless market parameters (oracle/gate/token/rcfThreshold). health_valuation-TRUSTED-1, liquidation-TRUSTED-1, market_gates-TRUSTED-1/-2, token_safety-TRUSTED-1, market_lifecycle-TRUSTED-1.
- `[ADMIN-KEY]` — unguarded single-address admin slots (no timelock/multisig/two-step). admin_roles-PRIV-1/-2/-3, settlement_fee-PRIV-1, continuous_fee-PRIV-1.
- `[SSTORE2]` — market-id / CREATE2 / fork identity (no finding; protective — see intro).
