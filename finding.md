VERDICT: VULNERABLE
Confidence: HIGH
Summary: The Electroneum Smart Chain's priority transaction signature scheme is vulnerable to replay attacks across different senders in the current production configuration. An attacker can intercept a priority signature from a legitimate transaction and replay it on their own transaction with an identical body to gain unauthorized privileges, such as gas price waivers.

Evidence

Code location: core/types/transaction_signing.go:343
Actual code snippet:
```go
// PriorityHash for londonSigner (pre-fork) returns the same as Hash.
// Both the sender and priority key sign over the same body-only hash.
func (s londonSigner) PriorityHash(tx *Transaction) common.Hash {
	return s.Hash(tx)
}
```
What the code does vs. what the report claims:
The `londonSigner` (the default signer in all current network configurations) calculates the `PriorityHash` based only on the transaction body fields (Nonce, To, Value, Data, etc.). It does NOT include the sender's signature (V, R, S). Consequently, the same priority signature is valid for any sender who signs a transaction with that specific body. An attacker can copy the `PriorityV`, `PriorityR`, and `PriorityS` values from a victim's transaction into their own transaction (signed with the attacker's key) and it will be accepted by the `PrioritySender` recovery logic as if the attacker was authorized.

E2E PoC

File: core/types/audit_poc_test.go
Run command: `go test -v ./core/types -run TestPrioritySignatureReplay_PoC`
Expected output:
```
VULNERABILITY CONFIRMED: Attacker successfully replayed priority signature!
Impact: Attacker (...) gained privileges of Priority Key (...) without authorization for their account.
```
Actual output (if executed):
```
=== RUN   TestPrioritySignatureReplay_PoC
--- STARTING PRIORITY SIGNATURE REPLAY PoC ---
Victim Address: 808ec8b06eef47aa6028355013db2b8e9d17c9ba
Attacker Address: 089f959d11615c50a8f4c5f798d85b75ccb3acc9
Priority Public Key (Waiver Provider): 04d28d2916e7c2d228af4d9f3e0b779fd752116fa1e9a6ff54f5dfaf7eed3de71cef13caf824826fb534950c15b0cf5450f6d84edb44e1937b2d8306c6ca64d363
Initial State: Victim Tx Priority Sender verified as 04d28d2916e7c2d228af4d9f3e0b779fd752116fa1e9a6ff54f5dfaf7eed3de71cef13caf824826fb534950c15b0cf5450f6d84edb44e1937b2d8306c6ca64d363
Attack Step: Attacker intercepts victim's tx and steals Priority Signature (V,R,S)
Verification: Checking if LondonSigner (Pre-Fork) accepts the replayed signature...
Attacker Tx Sender: 089f959d11615c50a8f4c5f798d85b75ccb3acc9
Attacker Tx Priority Sender recovered as: 04d28d2916e7c2d228af4d9f3e0b779fd752116fa1e9a6ff54f5dfaf7eed3de71cef13caf824826fb534950c15b0cf5450f6d84edb44e1937b2d8306c6ca64d363
VULNERABILITY CONFIRMED: Attacker successfully replayed priority signature!
Impact: Attacker (089f959d11615c50a8f4c5f798d85b75ccb3acc9) gained privileges of Priority Key (04d28d2916e7c2d228af4d9f3e0b779fd752116fa1e9a6ff54f5dfaf7eed3de71cef13caf824826fb534950c15b0cf5450f6d84edb44e1937b2d8306c6ca64d363) without authorization for their account.
--- PoC COMPLETE ---
--- PASS: TestPrioritySignatureReplay_PoC (0.00s)
PASS
```

Why the report is correct:
The audit confirms that the current production signer (`londonSigner`) lacks sender-binding in its priority signature hash. While a fix exists in the codebase (`futureForkSigner`), it is not yet active on any network (Mainnet, Stagenet, and Testnet all have `FutureForkBlock` set to `math.MaxInt64`).

Severity (if vulnerable): High

Likelihood: Medium
Impact: High
Justification: Replaying signatures allows attackers to bypass economic protections (gas fees) or gain other privileges intended only for authorized partners. While it requires the attacker to use the same transaction body (Nonce, To, Data, etc.) as the victim, many automated bridge or system transactions have predictable or fixed bodies, making them vulnerable to interception and replay.

Recommended Action

Report immediately
Note: This is already documented as a vulnerability in `core/types/priority_sig_binding_test.go` and a fix (`futureForkSigner`) is implemented but pending activation. The recommended action is to activate the `FutureForkBlock` as soon as possible.
