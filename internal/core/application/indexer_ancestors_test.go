package application

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestGetVtxoAncestors(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	testOutpoint := Outpoint{Txid: testTxids[0], VOut: 0}
	otherOutpoint := Outpoint{Txid: differentTxid, VOut: 0}

	t.Run("valid", func(t *testing.T) {
		t.Run("public, non-preconfirmed vtxo returns empty ancestors", func(t *testing.T) {
			vtxoData := domain.Vtxo{
				Outpoint:           domain.Outpoint{Txid: testTxids[0], VOut: 0},
				Preconfirmed:       false,
				RootCommitmentTxid: differentTxid,
			}
			vtxos := &mockedVtxoRepo{}
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: testTxids[0], VOut: 0}}).
				Return([]domain.Vtxo{vtxoData}, nil)

			indexer := newTestAncestorsIndexer(t, privkey, exposurePublic, nil, vtxos, nil, nil)
			resp, err := indexer.GetVtxoAncestors(t.Context(), "", testOutpoint, nil)
			require.NoError(t, err)
			require.Empty(t, resp.Ancestors)

			vtxos.AssertExpectations(t)
		})

		t.Run("public, single-hop preconfirmed vtxo returns parent", func(t *testing.T) {
			parentOutpoint := domain.Outpoint{Txid: differentTxid, VOut: 0}
			_, checkpointB64 := buildTestCheckpointTx(t, parentOutpoint)

			offchainTx := &domain.OffchainTx{
				CheckpointTxs: map[string]string{"0": checkpointB64},
			}
			parentVtxo := domain.Vtxo{
				Outpoint:     parentOutpoint,
				Preconfirmed: false,
			}
			// For a preconfirmed vtxo the outpoint txid IS the ark tx txid.
			childVtxo := domain.Vtxo{
				Outpoint:     domain.Outpoint{Txid: testTxids[0], VOut: 0},
				Preconfirmed: true,
			}

			vtxos := &mockedVtxoRepo{}
			offchainTxs := &mockedOffchainTxRepo{}

			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: testTxids[0], VOut: 0}}).
				Return([]domain.Vtxo{childVtxo}, nil)
			// vtxo.Txid (from embedded Outpoint) == testTxids[0]
			offchainTxs.On("GetOffchainTx", mock.Anything, testTxids[0]).
				Return(offchainTx, nil)
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{parentOutpoint}).
				Return([]domain.Vtxo{parentVtxo}, nil)

			indexer := newTestAncestorsIndexer(t, privkey, exposurePublic, nil, vtxos, nil, offchainTxs)
			resp, err := indexer.GetVtxoAncestors(t.Context(), "", testOutpoint, nil)
			require.NoError(t, err)
			require.Len(t, resp.Ancestors, 1)
			require.Equal(t, parentOutpoint, resp.Ancestors[0].Outpoint)

			vtxos.AssertExpectations(t)
			offchainTxs.AssertExpectations(t)
		})

		t.Run("private, valid token covers ancestor outpoints", func(t *testing.T) {
			parentOutpoint := domain.Outpoint{Txid: differentTxid, VOut: 0}
			_, checkpointB64 := buildTestCheckpointTx(t, parentOutpoint)

			offchainTx := &domain.OffchainTx{
				CheckpointTxs: map[string]string{"0": checkpointB64},
			}
			parentVtxo := domain.Vtxo{
				Outpoint:     parentOutpoint,
				Preconfirmed: false,
			}
			childVtxo := domain.Vtxo{
				Outpoint:     domain.Outpoint{Txid: testTxids[0], VOut: 0},
				Preconfirmed: true,
			}

			vtxos := &mockedVtxoRepo{}
			offchainTxs := &mockedOffchainTxRepo{}

			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: testTxids[0], VOut: 0}}).
				Return([]domain.Vtxo{childVtxo}, nil)
			offchainTxs.On("GetOffchainTx", mock.Anything, testTxids[0]).
				Return(offchainTx, nil)
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{parentOutpoint}).
				Return([]domain.Vtxo{parentVtxo}, nil)

			indexer := newTestAncestorsIndexer(t, privkey, exposurePrivate, nil, vtxos, nil, offchainTxs)

			// Token must cover both the child and the parent outpoint.
			allOutpoints := []Outpoint{testOutpoint, {Txid: differentTxid, VOut: 0}}
			token, err := indexer.createAuthToken(allOutpoints)
			require.NoError(t, err)

			resp, err := indexer.GetVtxoAncestors(t.Context(), token, testOutpoint, nil)
			require.NoError(t, err)
			require.Len(t, resp.Ancestors, 1)

			vtxos.AssertExpectations(t)
			offchainTxs.AssertExpectations(t)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		tests := []struct {
			name        string
			exposure    exposure
			makeToken   func(*testing.T, *indexerService) string
			outpoint    Outpoint
			errContains string
		}{
			{
				name:        "private, no token",
				exposure:    exposurePrivate,
				makeToken:   func(*testing.T, *indexerService) string { return "" },
				outpoint:    testOutpoint,
				errContains: "missing auth",
			},
			{
				name:        "private, bad base64",
				exposure:    exposurePrivate,
				makeToken:   func(*testing.T, *indexerService) string { return "not-base64!!!" },
				outpoint:    testOutpoint,
				errContains: "invalid auth token format",
			},
			{
				name:     "private, token for different outpoint",
				exposure: exposurePrivate,
				makeToken: func(t *testing.T, i *indexerService) string {
					token, err := i.createAuthToken([]Outpoint{otherOutpoint})
					require.NoError(t, err)
					return token
				},
				outpoint:    testOutpoint,
				errContains: "auth token is not for outpoint",
			},
			{
				name:        "withheld, invalid token",
				exposure:    exposureWithheld,
				makeToken:   func(*testing.T, *indexerService) string { return "invalidtoken!!!" },
				outpoint:    testOutpoint,
				errContains: "invalid auth token format",
			},
			{
				name:     "withheld, token for different outpoint",
				exposure: exposureWithheld,
				makeToken: func(t *testing.T, i *indexerService) string {
					token, err := i.createAuthToken([]Outpoint{otherOutpoint})
					require.NoError(t, err)
					return token
				},
				outpoint:    testOutpoint,
				errContains: "auth token is not for outpoint",
			},
			{
				name:     "private, expired token",
				exposure: exposurePrivate,
				makeToken: func(_ *testing.T, _ *indexerService) string {
					return buildExpiredToken(t, privkey, []Outpoint{testOutpoint})
				},
				outpoint:    testOutpoint,
				errContains: "auth token expired",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				indexer := newTestAncestorsIndexer(t, privkey, tc.exposure, nil, nil, nil, nil)
				token := tc.makeToken(t, indexer)

				_, err := indexer.GetVtxoAncestors(t.Context(), token, tc.outpoint, nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			})
		}
	})
}

func TestGetVtxoAncestorsByIntent(t *testing.T) {
	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Run("public, vtxo validation skipped", func(t *testing.T) {
			vtxoData := domain.Vtxo{
				Outpoint:     domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
				Preconfirmed: false,
			}
			vtxos := &mockedVtxoRepo{}
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: testVtxoTxid, VOut: testVtxoVout}}).
				Return([]domain.Vtxo{vtxoData}, nil)

			vtxoKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			validIntent, _ := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, 21000)

			indexer := newTestAncestorsIndexer(t, privkey, exposurePublic, nil, vtxos, nil, nil)
			resp, err := indexer.GetVtxoAncestorsByIntent(t.Context(), validIntent, nil)
			require.NoError(t, err)
			require.Empty(t, resp.Ancestors)

			vtxos.AssertExpectations(t)
		})

		t.Run("private, valid intent returns ancestors with auth token", func(t *testing.T) {
			vtxoKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			const vtxoAmount = int64(21000)
			validIntent, vtxoTaprootKey := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, vtxoAmount)

			parentOutpoint := domain.Outpoint{Txid: differentTxid, VOut: 0}
			_, checkpointB64 := buildTestCheckpointTx(t, parentOutpoint)

			offchainTx := &domain.OffchainTx{
				CheckpointTxs: map[string]string{"0": checkpointB64},
			}
			parentVtxo := domain.Vtxo{
				Outpoint:     parentOutpoint,
				Preconfirmed: false,
			}
			validVtxo := domain.Vtxo{
				Outpoint:     domain.Outpoint{Txid: testVtxoTxid, VOut: testVtxoVout},
				Amount:       uint64(vtxoAmount),
				PubKey:       hex.EncodeToString(schnorr.SerializePubKey(vtxoTaprootKey)),
				Preconfirmed: true,
			}

			vtxos := &mockedVtxoRepo{}
			offchainTxs := &mockedOffchainTxRepo{}
			wallet := &mockedWallet{}

			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{{Txid: testVtxoTxid, VOut: testVtxoVout}}).
				Return([]domain.Vtxo{validVtxo}, nil)
			// vtxo.Txid (embedded Outpoint) == testVtxoTxid
			offchainTxs.On("GetOffchainTx", mock.Anything, testVtxoTxid).
				Return(offchainTx, nil)
			vtxos.On("GetVtxos", mock.Anything, []domain.Outpoint{parentOutpoint}).
				Return([]domain.Vtxo{parentVtxo}, nil)

			indexer := newTestAncestorsIndexer(t, privkey, exposurePrivate, nil, vtxos, wallet, offchainTxs)
			resp, err := indexer.GetVtxoAncestorsByIntent(t.Context(), validIntent, nil)
			require.NoError(t, err)
			require.Len(t, resp.Ancestors, 1)
			require.NotEmpty(t, resp.AuthToken)

			vtxos.AssertExpectations(t)
			offchainTxs.AssertExpectations(t)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		vtxoKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		tests := []struct {
			name        string
			exposure    exposure
			makeIntent  func() Intent
			setupMocks  func(*mockedVtxoRepo, *mockedWallet)
			errContains string
		}{
			{
				name:        "empty proof",
				exposure:    exposurePrivate,
				makeIntent:  func() Intent { return Intent{} },
				setupMocks:  func(*mockedVtxoRepo, *mockedWallet) {},
				errContains: "missing intent proof tx",
			},
			{
				name:        "invalid PSBT",
				exposure:    exposurePrivate,
				makeIntent:  func() Intent { return Intent{Proof: "notavalidpsbt"} },
				setupMocks:  func(*mockedVtxoRepo, *mockedWallet) {},
				errContains: "failed to parse intent proof tx",
			},
			{
				name:     "private, unknown vtxo",
				exposure: exposurePrivate,
				makeIntent: func() Intent {
					intent, _ := buildTestIntent(t, testVtxoTxid, testVtxoVout, vtxoKey, 21000)
					return intent
				},
				setupMocks: func(vtxos *mockedVtxoRepo, wallet *mockedWallet) {
					vtxos.On("GetVtxos", mock.Anything, mock.Anything).
						Return([]domain.Vtxo{}, nil)
					wallet.On("GetTransaction", mock.Anything, testVtxoTxid).
						Return("", fmt.Errorf("tx not found"))
				},
				errContains: "failed to get boarding tx",
			},
			{
				name:       "more than one outpoint in intent",
				exposure:   exposurePrivate,
				setupMocks: func(*mockedVtxoRepo, *mockedWallet) {},
				makeIntent: func() Intent {
					vtxoHash1, _ := chainhash.NewHashFromStr(testVtxoTxid)
					vtxoHash2, _ := chainhash.NewHashFromStr(differentTxid)
					ptx, err := psbt.New(
						[]*wire.OutPoint{
							{Hash: chainhash.Hash{0x01}, Index: 0},
							{Hash: *vtxoHash1, Index: 0},
							{Hash: *vtxoHash2, Index: 0},
						},
						[]*wire.TxOut{{Value: 1000, PkScript: []byte{txscript.OP_TRUE}}},
						2, 0,
						[]uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum},
					)
					require.NoError(t, err)
					b64, err := ptx.B64Encode()
					require.NoError(t, err)
					return Intent{Proof: b64}
				},
				errContains: "only one outpoint expected in intent proof",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				vtxos := &mockedVtxoRepo{}
				wallet := &mockedWallet{}
				tc.setupMocks(vtxos, wallet)

				indexer := newTestAncestorsIndexer(t, privkey, tc.exposure, nil, vtxos, wallet, nil)

				_, err := indexer.GetVtxoAncestorsByIntent(t.Context(), tc.makeIntent(), nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)

				vtxos.AssertExpectations(t)
				wallet.AssertExpectations(t)
			})
		}
	})
}

// buildTestCheckpointTx creates a PSBT with a single input spending the given parentOutpoint.
// Returns the txid and base64-encoded PSBT.
func buildTestCheckpointTx(t *testing.T, parentOutpoint domain.Outpoint) (txid string, b64 string) {
	t.Helper()

	parentHash, err := chainhash.NewHashFromStr(parentOutpoint.Txid)
	require.NoError(t, err)

	ptx, err := psbt.New(
		[]*wire.OutPoint{{Hash: *parentHash, Index: parentOutpoint.VOut}},
		[]*wire.TxOut{{Value: 1000, PkScript: []byte{txscript.OP_TRUE}}},
		2, 0, []uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	txid = ptx.UnsignedTx.TxID()

	var buf bytes.Buffer
	require.NoError(t, ptx.Serialize(&buf))
	b64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	return
}

// newTestAncestorsIndexer extends newTestIndexer with an optional offchainTxs mock.
func newTestAncestorsIndexer(
	t *testing.T, privkey *btcec.PrivateKey, exp exposure,
	rounds *mockedRoundRepo, vtxos *mockedVtxoRepo, wallet *mockedWallet,
	offchainTxs *mockedOffchainTxRepo,
) *indexerService {
	t.Helper()

	svc := newTestIndexer(t, privkey, exp, rounds, vtxos, wallet)
	if offchainTxs != nil {
		svc.repoManager.(*mockedRepoManager).On("OffchainTxs").Return(offchainTxs)
	}
	return svc
}
