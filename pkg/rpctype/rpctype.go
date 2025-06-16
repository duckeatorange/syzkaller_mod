// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package rpctype contains types of message passed via net/rpc connections
// between syz-manager and syz-hub.
package rpctype

import (
	"github.com/google/syzkaller/pkg/glc"
	"github.com/google/syzkaller/pkg/hash"
)

type HubConnectArgs struct {
	// Client/Key are used for authentication.
	Client string
	// The key may be a secret password or the oauth token prefixed by "Bearer ".
	Key string
	// Manager name, must start with Client.
	Manager string
	// Manager HTTP URL.
	HTTP string
	// See pkg/mgrconfig.Config.HubDomain.
	Domain string
	// Manager has started with an empty corpus and requests whole hub corpus.
	Fresh bool
	// Set of system call names supported by this manager.
	// Used to filter out programs with unsupported calls.
	Calls []string
	// Current manager corpus.
	Corpus [][]byte
}

type HubSyncArgs struct {
	// see HubConnectArgs.
	Client     string
	Key        string
	Manager    string
	NeedRepros bool
	// Programs added to corpus since last sync or connect.
	Add [][]byte
	// Hashes of programs removed from corpus since last sync or connect.
	Del []string
	// Repros found since last sync.
	Repros [][]byte
}

type HubSyncRes struct {
	// Set of inputs from other managers.
	Inputs []HubInput
	// Same as Inputs but for legacy managers that don't understand new format (remove later).
	Progs [][]byte
	// Set of repros from other managers.
	Repros [][]byte
	// Number of remaining pending programs,
	// if >0 manager should do sync again.
	More int
}

type HubInput struct {
	// Domain of the source manager.
	Domain string
	Prog   []byte
	Sig    hash.Sig
	GLC    glc.CorpusGLC
}

type RPCTriage struct {
	Sig        hash.Sig
	CallIndex  int
	Prog       []byte
	Flags      int
	// Info       ipc.CallInfo
	Source     int
	SourceCost float64
}

type TriageArgs struct {
	Name string
	RPCTriage
}

type RPCMABStatus struct {
	Round      int
	Exp31Round int
	MABGLC     glc.MABGLC
	CorpusGLC  map[hash.Sig]glc.CorpusGLC
	TriageInfo map[hash.Sig]*glc.TriageInfo
}