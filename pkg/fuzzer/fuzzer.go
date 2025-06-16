// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sort"
	"sync"
	"time"
	"strings"
	"flag"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/glc"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

var (
	flagOS            = flag.String("os", "", "target OS type")
	flagKernelRepo    = flag.String("kernel", "", "path to the OS kernel source directory")
	flagSyzkallerRepo = flag.String("syzkaller", "", "path to the syzkaller repo")
	flagName          = flag.String("name", "", "the name under which the list should be saved")
	flagFilter        = flag.String("filter", "", "comma-separated list of subsystems to keep")
	flagEmails        = flag.Bool("emails", true, "save lists and maintainer fields")

	// MOD
	flagFeedback                       = flag.String("feedback", "KCOV", "Source of feedback")
	flagFuzzerConfigExecuteRetries     = flag.Int("fuzzerconfig_executeRetries", 0, "Number of extra executeRaw() during execute()")
	flagFuzzerConfigSignalRunThreshold = flag.Float64("fuzzerconfig_signalRunThreshold", 0.0, "Threshold for signalRuns during triaging")
	flagFuzzerConfigNoMinimization     = flag.Bool("fuzzerconfig_noMinimization", false, "Do not do minimization during triaging")
	flagFuzzerConfigGenerateWeight     = flag.Int("fuzzerconfig_generateWeight", 1, "Mutation-to-Generation Weight")
	flagFuzzerConfigMutateWeight       = flag.Int("fuzzerconfig_mutateWeight", 100, "Mutation-to-Generation Weight")
	flagFuzzerConfigSmashWeight        = flag.Int("fuzzerconfig_smashWeight", 100, "Smash-to-Generation Weight")
	flagFuzzerConfigSyncTriage         = flag.Bool("fuzzerconfig_syncTriage", false, "Sync triage with manager")
	flagFuzzerConfigSyncSmash          = flag.Bool("fuzzerconfig_syncSmash", false, "Sync smash with manager")
	flagFuzzerConfigVerifyFirst        = flag.Bool("fuzzerconfig_verifyFirst", false, "Verify signal during gen/mut instead of tri")
	flagFuzzerConfigMABAlgorithm       = flag.String("fuzzerconfig_MABAlgorithm", "N/A", "Which algorithm to use for multi-armed-bandit: Exp3-Gain/Exl3-Loss/Exp3-IX")
	flagFuzzerConfigMABTargetCorpus    = flag.Bool("fuzzerconfig_MABTargetCorpus", false, "Let MAB target corpus signal")
	flagFuzzerConfigMABSeedSelection   = flag.String("fuzzerconfig_MABSeedSelection", "N/A", "Use MAB for seed selection")
	flagFuzzerConfigMABVerbose         = flag.Bool("fuzzerconfig_MABVerbose", false, "Verbose MAB-related info")
	flagFuzzerConfigProgVerbose        = flag.Bool("fuzzerconfig_ProgVerbose", false, "Verbose Program content")
	flagFuzzerConfigMABZLogNormalize   = flag.Bool("fuzzerconfig_MABZLogNormalize", false, "Use Z-Log for normalization")
	flagFuzzerConfigMABTriageFirst     = flag.Bool("fuzzerconfig_MABTriageFirst", false, "Triage first for MAB scheduling")
	flagFuzzerConfigMABNormalize       = flag.Int("fuzzerconfig_MABNormalize", -1, "Normalize the gain and losses. <0: No normalize, =0: Max-min normalize, >0 Window normalize")
	flagFuzzerConfigMABTimeUnit        = flag.Float64("fuzzerconfig_MABTimeUnit", 0.0, "Use time average. <=0 for disable")
	flagFuzzerConfigMABExp31           = flag.Bool("fuzzerconfig_MABExp31", false, "Use exp3.1 algorithm to reset MAB periodically")
	flagFuzzerConfigMABDuration        = flag.Int("fuzzerconfig_MABDuration", -1, "# Rounds of MAB. <=0 to disable")
	flagFuzzerConfigMABGenerateFirst   = flag.Int("fuzzerconfig_MABGenerateFirst", -1, "Generate X programs before doing anything else. <=0 to disable")
	flagFuzzerConfigMABNoMutations     = flag.Int("fuzzerconfig_MABNoMutations", -1, "Don't mutate at all before K generations. <=0 to disable")
	flagFuzzerConfigMABGamma           = flag.Float64("fuzzerconfig_MABGamma", 0.1, "Exploration factor")
	flagFuzzerConfigMABEta             = flag.Float64("fuzzerconfig_MABEta", 0.1, "Weight increase factor")
	flagFuzzerConfigMABCorpusGamma     = flag.Float64("fuzzerconfig_MABCorpusGamma", 0.05, "Exploration factor")
	flagFuzzerConfigMABCorpusEta       = flag.Float64("fuzzerconfig_MABCorpusEta", 0.1, "Weight increase factor")
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}

	// add for syzvegas
	feedback     string
	fuzzerConfig config.FuzzerConfig

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus

	corpusMu       sync.RWMutex
	corpus         []*prog.Prog
	corpusHashes   map[hash.Sig]int
	corpusPrios    []float64
	corpusPriosSum []float64
	sumPrios       float64


	execQueues

	// MAB stuff
	triages           map[hash.Sig]int                 // All triage signatures, 0->Unfin. 1->Fin
	triagesUnfinished map[hash.Sig][]rpctype.RPCTriage // Buffer for unfinished triages to send to manager
	smashesFinished   []hash.Sig

	loggedPrograms map[hash.Sig]int

	MABMu    sync.RWMutex
	MABGamma float64 // No reset
	MABEta   float64 // No reset

	MABCorpusGamma float64
	MABCorpusEta   float64

	MABRound          int        // How many MAB choices have been made. No reset
	MABExp31Round     int        // How many rounds of Exp3.1. No reset
	MABExp31Threshold float64    // Threshold based on Round. No sync
	MABGLC            glc.MABGLC // {Generate, Mutate, Triage}. Used for stationary bandit

	MABCorpusUpdate map[int]int
	MABTriageInfo   map[hash.Sig]*glc.TriageInfo

	MABGMTStatus
}

/* type FuzzerConfig struct {		// move this to pkg/config/config.go
	executeRetries     int
	signalRunThreshold float64
	noMinimization     bool
	generateWeight     int
	mutateWeight       int
	smashWeight        int
	syncTriage         bool
	syncSmash          bool
	verifyFirst        bool

	MABAlgorithm     string
	MABSeedSelection string
	MABTargetCorpus  bool
	MABVerbose       bool
	ProgVerbose      bool
	MABTimeUnit      float64
	MABTriageFirst   bool
	MABZLogNormalize bool
	MABNormalize     int
	MABExp31         bool
	MABDuration      int
	MABGenerateFirst int
	MABNoMutations   int
} */

func (fuzzer *Fuzzer) ResetConfig() {
	fuzzer.fuzzerConfig.ExecuteRetries = 0
	fuzzer.fuzzerConfig.SignalRunThreshold = 0.0
	fuzzer.fuzzerConfig.NoMinimization = false
	fuzzer.fuzzerConfig.GenerateWeight = 1
	fuzzer.fuzzerConfig.MutateWeight = 100
	fuzzer.fuzzerConfig.SmashWeight = 100
	fuzzer.fuzzerConfig.SyncTriage = false
	fuzzer.fuzzerConfig.SyncSmash = false
	fuzzer.fuzzerConfig.VerifyFirst = false
	fuzzer.fuzzerConfig.MABAlgorithm = "N/A"
	fuzzer.fuzzerConfig.MABSeedSelection = "N/A"
	fuzzer.fuzzerConfig.MABTargetCorpus = false
	fuzzer.fuzzerConfig.MABVerbose = false
	fuzzer.fuzzerConfig.MABTimeUnit = 1000000.0
	fuzzer.fuzzerConfig.MABTriageFirst = false
	fuzzer.fuzzerConfig.MABZLogNormalize = false
	fuzzer.fuzzerConfig.MABNormalize = -1
	fuzzer.fuzzerConfig.MABExp31 = false
	fuzzer.fuzzerConfig.MABDuration = 0
	fuzzer.fuzzerConfig.MABGenerateFirst = 0
	fuzzer.fuzzerConfig.MABNoMutations = 0
}

func (fuzzer *Fuzzer) printFuzzerConfig(config config.FuzzerConfig) {
	fmt.Printf("# Fuzzer Config: %v\n%+v\n", fuzzer.feedback, config)
	fmt.Printf("# MABEta = %v, MABGamma = %v\n", fuzzer.MABEta, fuzzer.MABGamma)
}

type FuzzerSnapshot struct {
	fuzzerConfig   *config.FuzzerConfig
	corpus         []*prog.Prog
	corpusPrios    []float64
	corpusPriosSum []float64
	sumPrios       float64
	execQueues     execQueues
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	fuzzerConfig := config.FuzzerConfig{
		ExecuteRetries:     *flagFuzzerConfigExecuteRetries,
		SignalRunThreshold: *flagFuzzerConfigSignalRunThreshold,
		NoMinimization:     *flagFuzzerConfigNoMinimization,
		GenerateWeight:     *flagFuzzerConfigGenerateWeight,
		MutateWeight:       *flagFuzzerConfigMutateWeight,
		SmashWeight:        *flagFuzzerConfigSmashWeight,
		SyncTriage:         *flagFuzzerConfigSyncTriage,
		SyncSmash:          *flagFuzzerConfigSyncSmash,
		VerifyFirst:        *flagFuzzerConfigVerifyFirst,
		MABAlgorithm:       *flagFuzzerConfigMABAlgorithm,
		MABTargetCorpus:    *flagFuzzerConfigMABTargetCorpus,
		MABSeedSelection:   *flagFuzzerConfigMABSeedSelection,
		MABVerbose:         *flagFuzzerConfigMABVerbose,
		ProgVerbose:        *flagFuzzerConfigProgVerbose,
		MABTimeUnit:        *flagFuzzerConfigMABTimeUnit,
		MABTriageFirst:     *flagFuzzerConfigMABTriageFirst,
		MABZLogNormalize:   *flagFuzzerConfigMABZLogNormalize,
		MABNormalize:       *flagFuzzerConfigMABNormalize,
		MABExp31:           *flagFuzzerConfigMABExp31,
		MABDuration:        *flagFuzzerConfigMABDuration,
		MABGenerateFirst:   *flagFuzzerConfigMABGenerateFirst,
		MABNoMutations:     *flagFuzzerConfigMABNoMutations,
	}
	if fuzzerConfig.MABTimeUnit == 0.0 {
		fuzzerConfig.MABTimeUnit = 1000000.0
	}
	f := &Fuzzer{
		Stats:  newStats(target),
		Config: cfg,
		Cover:  newCover(),

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),
		
		// MOD (add for syzvegas)
		corpusHashes:      make(map[hash.Sig]int),
		MABCorpusUpdate:   make(map[int]int),
		triages:           make(map[hash.Sig]int),
		triagesUnfinished: make(map[hash.Sig][]rpctype.RPCTriage),
		loggedPrograms:    make(map[hash.Sig]int),
		feedback:          *flagFeedback,
		fuzzerConfig:      fuzzerConfig,
		MABGLC:            glc.MABGLC{},
		MABGamma:          *flagFuzzerConfigMABGamma,
		MABEta:            *flagFuzzerConfigMABEta,
		MABCorpusGamma:    *flagFuzzerConfigMABCorpusGamma,
		MABCorpusEta:      *flagFuzzerConfigMABCorpusEta,
		MABRound:          0,
		MABExp31Round:     1,
		MABTriageInfo:     make(map[hash.Sig]*glc.TriageInfo),
	}
	// fuzzer.workQueue.fuzzer = fuzzer
	// Initialize params for Exp31
	if f.fuzzerConfig.MABExp31 {
		f.MABBootstrapExp31()
	}
	fmt.Printf("Fuzzer Feedback: %s\n", f.feedback)
	f.printFuzzerConfig(f.fuzzerConfig)

	f.execQueues = newExecQueues(f)
	f.updateChoiceTable(nil)
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}
	return f
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	triageQueue          *queue.DynamicOrderer
	smashQueue           *queue.PlainQueue
	source               queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
		triageQueue:          queue.DynamicOrder(),
		smashQueue:           queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	// skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		// skipQueue = 2
	}
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(
		
		queue.Callback(func() *queue.Request {
			return fuzzer.MAB_SQ(ret)
		}),
		queue.Callback(fuzzer.genFuzz),
		
		/* queue.Callback(fuzzer.MABGenerate),			// Generate first
		queue.Callback(fuzzer.MABAlgorithm),		// if MABAlgorithm is enabled, use it
		ret.triageCandidateQueue,
		ret.candidateQueue,
		ret.triageQueue,
		queue.Alternate(ret.smashQueue, skipQueue),
		queue.Callback(fuzzer.genFuzz), */
	)
	return ret
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.statCandidates.Val()+fuzzer.statJobsTriageCandidate.Val() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// If we are already triaging this exact prog, this is flaky coverage.
	// Hanged programs are harmful as they consume executor procs.
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	// Triage the program.
	// We do it before unblocking the waiting threads because
	// it may result it concurrent modification of req.Prog.
	var triage map[int]*triageCall
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for call, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, call, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			queue, stat := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queue, stat = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{
				p:        req.Prog.Clone(),
				executor: res.Executor,
				flags:    flags,
				queue:    queue.Append(),
				calls:    triage,
				info: &JobInfo{
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			sort.Strings(job.info.Calls)
			fuzzer.startJob(stat, job, req)
		}
	}

	if res.Info != nil {
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)
	}

	// Corpus candidates may have flaky coverage, so we give them a second chance.
	maxCandidateAttempts := 3
	if req.Risky() {
		// In non-snapshot mode usually we are not sure which exactly input caused the crash,
		// so give it one more chance. In snapshot mode we know for sure, so don't retry.
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
}

type Config struct {
	Debug          bool
	Corpus         *corpus.Corpus
	Logf           func(level int, msg string, args ...interface{})
	Snapshot       bool
	Coverage       bool
	FaultInjection bool
	Comparisons    bool
	Collide        bool
	EnabledCalls   map[*prog.Syscall]bool
	NoMutateCalls  map[int]bool
	FetchRawCover  bool
	NewInputFilter func(call string) bool
	PatchTest      bool
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	// Either generate a new input or mutate an existing one.
	mutateRate := 0.95
	if !fuzzer.Config.Coverage {
		// If we don't have real coverage signal, generate programs
		// more frequently because fallback signal is weak.
		mutateRate = 0.5
	}
	var req *queue.Request
	rnd := fuzzer.rand()
	// fuzzerSnapshot := fuzzer.snapshot()
	if rnd.Float64() < mutateRate && fuzzer.MABRound >= fuzzer.fuzzerConfig.MABNoMutations{
		// ts0 := time.Now().UnixNano()
		// _, p := fuzzerSnapshot.chooseProgram(rnd)
		// p = p.Clone()
		// p.ResetMAB()
		fuzzer.writeLog("# Mutate\n")
		// fuzzer.logProgram(p)
		req = mutateProgRequest(fuzzer, rnd)
		// fuzzer.logProgram(p)
	}
	if req == nil {
		// ts0 := time.Now().UnixNano()
		req = genProgRequest(fuzzer, rnd)
		fuzzer.writeLog("# Generate\n")
		// fuzzer.logProgram(p)
	}
	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		req = &queue.Request{
			Prog: randomCollide(req.Prog, rnd),
			Stat: fuzzer.statExecCollide,
		}
	}
	fuzzer.prepare(req, 0, 0)
	return req
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob interface{}, req *queue.Request) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}
		fuzzerSnapshot := fuzzer.snapshot()
		var res interface{}
		switch j := newJob.(type) {
			case *triageJob:
				res = j.run(fuzzer) // TriageResult
			case *smashJob:
				res = j.run(fuzzer) // ExecResult
		}
		// res := newJob.run(fuzzer)
		// add for syzvegas to update MAB weight
		choice := req.MAB_TYPE
		weight := fuzzer.MABGetWeight(true)
		triage_count := 1
		mutate_count := 1
		if len(fuzzerSnapshot.corpus) == 0 { // Check whether mutation is an option
			mutate_count = 0
		}
		K := 1 + mutate_count + triage_count
		W := weight[0] + float64(mutate_count)*weight[1] + float64(triage_count)*weight[2]
		if W == 0.0 {
			fuzzer.writeLog("WTF: Error total weight W = 0")
		}
		gamma := fuzzer.MABGamma
		if fuzzer.fuzzerConfig.MABAlgorithm == "Exp3-IX" {
			// No explicit exploration for Exp3-IX
			gamma = 0
		}
		pr_generate := (1-gamma)*weight[0]/W + gamma/float64(K)
		pr_mutate := (1-gamma)*weight[1]/W + gamma/float64(K)
		pr_triage := (1-gamma)*weight[2]/W + gamma/float64(K)
		if fuzzer.fuzzerConfig.MABAlgorithm == "Exp3-IX" {
			pr_generate = weight[0] / W
			pr_mutate = weight[1] / W
			pr_triage = weight[2] / W
		}
		_pr_mutate := float64(mutate_count) * pr_mutate
		_pr_triage := float64(triage_count) * pr_triage
		pr_arr := []float64{pr_generate, _pr_mutate, _pr_triage} // Use real weight as pr. Consider cases where triage/mutation might be unavailable
		/* if choice == 2{
			var r TriageResult
			r.time = float64(res.Info.Elapsed / 1e6)
			r.gainRaw = res.Info.Calls
		}else{
			var r ExecResult
			r.time = float64(res.Info.Elapsed / 1e6)
			r.gainRaw = res.Info.Calls
		} */
		fuzzer.MABUpdateWeight(choice, res, pr_arr, K)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.statCandidates.Add(len(candidates))
	for _, candidate := range candidates {
		req := &queue.Request{
			Prog:      candidate.Prog,
			ExecOpts:  setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:      fuzzer.statExecCandidate,
			Important: true,
		}
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}

// add for syzvegas

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.DiffRaw(sign.ToRaw(), 0)
}

func (fuzzer *Fuzzer) writeLog(format string, args ...interface{}) {
	fuzzer.mu.Lock()
	fmt.Printf(format, args...)
	fuzzer.mu.Unlock()
	return
}

func (fuzzer *Fuzzer) logProgram(p *prog.Prog) {
	data := p.Serialize()
	sig := hash.Hash(data)
	if fuzzer.fuzzerConfig.ProgVerbose {
		if _, ok := fuzzer.loggedPrograms[sig]; !ok {
			s := strings.ReplaceAll(string(data), "\n", "\n> ")
			fuzzer.writeLog(">>> %s\n> %s\n<<<\n", sig.String(), s)
			fuzzer.loggedPrograms[sig] = 1
		} else {
			fuzzer.writeLog(">>> %s\n<<<\n", sig.String())
		}
	} else {
		fuzzer.writeLog(">>> %s\n<<<\n", sig.String())
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{&fuzzer.fuzzerConfig, fuzzer.corpus, fuzzer.corpusPrios, fuzzer.corpusPriosSum, fuzzer.sumPrios, fuzzer.execQueues}
}

/* func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) (int, *prog.Prog) {
	randVal := 0.0
	randVal = r.Float64() * fuzzer.sumPrios
	pidx := sort.Search(len(fuzzer.corpusPriosSum), func(i int) bool {
		return fuzzer.corpusPriosSum[i] >= randVal
	})
	if fuzzer.fuzzerConfig.MABVerbose {
		if len(fuzzer.corpusPrios) > 10 {
			fmt.Printf("- Corpus Priority %v, %v...%v\n", fuzzer.corpusPrios[pidx], fuzzer.corpusPrios[:5], fuzzer.corpusPrios[(len(fuzzer.corpusPrios)-5):])
			fmt.Printf("- Corpus Priority Sum %v, %v...%v, %v\n", fuzzer.corpusPriosSum[pidx], fuzzer.corpusPriosSum[:5], fuzzer.corpusPriosSum[(len(fuzzer.corpusPrios)-5):], fuzzer.sumPrios)
		} else {
			fmt.Printf("- Corpus Priority %v\n", fuzzer.corpusPrios)
			fmt.Printf("- Corpus Priority Sum %v, %v\n", fuzzer.corpusPriosSum, fuzzer.sumPrios)
		}
	}
	if pidx >= len(fuzzer.corpus) {
		pidx = len(fuzzer.corpus) - 1
		fmt.Printf("- Error. chooseProgram out of bound. %v/%v\n", pidx, len(fuzzer.corpus))
	}
	return pidx, fuzzer.corpus[pidx]
} */

func (fuzzer *Fuzzer) MABGenerate() *queue.Request {				// the original one is proc.go/loop()
	var req *queue.Request
	if fuzzer.MABRound <= fuzzer.fuzzerConfig.MABGenerateFirst {
		// Force Generate First
		fuzzer.MABRound += 1
		rnd := fuzzer.rand()
		// ts0 := time.Now().UnixNano()
		req = genProgRequest(fuzzer, rnd)
		fuzzer.writeLog("# %v Generate\n")
		// fuzzer.logProgram(p)
		fuzzer.writeLog("- Work Type: 0\n")
		return req
	}else{
		return nil
	}
}

/* func (fuzzer *Fuzzer) MABAlgorithm() *queue.Request {
	fuzzer.DoCandidate() // Deal with candidates first
	if fuzzer.fuzzerConfig.MABDuration <= 0 || fuzzer.MABRound < fuzzer.fuzzerConfig.MABDuration {
		fuzzer.MABLoop()
	} else if fuzzer.fuzzerConfig.MABDuration > 0 && fuzzer.MABRound >= fuzzer.fuzzerConfig.MABDuration {
		// Reset params
		fuzzer.ResetConfig()
	}
	return nil
} */

/* func (fuzzer *Fuzzer) ProcessItem(item interface{}) (int, interface{}) {
	if item != nil {
		switch item := item.(type) {
		case *WorkTriage:
			{
				fuzzer.writeLog("# %s\n", "WorkTriage")
				res := triageInput(item)
				return 2, res
			}
		case *WorkCandidate:
			{
				fuzzer.writeLog("# %s\n", "WorkCandidate")
				_, res := execute(proc.execOpts, item.p, item.flags, StatCandidate)
				return 0, res
			}
		case *WorkSmash:
			{
				fuzzer.writeLog("# %s\n", "WorkSmash")
				res := smashInput(item)
				return 1, res
			}
		default:
			log.Fatalf("unknown work type: %#v", item)
		}
	}
	return -1, nil
} */

func (fuzzer *Fuzzer) DoCandidate(ret execQueues) *queue.Request {			// get one request from candidateQueue
	// var req *queue.Request
	/* item := fuzzer.workQueue.dequeueType(0, true, true)
	for item != nil {
		fuzzer.writeLog("%s", "# WorkCandidate\n")
		ProcessItem(item)
		item = fuzzer.workQueue.dequeueType(0, true, true)
	} */
	return ret.candidateQueue.Next()
}

func (fuzzer *Fuzzer) DoGenerate() *queue.Request {
	/* ret := ExecResult{
		gainRaw:   0.0,
		time:      0.0,
		calls:     0,
		pidx:      -1,
		timeTotal: 0.0,
	} */
	var req *queue.Request
	/* ts0 := time.Now().UnixNano()
	defer func() {
		ret.timeTotal = float64(time.Now().UnixNano()-ts0) / fuzzer.fuzzerConfig.MABTimeUnit
	}() */
	// ct := fuzzer.choiceTable
	rnd := fuzzer.rand()
	req = genProgRequest(fuzzer, rnd)
	fuzzer.writeLog("%s", "# Generate\n")
	/*  _, r := execute(execOpts, p, ProgNormal, StatSmash)
	ret.gainRaw += r.gainRaw
	ret.calls += r.calls
	ret.time += r.time
	ret.timeTotal += r.timeTotal */
	// }
	return req
}

func (fuzzer *Fuzzer) DoMutate(ret execQueues, count int) *queue.Request {
	/* ret := ExecResult{
		gainRaw:   0.0,
		time:      0.0,
		calls:     0,
		pidx:      -1,
		timeTotal: 0.0,
	} */
	/* ts0 := time.Now().UnixNano()
	defer func() {
		ret.timeTotal = float64(time.Now().UnixNano()-ts0) / fuzzer.fuzzerConfig.MABTimeUnit
	}() */
	// corpus := proc.fuzzer.corpusSnapshot()
	// fuzzerSnapshot := fuzzer.snapshot()
	// ct := fuzzer.choiceTable
	var req *queue.Request
	rnd := fuzzer.rand()
	req = ret.smashQueue.Next()
    if req != nil{
		return req
	}else{
		// MAB seed selection is integrated with chooseProgram
		req = mutateProgRequest(fuzzer, rnd)
		// proc.fuzzer.MABIncrementCorpusMutateCount(pidx, 1)
		return req
	}
}

func (fuzzer *Fuzzer) DoTriage(ret execQueues) *queue.Request {
	/* ret := TriageResult{
		minimizeGainRaw:  0.0,
		verifyGainRaw:    0.0,
		verifyTime:       0.0,
		verifyCalls:      0,
		minimizeTime:     0.0,
		minimizeCalls:    0,
		source:           -1,
		sourceCost:       0.0,
		minimizeTimeSave: 0.0,
		pidx:             -1,
		success:          false,
	} */
	/* ts0 := time.Now().UnixNano()
	defer func() {
		ret.timeTotal = float64(time.Now().UnixNano()-ts0) / proc.fuzzer.fuzzerConfig.MABTimeUnit
	}() */

	/* item := proc.fuzzer.workQueue.dequeueType(2, true, true)
	if item == nil {
		return ret
	} */
	fuzzer.writeLog("%s", "# WorkTriage\n")
	var req *queue.Request
	// Triage first
	if fuzzer.fuzzerConfig.MABTriageFirst {
		/* // Skip all MAB stuff for triaging
		item := fuzzer.workQueue.dequeueType(2, true, true)
		if item != nil {
			fuzzer.ProcessItem(item)
			return
		} */
		req = ret.triageCandidateQueue.Next()
		if req != nil {
			return req
		}
	
		req = ret.triageQueue.Next()
		if req != nil {
			return req
		}	
	/* _, r := proc.ProcessItem(item)
	_ret, ok := r.(TriageResult)
	if !ok {
		return ret
	}
	ret = _ret
	proc.fuzzer.writeLog("# Triage Result: %+v\n", ret) */
	}
	return req
}

func (fuzzer *Fuzzer) MABLoop(ret execQueues) *queue.Request {							// copied from syzvegas/proc.go
	// Update Weight
	/* if fuzzer.MABRound % 100 == 0 {
		fuzzer.MABUpdateWeight(choice, r, pr_arr, K)
	} */

	var req *queue.Request
	// Triage first
	if fuzzer.fuzzerConfig.MABTriageFirst {
		/* // Skip all MAB stuff for triaging
		item := fuzzer.workQueue.dequeueType(2, true, true)
		if item != nil {
			fuzzer.ProcessItem(item)
			return
		} */
		req := ret.triageCandidateQueue.Next()
		if req != nil {
			return req
		}
		req = ret.triageQueue.Next()
		if req != nil {
			return req
		}
		return nil
	}
	// Compute weight and proba
	ts0 := time.Now().UnixNano()
	weight := fuzzer.MABGetWeight(true)
	// corpus := proc.fuzzer.corpusSnapshot()
	fuzzerSnapshot := fuzzer.snapshot()
	triage_count := 1
	mutate_count := 1
	if len(fuzzerSnapshot.corpus) == 0 { // Check whether mutation is an option
		mutate_count = 0
	}
	ql_triage := ret.triageQueue.Len()
	ql_triageCandidate := ret.triageCandidateQueue.Len()
	// proc.fuzzer.writeLog("- Triage Queue Length: %v + %v\n", ql_triage, ql_triageCandidate)

	if ql_triage+ql_triageCandidate == 0 {
		triage_count = 0
	}
	K := 1 + mutate_count + triage_count
	W := weight[0] + float64(mutate_count)*weight[1] + float64(triage_count)*weight[2]
	if W == 0.0 {
		fuzzer.writeLog("WTF: Error total weight W = 0")
	}
	gamma := fuzzer.MABGamma
	if fuzzer.fuzzerConfig.MABAlgorithm == "Exp3-IX" {
		// No explicit exploration for Exp3-IX
		gamma = 0
	}
	pr_generate := (1-gamma)*weight[0]/W + gamma/float64(K)
	pr_mutate := (1-gamma)*weight[1]/W + gamma/float64(K)
	pr_triage := (1-gamma)*weight[2]/W + gamma/float64(K)
	if fuzzer.fuzzerConfig.MABAlgorithm == "Exp3-IX" {
		pr_generate = weight[0] / W
		pr_mutate = weight[1] / W
		pr_triage = weight[2] / W
	}
	_pr_mutate := float64(mutate_count) * pr_mutate
	_pr_triage := float64(triage_count) * pr_triage
	pr_arr := []float64{pr_generate, _pr_mutate, _pr_triage} // Use real weight as pr. Consider cases where triage/mutation might be unavailable
	fuzzer.writeLog("- MAB Probability: [%v, %v, %v]\n", pr_arr[0], pr_arr[1], pr_arr[2])
	// Choose
	rand_num := rand.Float64() * (pr_generate + _pr_mutate + _pr_triage)
	choice := -1
	if rand_num <= pr_generate {
		choice = 0
	} else if rand_num > pr_generate && rand_num <= pr_generate+_pr_mutate {
		choice = 1
	} else {
		choice = 2
	}
	ts1 := time.Now().UnixNano()
	fuzzer.writeLog("- MAB Choose: %v\n", ts1-ts0)
	// Handle choices
	var r interface{}
	if choice == 0 {
		req = fuzzer.DoGenerate()
	} else if choice == 1 {
		req = fuzzer.DoMutate(ret, fuzzer.fuzzerConfig.MutateWeight)
	} else if choice == 2 {
		req = fuzzer.DoTriage(ret)
		// cost_before_min = float64(r.verifyTime) / 3.0 / proc.fuzzer.fuzzerConfig.MABTimeUnit
	}
	fuzzer.writeLog("- MAB Choice: %v, Result: %+v\n", choice, r)
	// Update Weight
	// fuzzer.MABUpdateWeight(choice, r, pr_arr, K)
	return req
}

func (fuzzer *Fuzzer) MAB_SQ(ret execQueues) *queue.Request {				// the original one is proc.go/loop()
	// generatePeriod = proc.fuzzer.fuzzerConfig.mutateWeight/proc.fuzzer.fuzzerConfig.generateWeight + 1
	fuzzer.MABRound += 1
	var req *queue.Request
	if fuzzer.MABRound <= fuzzer.fuzzerConfig.MABGenerateFirst {
		// Force Generate First
		fuzzer.MABRound += 1
		rnd := fuzzer.rand()
		// ts0 := time.Now().UnixNano()
		req = genProgRequest(fuzzer, rnd)
		fuzzer.writeLog("# %v Generate\n")
		// fuzzer.logProgram(p)
		fuzzer.writeLog("- Work Type: 0\n")
		return req
	}
	if fuzzer.fuzzerConfig.MABAlgorithm != "N/A" {
		req = fuzzer.DoCandidate(ret) // Deal with candidates first
		if req != nil {
			return req
		} else if fuzzer.fuzzerConfig.MABDuration <= 0 || fuzzer.MABRound < fuzzer.fuzzerConfig.MABDuration {
			req = fuzzer.MABLoop(ret)
			if req != nil {
				return req
			}
		} else if fuzzer.fuzzerConfig.MABDuration > 0 && fuzzer.MABRound >= fuzzer.fuzzerConfig.MABDuration {
			// Reset params
			fuzzer.ResetConfig()
			return nil
		}
	}
	
	/* item := fuzzer.workQueue.dequeue()		// check whether source is empty
	if item != nil {
		itemType, r := proc.ProcessItem(item)
		if itemType == 1 && proc.fuzzer.fuzzerConfig.MABSeedSelection != "N/A" {
			proc.fuzzer.MABUpdateWeight(1, r, []float64{1.0, 1.0, 1.0}, 1.0)
		}
		proc.fuzzer.writeLog("- Work Type: %v, Result: %+v\n", itemType, r)
		// Don't count triage under NoMutations setup
		if itemType == 2 && proc.fuzzer.fuzzerConfig.MABNoMutations > 0 {
			proc.fuzzer.MABRound -= 1
		}
		continue
	} */
	return req
}

// copied from syzvegas
func (fuzzer *Fuzzer) newTriage(inp rpctype.RPCTriage) {
	if !fuzzer.fuzzerConfig.SyncTriage {
		return
	}
	ts0 := time.Now().UnixNano()
	defer func() {
		ts1 := time.Now().UnixNano()
		fuzzer.writeLog("- MAB NewTriage: %v\n", ts1-ts0)
	}()
	// Update local record
	fuzzer.triages[inp.Sig] = 0
	// Update local buffer for sync
	if _, ok := fuzzer.triagesUnfinished[inp.Sig]; !ok {
		fuzzer.triagesUnfinished[inp.Sig] = make([]rpctype.RPCTriage, 0)
	}
	fuzzer.triagesUnfinished[inp.Sig] = append(fuzzer.triagesUnfinished[inp.Sig], inp)
	// Triage Info for corpus target
	if fuzzer.fuzzerConfig.MABTargetCorpus {
		if _, ok := fuzzer.MABTriageInfo[inp.Sig]; !ok {
			fuzzer.MABTriageInfo[inp.Sig] = &glc.TriageInfo{}
		}
		fuzzer.MABTriageInfo[inp.Sig].TriageTotal += 1
		fuzzer.MABTriageInfo[inp.Sig].Source = inp.Source
		fuzzer.MABTriageInfo[inp.Sig].SourceCost = inp.SourceCost
		fuzzer.writeLog("- MAB NewTriageInfo %+v\n", fuzzer.MABTriageInfo[inp.Sig])
	}
}

func (fuzzer *Fuzzer) completeTriage(inp rpctype.RPCTriage) {
	if !fuzzer.fuzzerConfig.SyncTriage {
		return
	}
	ts0 := time.Now().UnixNano()
	defer func() {
		ts1 := time.Now().UnixNano()
		fuzzer.writeLog("- MAB CompleteTriage: %v\n", ts1-ts0)
	}()
	// Delete local record
	if _, ok := fuzzer.triages[inp.Sig]; ok {
		fuzzer.triages[inp.Sig] = 1
	}
	if _, ok := fuzzer.triagesUnfinished[inp.Sig]; ok {
		delete(fuzzer.triagesUnfinished, inp.Sig)
	}
}

func (fuzzer *Fuzzer) logSignal(sign signal.Signal, prefix string) {
	for e := range sign {
		fuzzer.writeLog("%s %x\n", prefix, e)
	}
}