// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/glc"
	"github.com/google/syzkaller/prog"
)

// add for syzvegas
type ExecResult struct {
	gainRaw   float64
	time      float64
	timeTotal float64
	calls     int
	count     int
	pidx      int
}

type TriageResult struct {
	corpusGainRaw    float64 // # sigs added to the corpus
	verifyGainRaw    float64 // # of sigs discovered by stablization
	verifyTime       float64
	verifyCalls      int
	minimizeGainRaw  float64 // # of sigs discovered by minimization
	minimizeTime     float64
	minimizeTimeSave float64
	minimizeCalls    int
	source           int
	sourceSig        hash.Sig
	sourceCost       float64
	pidx             int
	success          bool
	timeTotal        float64
}


type job interface {
	run(fuzzer *Fuzzer) 
}

type jobIntrospector interface {
	getInfo() *JobInfo
}

type JobInfo struct {
	Name  string
	Calls []string
	Type  string
	Execs atomic.Int32

	syncBuffer
}

func (ji *JobInfo) ID() string {
	return fmt.Sprintf("%p", ji)
}

func genProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	p := fuzzer.target.Generate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable())
	fuzzer.logProgram(p)
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
}

func mutateProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	_, p := fuzzer.Config.Corpus.ChooseProgram(rnd)
	if p == nil {
		return nil
	}
	fuzzer.logProgram(p)
	newP := p.Clone()
	p.ResetMAB()
	newP.Mutate(rnd,
		prog.RecommendedCalls,
		fuzzer.ChoiceTable(),
		fuzzer.Config.NoMutateCalls,
		fuzzer.Config.Corpus.Programs(),
	)
	fuzzer.logProgram(newP)
	/* if fuzzer.fuzzerConfig.MABSeedSelection != "N/A" {
		fuzzer.MABUpdateWeight(1, r, []float64{1.0, 1.0, 1.0}, 1.0)
	} */
	return &queue.Request{
		Prog:     newP,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecFuzz,
	}
}

// triageJob are programs for which we noticed potential new coverage during
// first execution. But we are not sure yet if the coverage is real or not.
// During triage we understand if these programs in fact give new coverage,
// and if yes, minimize them and add to corpus.
type triageJob struct {
	p        *prog.Prog
	executor queue.ExecutorID
	flags    ProgFlags
	fuzzer   *Fuzzer
	queue    queue.Executor
	// Set of calls that gave potential new coverage.
	calls map[int]*triageCall

	info *JobInfo
}

type triageCall struct {
	errno     int32
	newSignal signal.Signal
	info 	  *flatrpc.CallInfo

	// Filled after deflake:
	signals         [deflakeNeedRuns]signal.Signal
	stableSignal    signal.Signal
	newStableSignal signal.Signal
	cover           cover.Cover
	rawCover        []uint64
}

// As demonstrated in #4639, programs reproduce with a very high, but not 100% probability.
// The triage algorithm must tolerate this, so let's pick the signal that is common
// to 3 out of 5 runs.
// By binomial distribution, a program that reproduces 80% of time will pass deflake()
// with a 94% probability. If it reproduces 90% of time, it passes in 99% of cases.
//
// During corpus triage we are more permissive and require only 2/6 to produce new stable signal.
// Such parameters make 80% flakiness to pass 99% of time, and even 60% flakiness passes 96% of time.
// First, we don't need to be strict during corpus triage since the program has already passed
// the stricter check when it was added to the corpus. So we can do fewer runs during triage,
// and finish it sooner. If the program does not produce any stable signal any more, just flakes,
// (if the kernel code was changed, or configs disabled), then it still should be phased out
// of the corpus eventually.
// Second, even if small percent of programs are dropped from the corpus due to flaky signal,
// later after several restarts we will add them to the corpus again, and it will create lots
// of duplicate work for minimization/hints/smash/fault injection. For example, a program with
// 60% flakiness has 68% chance to pass 3/5 criteria, but it's also likely to be dropped from
// the corpus if we use the same 3/5 criteria during triage. With a large corpus this effect
// can cause re-addition of thousands of programs to the corpus, and hundreds of thousands
// of runs for the additional work. With 2/6 criteria, a program with 60% flakiness has
// 96% chance to be kept in the corpus after retriage.
const (
	deflakeNeedRuns         = 3
	deflakeMaxRuns          = 5
	deflakeNeedCorpusRuns   = 2
	deflakeMinCorpusRuns    = 4
	deflakeMaxCorpusRuns    = 6
	deflakeTotalCorpusRuns  = 20
	deflakeNeedSnapshotRuns = 2
)

func (job *triageJob) execute(req *queue.Request, flags ProgFlags) (*queue.Result, float64) {		// original code: proc.go/executeRaw(200108)
	ts := time.Now().UnixNano()
	defer job.info.Execs.Add(1)
	req.Important = true // All triage executions are important.
	ts_end := time.Now().UnixNano()
	return job.fuzzer.executeWithFlags(job.queue, req, flags), float64(ts_end-ts) / job.fuzzer.fuzzerConfig.MABTimeUnit
}

func (job *triageJob) run(fuzzer *Fuzzer) TriageResult {			// original code: proc.go/trageInput(200108)
	ts_bgn := time.Now().UnixNano()
	source_data := job.p.Serialize()
	source_sig := hash.Hash(source_data)
	if fuzzer.fuzzerConfig.SyncTriage {
		fuzzer.completeTriage(rpctype.RPCTriage{
			Sig:        source_sig,
			// CallIndex:  job.call,
			Prog:       source_data,
			Flags:      int(job.flags),
			// Info:       job.info,
			Source:     job.p.Source,
			SourceCost: job.p.CorpusGLC.Cost,
		})
	}
	source := job.p.Source
	sourceCost := job.p.CorpusGLC.Cost
	if _, ok := fuzzer.MABTriageInfo[source_sig]; ok {
		source = fuzzer.MABTriageInfo[source_sig].Source
		sourceCost = fuzzer.MABTriageInfo[source_sig].SourceCost
	}
	ret := TriageResult{
		corpusGainRaw:    0.0,
		minimizeGainRaw:  0.0,
		verifyGainRaw:    0.0,
		verifyTime:       0.0,
		verifyCalls:      0,
		minimizeTime:     0.0,
		minimizeCalls:    0,
		source:           source,
		sourceSig:        source_sig,
		sourceCost:       sourceCost,
		minimizeTimeSave: 0.0,
		pidx:             -1,
		success:          false,
		timeTotal:        0.0,
	}
	size_bgn := len(job.p.Calls)
	fuzzer.statNewInputs.Add(1)
	job.fuzzer = fuzzer
	job.info.Logf("\n%s", job.p.Serialize())
	for call, info := range job.calls {
		job.info.Logf("call #%d [%s]: |new signal|=%d%s",
			call, job.p.CallName(call), info.newSignal.Len(), signalPreview(info.newSignal))
	}

	// Compute input coverage and non-flaky signal for minimization.
	stop := job.deflake(func(req *queue.Request, flags ProgFlags) *queue.Result {
		result, _ := job.execute(req, flags) 
		return result
	}, &ret, ts_bgn, size_bgn)
	if stop {
		return ret
	}
	var wg sync.WaitGroup
	for call, info := range job.calls {
		wg.Add(1)
		go func() {
			job.handleCall(call, info, &ret)				// add ret for syzvegas
			wg.Done()
		}()
	}
	wg.Wait()
	ts_end := time.Now().UnixNano()
	ret.timeTotal = float64(ts_end-ts_bgn) / job.fuzzer.fuzzerConfig.MABTimeUnit
	// ret.minimizeGainRaw = minimizeGainRaw
	// ret.corpusGainRaw = corpusGainRaw
	// ret.minimizeTimeSave = sourceCost - minimizeTimeAfter
	// ret.minimizeTime = t_minimize
	// ret.verifyTime = t_corpus
	// ret.minimizeCalls = minimizeCalls
	// ret.verifyCalls = size_bgn * signalRuns
	ret.success = true
	return ret
}

func (job *triageJob) handleCall(call int, info *triageCall, ret *TriageResult) {
	if info.newStableSignal.Empty() {
		return
	}

	// add for syzvegas
	const signalRuns = 3
	minimizeGainRaw := 0.0
	sourceCost := ret.sourceCost
	data := job.p.Serialize()
	sig := hash.Hash(data)

	ret.success = true
	if ret.sourceCost == 0.0 {
		ret.sourceCost = ret.verifyTime / 3.0
	} else {
		ret.sourceCost = (ret.verifyTime + ret.sourceCost) / 4.0
	}
	job.fuzzer.writeLog("# %v Minimize\n", 0)
	job.fuzzer.logProgram(job.p)
	minimizeCalls := 0
	
	minimizeTimeAfter := ret.sourceCost
	size_bgn := len(job.p.Calls)

	ret.minimizeGainRaw = minimizeGainRaw
	ret.minimizeTimeSave = sourceCost - minimizeTimeAfter
	ret.minimizeCalls = minimizeCalls
	ret.verifyCalls = size_bgn * signalRuns

	p := job.p
	if job.flags&ProgMinimized == 0 {				//original code: proc.go/trageInput(200108)
		job.fuzzer.writeLog("%s\n", "# Minimize Attempt")
		p, call = job.minimize(call, info, *ret)
		if p == nil {
			return
		}
	}
	job.fuzzer.writeLog("%s\n", "# Minimize Final")
	job.fuzzer.logProgram(job.p)

	prio := signalPrio(job.p, info.info, call)
	inputSignal := signal.FromRaw(info.info.Signal, prio)
	newSignal := job.fuzzer.corpusSignalDiff(inputSignal)

	corpusGainRaw := 0.0
	if len(inputSignal) > 0 {
		corpusGainRaw = float64(len(newSignal))
	}
	ret.corpusGainRaw = corpusGainRaw

	callName := p.CallName(call)
	if !job.fuzzer.Config.NewInputFilter(callName) {
		return
	}
	if job.flags&ProgSmashed == 0 {
		numSmashes := int(math.Floor(float64(job.fuzzer.fuzzerConfig.SmashWeight) / float64(job.fuzzer.fuzzerConfig.MutateWeight)))
		for i := 0; i < numSmashes; i++ {
			job.fuzzer.startJob(job.fuzzer.statJobsSmash, &smashJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				info: &JobInfo{
					Name:  p.String(),
					Type:  "smash",
					Calls: []string{p.CallName(call)},
				},
			}, job.fuzzer.smashQueue.Next())
		}
		if job.fuzzer.Config.Comparisons && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsHints, &hintsJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
				info: &JobInfo{
					Name:  p.String(),
					Type:  "hints",
					Calls: []string{p.CallName(call)},
				},
			}, job.fuzzer.smashQueue.Next())
		}
		if job.fuzzer.Config.FaultInjection && call >= 0 {
			job.fuzzer.startJob(job.fuzzer.statJobsFaultInjection, &faultInjectionJob{
				exec: job.fuzzer.smashQueue,
				p:    p.Clone(),
				call: call,
			}, job.fuzzer.smashQueue.Next())
		}
	}

	job.fuzzer.Logf(2, "added new input for %v to the corpus: %s", callName, p)
	input := corpus.NewInput{
		Prog:     p,
		Call:     call,
		Signal:   info.stableSignal,
		Cover:    info.cover.Serialize(),
		RawCover: info.rawCover,
		CorpusGLC: glc.CorpusGLC{
			VerifyGain:       0.0,
			VerifyCost:       ret.verifyTime,
			MinimizeGain:     minimizeGainRaw,
			MinimizeCost:     ret.minimizeTime,
			MinimizeTimeSave: sourceCost - minimizeTimeAfter,
		},
	}
	job.fuzzer.writeLog("# addInputToCorpus %x: %v. Source: %v\n", sig, job.fuzzer.corpusSignal.Len(), ret.source)
	job.fuzzer.logSignal(inputSignal, "+")
	job.fuzzer.Config.Corpus.Save(input)
}

func (job *triageJob) deflake(exec func(*queue.Request, ProgFlags) *queue.Result, ret *TriageResult, ts_bgn int64, size_bgn int) (stop bool) {			// add ret for syzvegas
	job.info.Logf("deflake started")

	avoid := []queue.ExecutorID{job.executor}
	needRuns := deflakeNeedCorpusRuns
	if job.fuzzer.Config.Snapshot {
		needRuns = deflakeNeedSnapshotRuns
	} else if job.flags&ProgFromCorpus == 0 {
		needRuns = deflakeNeedRuns
	}
	prevTotalNewSignal := 0
	for run := 1; ; run++ {
		totalNewSignal := 0
		indices := make([]int, 0, len(job.calls))
		for call, info := range job.calls {
			indices = append(indices, call)
			totalNewSignal += len(info.newSignal)
		}
		if job.stopDeflake(run, needRuns, prevTotalNewSignal == totalNewSignal) {
			break
		}
		prevTotalNewSignal = totalNewSignal
		result, _time:= job.execute(&queue.Request{
			Prog:            job.p,
			ExecOpts:        setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			ReturnAllSignal: indices,
			Avoid:           avoid,
			Stat:            job.fuzzer.statExecTriage,
		}, progInTriage)
		ret.verifyTime += _time
		if result.Stop() {
			ret.timeTotal = float64(time.Now().UnixNano()-ts_bgn) / job.fuzzer.fuzzerConfig.MABTimeUnit
			ret.verifyCalls = (run + 1) * size_bgn
			ret.corpusGainRaw = 0.0
			return true
		}
		avoid = append(avoid, result.Executor)
		if result.Info == nil {
			continue // the program has failed
		}
		deflakeCall := func(call int, res *flatrpc.CallInfo) {
			info := job.calls[call]
			if info == nil {
				job.fuzzer.triageProgCall(job.p, res, call, &job.calls)
				info = job.calls[call]
			}
			if info == nil || res == nil {
				return
			}
			if len(info.rawCover) == 0 && job.fuzzer.Config.FetchRawCover {
				info.rawCover = res.Cover
			}
			// Since the signal is frequently flaky, we may get some new new max signal.
			// Merge it into the new signal we are chasing.
			// Most likely we won't conclude it's stable signal b/c we already have at least one
			// initial run w/o this signal, so if we exit after needRuns runs,
			// it won't be stable. However, it's still possible if we do more than needRuns runs.
			// But also we already observed it and we know it's flaky, so at least doing
			// cover.addRawMaxSignal for it looks useful.
			prio := signalPrio(job.p, res, call)
			newMaxSignal := job.fuzzer.Cover.addRawMaxSignal(res.Signal, prio)
			info.newSignal.Merge(newMaxSignal)
			info.cover.Merge(res.Cover)
			thisSignal := signal.FromRaw(res.Signal, prio)
			for j := needRuns - 1; j > 0; j-- {
				intersect := info.signals[j-1].Intersection(thisSignal)
				info.signals[j].Merge(intersect)
			}
			info.signals[0].Merge(thisSignal)
		}
		for i, callInfo := range result.Info.Calls {
			deflakeCall(i, callInfo)
		}
		deflakeCall(-1, result.Info.Extra)
	}
	job.info.Logf("deflake complete")
	for call, info := range job.calls {
		info.stableSignal = info.signals[needRuns-1]
		info.newStableSignal = info.newSignal.Intersection(info.stableSignal)
		job.info.Logf("call #%d [%s]: |stable signal|=%d, |new stable signal|=%d%s",
			call, job.p.CallName(call), info.stableSignal.Len(), info.newStableSignal.Len(),
			signalPreview(info.newStableSignal))
	}
	return false
}

func (job *triageJob) stopDeflake(run, needRuns int, noNewSignal bool) bool {
	if job.fuzzer.Config.Snapshot {
		return run >= needRuns+1
	}
	haveSignal := true
	for _, call := range job.calls {
		if !call.newSignal.IntersectsWith(call.signals[needRuns-1]) {
			haveSignal = false
		}
	}
	if job.flags&ProgFromCorpus == 0 {
		// For fuzzing programs we stop if we already have the right deflaked signal for all calls,
		// or there's no chance to get coverage common to needRuns for all calls.
		if run >= deflakeMaxRuns {
			return true
		}
		noChance := true
		for _, call := range job.calls {
			if left := deflakeMaxRuns - run; left >= needRuns ||
				call.newSignal.IntersectsWith(call.signals[needRuns-left-1]) {
				noChance = false
			}
		}
		if haveSignal || noChance {
			return true
		}
	} else if run >= deflakeTotalCorpusRuns ||
		noNewSignal && (run >= deflakeMaxCorpusRuns || run >= deflakeMinCorpusRuns && haveSignal) {
		// For programs from the corpus we use a different condition b/c we want to extract
		// as much flaky signal from them as possible. They have large coverage and run
		// in the beginning, gathering flaky signal on them allows to grow max signal quickly
		// and avoid lots of useless executions later. Any bit of flaky coverage discovered
		// later will lead to triage, and if we are unlucky to conclude it's stable also
		// to minimization+smash+hints (potentially thousands of runs).
		// So we run them at least 5 times, or while we are still getting any new signal.
		return true
	}
	return false
}

func (job *triageJob) minimize(call int, info *triageCall, ret TriageResult) (*prog.Prog, int) {
	job.info.Logf("[call #%d] minimize started", call)
	minimizeAttempts := 3
	if job.fuzzer.Config.Snapshot {
		minimizeAttempts = 2
	}
	stop := false
	mode := prog.MinimizeCorpus
	if job.fuzzer.Config.PatchTest {
		mode = prog.MinimizeCallsOnly
	}
	p, call := prog.Minimize(job.p, call, mode, func(p1 *prog.Prog, call1 int) bool {
		if stop {
			return false
		}
		var mergedSignal signal.Signal
		job.fuzzer.writeLog("%s\n", "# Minimize Attempt")
		p1.Source = 2
		job.fuzzer.logProgram(p1)
		t_avg := 0.0
		ret.minimizeCalls = 0
		ret.minimizeGainRaw = 0.0
		for i := 0; i < minimizeAttempts; i++ {
			result, _ := job.execute(&queue.Request{
				Prog:            p1,
				ExecOpts:        setFlags(flatrpc.ExecFlagCollectSignal),
				ReturnAllSignal: []int{call1},
				Stat:            job.fuzzer.statExecMinimize,
			}, 0)
			if result.Stop() {
				stop = true
				return false
			}
			ret.minimizeCalls += len(p1.Calls)
			ret.minimizeGainRaw += result.GainRaw
			if !reexecutionSuccess(result.Info, info.errno, call1) {
				// The call was not executed or failed.
				continue
			}
			thisSignal := getSignalAndCover(p1, result.Info, call1)
			if mergedSignal.Len() == 0 {
				mergedSignal = thisSignal
			} else {
				mergedSignal.Merge(thisSignal)
			}
			if info.newStableSignal.Intersection(mergedSignal).Len() == info.newStableSignal.Len() {
				job.info.Logf("[call #%d] minimization step success (|calls| = %d)",
					call, len(p1.Calls))
				t_avg = t_avg / float64(i+1)
				return true
			}
		}
		job.info.Logf("[call #%d] minimization step failure", call)
		return false
	})
	if stop {
		return nil, 0
	}
	return p, call
}

func reexecutionSuccess(info *flatrpc.ProgInfo, oldErrno int32, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldErrno == 0 && info.Calls[call].Error != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return info.Extra != nil && len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *flatrpc.ProgInfo, call int) signal.Signal {
	inf := info.Extra
	if call != -1 {
		inf = info.Calls[call]
	}
	if inf == nil {
		return nil
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call))
}

func signalPreview(s signal.Signal) string {
	if s.Len() > 0 && s.Len() <= 3 {
		var sb strings.Builder
		sb.WriteString(" (")
		for i, x := range s.ToRaw() {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "0x%x", x)
		}
		sb.WriteByte(')')
		return sb.String()
	}
	return ""
}

func (job *triageJob) getInfo() *JobInfo {
	return job.info
}

type smashJob struct {
	exec queue.Executor
	p    *prog.Prog
	info *JobInfo
}

func (job *smashJob) run(fuzzer *Fuzzer) ExecResult {						// original code: proc.go/smashInput(200108)
	ret := ExecResult{
		gainRaw:   0.0,
		time:      0.0,
		calls:     0,
		pidx:      -1,
		count:     0,
		timeTotal: 0.0,
	}
	ts_bgn := time.Now().UnixNano()
	sig := hash.Hash(job.p.Serialize())
	fuzzer.Logf(2, "smashing the program %s:", job.p)
	job.info.Logf("\n%s", job.p.Serialize())

	// fuzzerSnapshot := job.fuzzer.snapshot()
	pidx := -1
	if v, ok := fuzzer.corpusHashes[sig]; ok {
		pidx = v
		ret.pidx = pidx
	}
	// Mark for update if we're syncing smash
	if pidx > 0 && fuzzer.fuzzerConfig.SyncSmash {
		fuzzer.MABCorpusUpdate[pidx] = 1
		job.p.CorpusGLC.Smashed = true
		fuzzer.smashesFinished = append(fuzzer.smashesFinished, sig)
	}

	const iters = 25
	rnd := fuzzer.rand()
	for i := 0; i < iters; i++ {
		p := job.p.Clone()
		p.ResetMAB()
		fuzzer.writeLog("# %v Mutate Smash\n", i)
		fuzzer.logProgram(p)
		p.Mutate(rnd, prog.RecommendedCalls,
			fuzzer.ChoiceTable(),
			fuzzer.Config.NoMutateCalls,
			fuzzer.Config.Corpus.Programs())
		fuzzer.logProgram(p)
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:     fuzzer.statExecSmash,
		})
		if fuzzer.fuzzerConfig.MABAlgorithm == "N/A" && fuzzer.fuzzerConfig.MABSeedSelection == "N/A" && fuzzer.fuzzerConfig.SyncSmash {
			// Without MAB, we need to count mutations for smash syncing
			fuzzer.MABIncrementCorpusMutateCount(pidx, 1)
		}
		if result.Stop() {
			return ret
		}
		job.info.Execs.Add(1)
		ret.count += 1
		ret.calls += result.Calls
		ret.gainRaw += result.GainRaw
		ret.time += result.Time
	}
	ts_end := time.Now().UnixNano()
	ret.timeTotal = float64(ts_end-ts_bgn) / fuzzer.fuzzerConfig.MABTimeUnit
	return ret
}

func (job *smashJob) getInfo() *JobInfo {
	return job.info
}

func randomCollide(origP *prog.Prog, rnd *rand.Rand) *prog.Prog {
	if rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	if rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, rnd)
	if rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, rnd)
	}
	return p
}

type faultInjectionJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
}

func (job *faultInjectionJob) run(fuzzer *Fuzzer) {
	for nth := 1; nth <= 100; nth++ {
		fuzzer.Logf(2, "injecting fault into call %v, step %v",
			job.call, nth)
		newProg := job.p.Clone()
		newProg.Calls[job.call].Props.FailNth = nth
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog: newProg,
			Stat: fuzzer.statExecFaultInject,
		})
		if result.Stop() {
			return
		}
		info := result.Info
		if info != nil && len(info.Calls) > job.call &&
			info.Calls[job.call].Flags&flatrpc.CallFlagFaultInjected == 0 {
			break
		}
	}
}

type hintsJob struct {
	exec queue.Executor
	p    *prog.Prog
	call int
	info *JobInfo
}

func (job *hintsJob) run(fuzzer *Fuzzer) {
	// First execute the original program several times to get comparisons from KCOV.
	// Additional executions lets us filter out flaky values, which seem to constitute ~30-40%.
	p := job.p
	job.info.Logf("\n%s", p.Serialize())

	var comps prog.CompMap
	for i := 0; i < 3; i++ {
		result := fuzzer.execute(job.exec, &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectComps),
			Stat:     fuzzer.statExecSeed,
		})
		if result.Stop() {
			return
		}
		job.info.Execs.Add(1)
		if result.Info == nil || len(result.Info.Calls[job.call].Comps) == 0 {
			continue
		}
		got := make(prog.CompMap)
		for _, cmp := range result.Info.Calls[job.call].Comps {
			got.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
		}
		if i == 0 {
			comps = got
		} else {
			comps.InplaceIntersect(got)
		}
	}

	job.info.Logf("stable comps: %d", comps.Len())
	fuzzer.hintsLimiter.Limit(comps)
	job.info.Logf("stable comps (after the hints limiter): %d", comps.Len())

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(job.call, comps,
		func(p *prog.Prog) bool {
			defer job.info.Execs.Add(1)
			result := fuzzer.execute(job.exec, &queue.Request{
				Prog:     p,
				ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:     fuzzer.statExecHint,
			})
			return !result.Stop()
		})
}

func (job *hintsJob) getInfo() *JobInfo {
	return job.info
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *syncBuffer) Logf(logFmt string, args ...any) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	fmt.Fprintf(&sb.buf, "%s: ", time.Now().Format(time.DateTime))
	fmt.Fprintf(&sb.buf, logFmt, args...)
	sb.buf.WriteByte('\n')
}

func (sb *syncBuffer) Bytes() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Bytes()
}
