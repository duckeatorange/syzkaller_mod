// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math/rand"
	"sort"
	"fmt"
	                                         
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/pkg/config"
)

type ProgramsList struct {
	fuzzerConfig   *config.FuzzerConfig
	progs    []*prog.Prog				// original name is corpus
	sumPrios float64
	corpusPriosSum []float64
	accPrios []float64					// original name is corpusPrios
	// workQueue      *WorkQueue
}

func (pl *ProgramsList) chooseProgram(r *rand.Rand) (int, *prog.Prog) {
	if len(pl.progs) == 0 {
		return 0, nil
	}
	randVal := 0.0
	randVal = r.Float64() * pl.sumPrios
	// randVal := r.Int63n(pl.sumPrios + 1)
	pidx := sort.Search(len(pl.corpusPriosSum), func(i int) bool {
	// idx := sort.Search(len(pl.accPrios), func(i int) bool {
		return pl.corpusPriosSum[i] >= randVal
		// return pl.accPrios[i] >= randVal
	})
	if pl.fuzzerConfig.MABVerbose {
		if len(pl.accPrios) > 10 {
			fmt.Printf("- Corpus Priority %v, %v...%v\n", pl.accPrios[pidx], pl.accPrios[:5], pl.accPrios[(len(pl.accPrios)-5):])
			fmt.Printf("- Corpus Priority Sum %v, %v...%v, %v\n", pl.corpusPriosSum[pidx], pl.corpusPriosSum[:5], pl.corpusPriosSum[(len(pl.accPrios)-5):], pl.sumPrios)
		} else {
			fmt.Printf("- Corpus Priority %v\n", pl.accPrios)
			fmt.Printf("- Corpus Priority Sum %v, %v\n", pl.corpusPriosSum, pl.sumPrios)
		}
	}
	if pidx >= len(pl.progs) {
		pidx = len(pl.progs) - 1
		fmt.Printf("- Error. chooseProgram out of bound. %v/%v\n", pidx, len(pl.progs))
	}
	return pidx, pl.progs[pidx]
	// return pl.progs[idx]
}

func (pl *ProgramsList) saveProgram(p *prog.Prog, signal signal.Signal) {
	prio := float64(len(signal))
	if prio == 0 {
		prio = 1
	}
	pl.sumPrios += prio
	pl.accPrios = append(pl.accPrios, pl.sumPrios)
	pl.progs = append(pl.progs, p)
}

func (corpus *Corpus) ChooseProgram(r *rand.Rand) (int, *prog.Prog) {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	if len(corpus.progsMap) == 0 {
		return 0, nil
	}
	// We could have used an approach similar to chooseProgram(), but for small number
	// of focus areas that is an overkill.
	var randArea *focusAreaState
	if len(corpus.focusAreas) > 0 {
		sum := 0.0
		nonEmpty := make([]*focusAreaState, 0, len(corpus.focusAreas))
		for _, area := range corpus.focusAreas {
			if len(area.progs) == 0 {
				continue
			}
			sum += area.Weight
			nonEmpty = append(nonEmpty, area)
		}
		val := r.Float64() * sum
		currSum := 0.0
		for _, area := range nonEmpty {
			if val >= currSum {
				randArea = area
			}
			currSum += area.Weight
		}
	}
	if randArea != nil {
		return randArea.chooseProgram(r)
	}
	return corpus.chooseProgram(r)
}

func (corpus *Corpus) Programs() []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progs
}
