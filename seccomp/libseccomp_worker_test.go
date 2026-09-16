//go:build libseccomp

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package seccomp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/libseccomp"
)

// Some rule sets make libseccomp loop forever while it adds a rule. A hang
// inside a cgo call cannot be interrupted, so the tests compile in worker
// processes, which are killed when a compile does not return in time. A
// worker is the test binary itself, started with compileWorkerEnv set.

const (
	compileWorkerEnv = "SPM_LIBSECCOMP_COMPILE_WORKER"
	// compileTimeout is far above what any compile in these tests takes, so
	// only a compile that does not return at all hits it.
	compileTimeout = 5 * time.Second
)

var (
	// errCompileHang is returned when libseccomp does not return in time.
	errCompileHang = errors.New("libseccomp did not return")
	// errRuleConflict is returned when libseccomp refuses a rule with
	// EEXIST, which runc and crun treat as a failure to load the profile.
	errRuleConflict = errors.New("libseccomp refused a conflicting rule")
	// errCompileFailed is returned for every other compile failure.
	errCompileFailed = errors.New("libseccomp compile failed")
	// errWorkerExited is returned when a worker ends its conversation.
	errWorkerExited = errors.New("compile worker exited")
)

func TestMain(m *testing.M) {
	if os.Getenv(compileWorkerEnv) != "" {
		os.Exit(serveCompiles(os.Stdin, os.Stdout))
	}

	code := m.Run()

	compilers.close()
	os.Exit(code)
}

type compileResponse struct {
	Prog     []libseccomp.Instruction `json:"prog"`
	Conflict bool                     `json:"conflict"`
	Err      string                   `json:"err"`
}

// serveCompiles is the worker loop: it reads profiles and answers with the
// compiled program or the failure.
func serveCompiles(requests io.Reader, responses io.Writer) int {
	scratch, err := os.MkdirTemp("", "spm-libseccomp")
	if err != nil {
		return 1
	}

	defer func() { _ = os.RemoveAll(scratch) }()

	decoder := json.NewDecoder(requests)
	encoder := json.NewEncoder(responses)

	for {
		var profile specs.LinuxSeccomp

		err := decoder.Decode(&profile)
		if errors.Is(err, io.EOF) {
			return 0
		}

		if err != nil {
			return 1
		}

		prog, err := libseccomp.Compile(&profile, scratch)

		response := compileResponse{Prog: prog, Conflict: false, Err: ""}
		if err != nil {
			response.Err = err.Error()
			response.Conflict = errors.Is(err, libseccomp.ErrRuleConflict)
		}

		err = encoder.Encode(response)
		if err != nil {
			return 1
		}
	}
}

// compileWorker is one running worker process.
type compileWorker struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	encoder *json.Encoder
	decoder *json.Decoder
}

func startCompileWorker() (*compileWorker, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find test binary: %w", err)
	}

	cmd := exec.CommandContext(context.Background(), executable, "-test.run=^$")

	cmd.Env = append(os.Environ(), compileWorkerEnv+"=1")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("worker stdin: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("worker stdout: %w", err)
	}

	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("start worker: %w", err)
	}

	return &compileWorker{
		cmd:     cmd,
		stdin:   stdin,
		encoder: json.NewEncoder(stdin),
		decoder: json.NewDecoder(stdout),
	}, nil
}

func (w *compileWorker) stop() {
	_ = w.stdin.Close()
	_ = w.cmd.Process.Kill()
	_ = w.cmd.Wait()
}

// compilerPool hands out workers, one per concurrent compile.
type compilerPool struct {
	mu    sync.Mutex
	idle  []*compileWorker
	slots chan struct{}
}

var compilers = &compilerPool{
	mu:    sync.Mutex{},
	idle:  nil,
	slots: make(chan struct{}, runtime.GOMAXPROCS(0)),
}

func (p *compilerPool) acquire() (*compileWorker, error) {
	p.slots <- struct{}{}

	p.mu.Lock()
	defer p.mu.Unlock()

	if count := len(p.idle); count > 0 {
		worker := p.idle[count-1]
		p.idle = p.idle[:count-1]

		return worker, nil
	}

	worker, err := startCompileWorker()
	if err != nil {
		<-p.slots

		return nil, err
	}

	return worker, nil
}

// release returns a worker to the pool, or discards it when it is nil.
func (p *compilerPool) release(worker *compileWorker) {
	p.mu.Lock()
	if worker != nil {
		p.idle = append(p.idle, worker)
	}
	p.mu.Unlock()

	<-p.slots
}

func (p *compilerPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, worker := range p.idle {
		worker.stop()
	}

	p.idle = nil
}

// compile builds the profile with libseccomp in a worker. It returns
// errCompileHang when libseccomp does not return, errRuleConflict when it
// refuses a rule with EEXIST, and errCompileFailed for anything else.
func (p *compilerPool) compile(profile *specs.LinuxSeccomp) ([]libseccomp.Instruction, error) {
	worker, err := p.acquire()
	if err != nil {
		return nil, err
	}

	done := make(chan error, 1)

	var response compileResponse

	go func() {
		err := worker.encoder.Encode(profile)
		if err == nil {
			err = worker.decoder.Decode(&response)
		}

		done <- err
	}()

	timer := time.NewTimer(compileTimeout)
	defer timer.Stop()

	select {
	case err = <-done:
	case <-timer.C:
		// Killing the worker ends the pending read, so the goroutine
		// finishes before the pipes are closed.
		_ = worker.cmd.Process.Kill()

		<-done
		worker.stop()
		p.release(nil)

		return nil, errCompileHang
	}

	if err != nil {
		worker.stop()
		p.release(nil)

		return nil, fmt.Errorf("%w: %w", errWorkerExited, err)
	}

	p.release(worker)

	switch {
	case response.Conflict:
		return nil, fmt.Errorf("%w: %s", errRuleConflict, response.Err)
	case response.Err != "":
		return nil, fmt.Errorf("%w: %s", errCompileFailed, response.Err)
	default:
		return response.Prog, nil
	}
}
