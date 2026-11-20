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
	"strconv"
	"sync"
	"syscall"
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
	// compileScratchEnv names the directory a worker keeps its scratch
	// files in. The parent creates it and removes it when the pool closes,
	// since a worker it kills never gets to remove its own.
	compileScratchEnv = "SPM_LIBSECCOMP_COMPILE_SCRATCH"
	// compileTimeout is far above what any compile in these tests takes.
	// A compile that exceeds it either never returns or ran on a heavily
	// loaded machine, which is why compile retries it once before it
	// reports a hang.
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

// optimizeEnv names the libseccomp optimization level the whole run compiles
// with. Unset, libseccomp sorts the syscalls of a filter by priority, as
// crun and runc for a small profile have it do. Set to 2, it sorts them
// into a binary tree, which is how runc compiles a profile naming more than
// 32 syscalls. The workers inherit it with the environment.
const optimizeEnv = "SPM_LIBSECCOMP_OPTIMIZE"

func TestMain(m *testing.M) {
	if value := os.Getenv(optimizeEnv); value != "" {
		level, err := strconv.ParseUint(value, 10, 32)
		if err != nil || (level != 0 && level != libseccomp.BinaryTree) {
			// A value that is not read would quietly repeat the default run.
			fmt.Fprintf(os.Stderr, "%s=%q: want 0 or %d\n",
				optimizeEnv, value, libseccomp.BinaryTree)
			os.Exit(2)
		}

		libseccomp.SetOptimize(uint32(level))
	}

	if os.Getenv(compileWorkerEnv) != "" {
		os.Exit(serveCompiles(os.Getenv(compileScratchEnv), os.Stdin, os.Stdout))
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
// compiled program or the failure. It keeps its scratch files in a
// directory of its own below root, which the parent removes.
func serveCompiles(root string, requests io.Reader, responses io.Writer) int {
	if root == "" {
		return 1
	}

	scratch, err := os.MkdirTemp(root, "worker")
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

func startCompileWorker(scratch string) (*compileWorker, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find test binary: %w", err)
	}

	cmd := exec.CommandContext(context.Background(), executable, "-test.run=^$")

	cmd.Env = append(os.Environ(), compileWorkerEnv+"=1", compileScratchEnv+"="+scratch)
	// A worker dies with the test binary, so that one stuck in a compile
	// does not outlive a run that times out.
	cmd.SysProcAttr = new(syscall.SysProcAttr)
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
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

// stop ends the worker and returns its exit status.
func (w *compileWorker) stop() error {
	_ = w.stdin.Close()
	_ = w.cmd.Process.Kill()

	err := w.cmd.Wait()
	if err != nil {
		return fmt.Errorf("exit: %w", err)
	}

	return nil
}

// withExit adds how the worker exited to the error its pipes reported.
func withExit(err, exitErr error) error {
	switch {
	case exitErr == nil:
		return err
	case err == nil:
		return exitErr
	default:
		return fmt.Errorf("%w (%w)", err, exitErr)
	}
}

// compilerPool hands out workers, one per concurrent compile.
type compilerPool struct {
	mu    sync.Mutex
	idle  []*compileWorker
	slots chan struct{}
	// scratch is the directory the workers keep their scratch files in,
	// created with the first worker and removed by close. A run killed
	// before close, as by -test.timeout, leaves it behind; its workers die
	// with the run, and the directory holds at most their empty
	// subdirectories.
	scratch string
}

var compilers = &compilerPool{
	mu:    sync.Mutex{},
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

	if p.scratch == "" {
		scratch, err := os.MkdirTemp("", "spm-libseccomp")
		if err != nil {
			<-p.slots

			return nil, fmt.Errorf("worker scratch: %w", err)
		}

		p.scratch = scratch
	}

	worker, err := startCompileWorker(p.scratch)
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
		_ = worker.stop()
	}

	p.idle = nil

	if p.scratch != "" {
		_ = os.RemoveAll(p.scratch)
		p.scratch = ""
	}
}

// compile builds the profile with libseccomp in a worker. It returns
// errCompileHang when libseccomp does not return twice in a row,
// errRuleConflict when it refuses a rule with EEXIST, and errCompileFailed
// for anything else. A compile past the timeout is retried once, in a fresh
// worker, so that a compile a loaded machine delays is not taken for one
// libseccomp never finishes, which the tests leave out of the comparison.
func (p *compilerPool) compile(profile *specs.LinuxSeccomp) ([]libseccomp.Instruction, error) {
	prog, err := p.compileOnce(profile)
	if errors.Is(err, errCompileHang) {
		prog, err = p.compileOnce(profile)
	}

	return prog, err
}

// compileOnce is one attempt of compile.
func (p *compilerPool) compileOnce(profile *specs.LinuxSeccomp) ([]libseccomp.Instruction, error) {
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
		// finishes before the pipes are closed. A nil error means the
		// compile finished as the timer fired: its response stands, only
		// the worker is lost.
		_ = worker.cmd.Process.Kill()

		err = <-done
		exitErr := worker.stop()

		p.release(nil)

		if err != nil {
			return nil, fmt.Errorf("%w: %w", errCompileHang, withExit(err, exitErr))
		}

		return response.result()
	}

	if err != nil {
		exitErr := worker.stop()

		p.release(nil)

		return nil, fmt.Errorf("%w: %w", errWorkerExited, withExit(err, exitErr))
	}

	p.release(worker)

	return response.result()
}

// result reads the response of a compile.
func (r compileResponse) result() ([]libseccomp.Instruction, error) {
	switch {
	case r.Conflict:
		return nil, fmt.Errorf("%w: %s", errRuleConflict, r.Err)
	case r.Err != "":
		return nil, fmt.Errorf("%w: %s", errCompileFailed, r.Err)
	default:
		return r.Prog, nil
	}
}
