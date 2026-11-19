package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Store struct{ dir string }

type Runtime struct {
	ID       string   `json:"id"`
	Phase    string   `json:"phase"`
	Endpoint string   `json:"endpoint"`
	Token    string   `json:"token"`
	Apps     []string `json:"apps"`
	Nodes    []string `json:"nodes"`
	LUID     uint64   `json:"luid"`
	Revision string   `json:"revision"`
	Failure  string   `json:"failure,omitempty"`
}

const (
	configFile = "settings.json"
	stateFile  = "runtime.json"
	guardFile  = "guard.json"
)

func openStore() (Store, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return Store{}, err
	}
	dir = filepath.Join(dir, "Forten")
	return Store{dir}, os.MkdirAll(dir, 0700)
}

func (s Store) path(name string) string { return filepath.Join(s.dir, name) }

func (s Store) read(name string, out any) error {
	file, err := os.Open(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := bounded(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func atomicFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".forten-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	from, err := windows.UTF16PtrFromString(file.Name())
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 10; attempt++ {
		err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return err
}

func (s Store) write(name string, data any) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return atomicFile(s.path(name), raw)
}

func (s Store) lock(name string) (*os.File, error) {
	file, err := os.OpenFile(s.path(name), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err != nil {
		file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, nil
		}
	}
	return file, err
}

func installationFile(name string) string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), name)
}

func corePath() (string, error) {
	path := installationFile("mihomo.exe")
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return "", errors.New("mihomo.exe is missing next to forten.exe; run scripts/install-core.ps1")
	}
	return path, nil
}

func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

func (s Store) checkCore(c Config) error {
	core, err := corePath()
	if err != nil {
		return err
	}
	data, err := c.render("", "", false)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(s.dir, ".validate-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := hidden(exec.CommandContext(ctx, core, "-d", s.dir, "-f", file.Name(), "-t")).CombinedOutput()
	if err != nil {
		if writeErr := atomicFile(s.path("validation.log"), output); writeErr != nil {
			return fmt.Errorf("Mihomo rejected the configuration: %w", err)
		}
		return errors.New("Mihomo rejected the configuration; see " + s.path("validation.log"))
	}
	return nil
}

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func (s Store) stop() error {
	var state Runtime
	if err := s.read(stateFile, &state); err != nil || state.ID == "" {
		return err
	}
	if err := atomicFile(s.path("stop.signal"), []byte(state.ID)); err != nil {
		return err
	}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		lock, err := s.lock("worker.lock")
		if err != nil {
			return err
		}
		if lock != nil {
			defer lock.Close()
			state.Phase = "stopped"
			state.Failure = ""
			if err := s.write(stateFile, state); err != nil {
				return err
			}
			err := os.Remove(s.path("active.yaml"))
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("worker did not finish stopping; its TUN permissions may still be active")
}

func (s Store) start(c Config, revision string, checkOnly bool) error {
	if err := s.checkCore(c); err != nil || checkOnly {
		return err
	}
	if !elevated() {
		return errors.New("run start from an Administrator terminal")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	core, err := corePath()
	if err != nil {
		return err
	}
	apps := []string{}
	for _, policy := range c.Policies {
		path, err := filepath.EvalSymlinks(policy.Exe)
		if err != nil {
			return fmt.Errorf("bound executable %s: %w", policy.Exe, err)
		}
		if !strings.EqualFold(path, policy.Exe) {
			return fmt.Errorf("bind the resolved executable path %s", path)
		}
		if strings.EqualFold(path, exe) || strings.EqualFold(path, core) {
			return errors.New("Forten and its core cannot be bound")
		}
		apps = append(apps, strings.ToLower(path))
	}
	if err := checkOtherTunnel(); err != nil {
		return err
	}
	if err := s.stop(); err != nil {
		return err
	}
	guarded := []string{}
	if err := s.read(guardFile, &guarded); err != nil {
		return err
	}
	known := map[string]bool{}
	for _, path := range guarded {
		known[path] = true
	}
	for _, path := range apps {
		if !known[path] {
			guarded = append(guarded, path)
		}
	}
	// Journal pending rules before the first WFP write so release can recover
	// a partial installation even if this process exits unexpectedly.
	if err := s.write(guardFile, guarded); err != nil {
		return err
	}
	if err := installBlocks(apps); err != nil {
		return fmt.Errorf("could not install persistent application guard: %w", err)
	}
	endpoint, err := loopbackEndpoint()
	if err != nil {
		return err
	}
	state := Runtime{
		ID: randomHex(16), Token: randomHex(32), Endpoint: endpoint,
		Phase: "starting", Apps: apps, Nodes: nodeNames(c), Revision: revision,
	}
	data, err := c.render(endpoint, state.Token, true)
	if err != nil {
		return err
	}
	if err := atomicFile(s.path("active.yaml"), data); err != nil {
		return err
	}
	if err := s.write(stateFile, state); err != nil {
		return err
	}
	cmd := hidden(exec.Command(exe, "_worker", state.ID))
	if err := cmd.Start(); err != nil {
		state.Phase, state.Failure = "failed", err.Error()
		return errors.Join(err, s.write(stateFile, state))
	}
	defer cmd.Process.Release()
	deadline := time.Now().Add(28 * time.Second)
	for time.Now().Before(deadline) {
		if err := s.read(stateFile, &state); err != nil {
			return err
		}
		switch state.Phase {
		case "running":
			return nil
		case "failed", "stopped":
			return fmt.Errorf("core failed to start (%s); see %s", state.Failure, s.path("core.log"))
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.Join(errors.New("timed out waiting for Forten TUN"), s.stop())
}

func checkOtherTunnel() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if iface.Flags&net.FlagUp != 0 && (strings.HasPrefix(name, "mihomo") || strings.HasPrefix(name, "clash")) {
			return fmt.Errorf("disable the existing Clash TUN adapter %q before starting Forten", iface.Name)
		}
	}
	return nil
}

func randomHex(size int) string {
	value := make([]byte, size)
	rand.Read(value)
	return hex.EncodeToString(value)
}

func tunLUID() (uint64, error) {
	iface, err := net.InterfaceByName(adapter)
	if err != nil {
		return 0, err
	}
	if iface.Flags&net.FlagUp == 0 {
		return 0, errors.New("Forten tunnel is down")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return 0, err
	}
	for _, address := range addrs {
		ip, _, _ := strings.Cut(address.String(), "/")
		if ip == tunnelIPv4 {
			return interfaceLUID(adapter)
		}
	}
	return 0, errors.New("Forten TUN IPv4 address is missing")
}

var localClient = &http.Client{
	Transport:     &http.Transport{Proxy: nil},
	Timeout:       900 * time.Millisecond,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (r Runtime) api(path string, out any) error {
	host, _, err := net.SplitHostPort(r.Endpoint)
	if err != nil || host != "127.0.0.1" || len(r.Token) != 64 {
		return errors.New("invalid local control endpoint")
	}
	req, err := http.NewRequest("GET", "http://"+r.Endpoint+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	res, err := localClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("core API returned %d", res.StatusCode)
	}
	if out == nil {
		return nil
	}
	data, err := bounded(res.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func newKillJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func (s Store) worker(id string) (retErr error) {
	lock, err := s.lock("worker.lock")
	if err != nil || lock == nil {
		return err
	}
	defer lock.Close()
	var state Runtime
	if err := s.read(stateFile, &state); err != nil || state.ID != id || state.Phase != "starting" {
		return err
	}
	stopRequested := func() bool {
		data, _ := os.ReadFile(s.path("stop.signal"))
		return string(data) == id
	}
	if stopRequested() {
		return nil
	}
	defer func() {
		state.Phase, state.Failure = "stopped", ""
		if retErr != nil {
			state.Phase, state.Failure = "failed", retErr.Error()
		}
		retErr = errors.Join(retErr, s.write(stateFile, state))
	}()
	core, err := corePath()
	if err != nil {
		return err
	}
	log, err := os.Create(s.path("core.log"))
	if err != nil {
		return err
	}
	defer log.Close()
	job, err := newKillJob()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	cmd := hidden(exec.Command(core, "-d", s.dir, "-f", s.path("active.yaml")))
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Process.Kill()
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	err = windows.AssignProcessToJobObject(job, handle)
	windows.CloseHandle(handle)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	exited := make(chan struct{})
	var exitErr error
	go func() {
		exitErr = cmd.Wait()
		close(exited)
	}()
	defer func() {
		// Wait for the old core to release its interface before reporting stop.
		windows.TerminateJobObject(job, 1)
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
		}
	}()
	deadline := time.Now().Add(22 * time.Second)
	for time.Now().Before(deadline) && !stopRequested() {
		select {
		case <-exited:
			return fmt.Errorf("Mihomo exited during startup: %v", exitErr)
		default:
		}
		luid, err := tunLUID()
		if err == nil && state.api("/version", nil) == nil {
			state.LUID = luid
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if stopRequested() {
		return nil
	}
	if state.LUID == 0 {
		return errors.New("TUN or authenticated core API did not become ready")
	}
	permits, err := tunnelPermits(state.Apps, state.LUID)
	if err != nil {
		return err
	}
	defer permits.Close()
	present, err := filtersPresent(state.Apps, 0)
	if err != nil || !present {
		return errors.Join(errors.New("persistent application filters are missing"), err)
	}
	state.Phase = "running"
	if err := s.write(stateFile, state); err != nil {
		return err
	}
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-exited:
			return fmt.Errorf("Mihomo exited: %v", exitErr)
		case <-tick.C:
			if stopRequested() {
				return nil
			}
			if luid, err := tunLUID(); err != nil || luid != state.LUID {
				return errors.New("Forten tunnel interface disappeared or changed")
			}
		}
	}
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return bounded(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return bounded(f)
}

func writeJSON(w io.Writer, result any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(result)
}
