package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

var (
	guardLayer = wf.SublayerID{Data1: 0x3db4f89f, Data2: 0x1796, Data3: 0x419a, Data4: [8]byte{0xa7, 0x68, 0x43, 0xe1, 0xa7, 0x17, 0x65, 0x74}}
	families   = []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6}
	wfp        = windows.NewLazySystemDLL("fwpuclnt.dll")
	iphlp      = windows.NewLazySystemDLL("iphlpapi.dll")
)

const (
	wfpAlreadyExists = windows.Errno(0x80320009)
	wfpFilterMissing = windows.Errno(0x80320003)
)

func guardRule(path, appID string, family int, luid uint64) *wf.Rule {
	kind := "block"
	action := wf.ActionBlock
	weight := uint64(10)
	conditions := []*wf.Match{{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: appID}}
	if luid != 0 {
		kind = "tunnel"
		action = wf.ActionPermit
		weight = 20
		conditions = append(conditions, &wf.Match{Field: wf.FieldIPNexthopInterface, Op: wf.MatchTypeEqual, Value: luid})
	}
	hash := sha256.Sum256([]byte(fmt.Sprintf("Forten/v1/%s/%d/%s", kind, family, path)))
	guid := fmt.Sprintf("{%x-%x-%x-%x-%x}", hash[:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
	id, _ := windows.GUIDFromString(guid)
	return &wf.Rule{
		ID: wf.RuleID(id), Name: "Forten " + kind, Description: path,
		Sublayer: guardLayer, Layer: families[family], Conditions: conditions,
		Action: action, Weight: weight, Persistent: luid == 0,
	}
}

func installBlocks(paths []string) error {
	s, err := wf.New(&wf.Options{Name: "Forten persistent guard"})
	if err != nil {
		return err
	}
	defer s.Close()
	err = s.AddSublayer(&wf.Sublayer{ID: guardLayer, Name: "Forten application guard", Persistent: true, Weight: 0xE000})
	if err != nil && !errors.Is(err, wfpAlreadyExists) {
		return err
	}
	for _, path := range paths {
		appID, err := wf.AppID(path)
		if err != nil {
			return fmt.Errorf("identify %s: %w", path, err)
		}
		for family := range families {
			err = s.AddRule(guardRule(path, appID, family, 0))
			if err != nil && !errors.Is(err, wfpAlreadyExists) {
				return fmt.Errorf("block %s: %w", path, err)
			}
		}
	}
	return nil
}

func tunnelPermits(paths []string, luid uint64) (*wf.Session, error) {
	if luid == 0 {
		return nil, errors.New("cannot identify Forten tunnel interface")
	}
	s, err := wf.New(&wf.Options{Name: "Forten active tunnel", Dynamic: true})
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		appID, err := wf.AppID(path)
		if err == nil {
			for family := range families {
				if err = s.AddRule(guardRule(path, appID, family, luid)); err != nil {
					break
				}
			}
		}
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("permit TUN for %s: %w", path, err)
		}
	}
	return s, nil
}

func releaseBlocks(paths []string) error {
	s, err := wf.New(&wf.Options{Name: "Forten guard removal"})
	if err != nil {
		return err
	}
	defer s.Close()
	for _, path := range paths {
		for family := range families {
			id := guardRule(path, "", family, 0).ID
			if err := s.DeleteRule(id); err != nil && !errors.Is(err, wfpFilterMissing) {
				return err
			}
		}
	}
	return nil
}

func filtersPresent(paths []string, luid uint64) (bool, error) {
	if len(paths) == 0 {
		return true, nil
	}
	var engine windows.Handle
	result, _, _ := wfp.NewProc("FwpmEngineOpen0").Call(0, 10, 0, 0, uintptr(unsafe.Pointer(&engine)))
	if result != 0 {
		return false, windows.Errno(result)
	}
	defer wfp.NewProc("FwpmEngineClose0").Call(uintptr(engine))
	get := wfp.NewProc("FwpmFilterGetByKey0")
	free := wfp.NewProc("FwpmFreeMemory0")
	for _, path := range paths {
		for family := range families {
			id := guardRule(path, "", family, luid).ID
			var pointer uintptr
			result, _, _ := get.Call(uintptr(engine), uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&pointer)))
			if result == uintptr(wfpFilterMissing) {
				return false, nil
			}
			if result != 0 {
				return false, windows.Errno(result)
			}
			free.Call(uintptr(unsafe.Pointer(&pointer)))
		}
	}
	return true, nil
}

func interfaceLUID(name string) (uint64, error) {
	alias, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var luid uint64
	result, _, _ := iphlp.NewProc("ConvertInterfaceAliasToLuid").Call(uintptr(unsafe.Pointer(alias)), uintptr(unsafe.Pointer(&luid)))
	if result != 0 {
		return 0, windows.Errno(result)
	}
	return luid, nil
}
