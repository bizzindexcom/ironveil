//go:build windows

package main

import "unsafe"

// hardenProcess applies process-wide mitigations before any window exists:
//   - DLLs load only from System32 (no DLL planting from the app's folder or CWD);
//   - per-monitor DPI awareness (crisp text; also declared in the manifest);
//   - strict handle checks, no Win32k extension points (AppInit DLLs) and
//     image-load restrictions where the OS supports them.
func hardenProcess() {
	if callOK(pSetDefaultDllDirectories) {
		_, _, _ = pSetDefaultDllDirectories.Call(loadLibrarySearchSystem)
	}
	if callOK(pSetProcessDpiAwarenessCtx) {
		_, _, _ = pSetProcessDpiAwarenessCtx.Call(dpiAwarenessPerMonitor2)
	}
	if !callOK(pSetProcessMitigationPolicy) {
		return
	}
	// PROCESS_MITIGATION_POLICY values (winnt.h).
	const (
		processStrictHandleCheckPolicy     = 3
		processExtensionPointDisablePolicy = 6
		processImageLoadPolicy             = 10
	)
	one := uint32(1) | uint32(1)<<1 // RaiseExceptionOnInvalidHandleReference | HandleExceptionsPermanentlyEnabled
	_, _, _ = pSetProcessMitigationPolicy.Call(processStrictHandleCheckPolicy, uintptr(unsafe.Pointer(&one)), 4)
	ext := uint32(1) // DisableExtensionPoints
	_, _, _ = pSetProcessMitigationPolicy.Call(processExtensionPointDisablePolicy, uintptr(unsafe.Pointer(&ext)), 4)
	img := uint32(1) | uint32(1)<<1 // NoRemoteImages | NoLowMandatoryLabelImages
	_, _, _ = pSetProcessMitigationPolicy.Call(processImageLoadPolicy, uintptr(unsafe.Pointer(&img)), 4)
}
