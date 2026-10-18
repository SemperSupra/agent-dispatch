#!/usr/bin/env python3
"""Public-safe probe of latent hardware/accelerator surfaces on hosted runners."""
from __future__ import annotations

import argparse
import glob
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_census as passive

PROBE_VERSION = "public-latent-hardware/2"


def _run(argv: list[str], timeout: int = 30) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", f"{type(exc).__name__}: {exc}"


def _cap(name: str, *, observed: bool | None, installed: bool | None,
         callable_: bool | None, exercised: bool, oracle: bool,
         classification: str, reason: str, evidence: Any = None) -> dict[str, Any]:
    return {
        "name": name,
        "advertised": None,
        "observed": observed,
        "installed": installed,
        "callable": callable_,
        "exercised": exercised,
        "oracleSatisfied": oracle,
        "classification": classification,
        "reason": reason,
        "evidence": evidence,
    }


def _selected_cpu_features() -> dict[str, bool]:
    selected = {
        "aes", "avx", "avx2", "avx512f", "avx512bw", "avx512vl", "fma",
        "bmi1", "bmi2", "sha_ni", "amx_tile", "amx_int8", "amx_bf16", "vmx", "svm",
        "asimd", "neon", "crc32", "atomics", "sha1", "sha2", "sha3", "sha512",
        "sve", "sve2",
    }
    found: set[str] = set()
    if platform.system() == "Linux":
        path = pathlib.Path("/proc/cpuinfo")
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key.strip().lower() in {"flags", "features"}:
                    found.update(value.strip().lower().split())
    elif platform.system() == "Darwin":
        code, out, _ = _run(["sysctl", "-a"], timeout=10)
        if code == 0:
            lowered = out.lower()
            aliases = {
                "aes": ("hw.optional.aes: 1", "hw.optional.arm.feat_aes: 1"),
                "avx": ("hw.optional.avx1_0: 1",),
                "avx2": ("hw.optional.avx2_0: 1",),
                "avx512f": ("hw.optional.avx512f: 1",),
                "neon": ("hw.optional.neon: 1",),
                "sha1": ("hw.optional.arm.feat_sha1: 1",),
                "sha2": ("hw.optional.arm.feat_sha256: 1",),
            }
            for feature, needles in aliases.items():
                if any(needle in lowered for needle in needles):
                    found.add(feature)
    return {name: name in found for name in sorted(selected)}


def probe_cpu_features() -> dict[str, Any]:
    features = _selected_cpu_features()
    present = [name for name, value in features.items() if value]
    return _cap(
        "cpu:instruction-surface",
        observed=bool(present), installed=None, callable_=None, exercised=False, oracle=False,
        classification="INCONCLUSIVE" if present else "NEGATIVE_OBSERVATION",
        reason="selected CPU instruction features observed; no instruction oracle executed"
               if present else "none of the selected instruction features were observed",
        evidence={"features": features},
    )


def _existing(patterns: list[str]) -> list[str]:
    paths: set[str] = set()
    for pattern in patterns:
        paths.update(glob.glob(pattern))
    return sorted(paths)


def _pci_accelerators() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    root = pathlib.Path("/sys/bus/pci/devices")
    if not root.exists():
        return rows
    for dev in sorted(root.iterdir()):
        try:
            cls = (dev / "class").read_text().strip().lower().removeprefix("0x")
            vendor = (dev / "vendor").read_text().strip().lower()
            device = (dev / "device").read_text().strip().lower()
        except OSError:
            continue
        if cls.startswith("03") or cls.startswith("12") or cls.startswith("0207"):
            rows.append({"bdf": dev.name, "class": cls, "vendor": vendor, "device": device})
    return rows


def probe_linux_surfaces() -> list[dict[str, Any]]:
    if platform.system() != "Linux":
        return []
    surface_patterns = {
        "linux:gpu-dri-render-surface": ["/dev/dri/renderD*"],
        "linux:nvidia-device-surface": ["/dev/nvidia[0-9]*", "/dev/nvidiactl"],
        "linux:rocm-kfd-surface": ["/dev/kfd"],
        "linux:rdma-device-surface": ["/dev/infiniband/*", "/sys/class/infiniband/*"],
        "linux:fpga-device-surface": ["/sys/class/fpga_manager/*", "/sys/class/fpga_region/*"],
        "linux:accelerator-class-surface": ["/dev/accel/*", "/sys/class/accel/*"],
        "linux:vfio-device-surface": ["/dev/vfio/*"],
    }
    caps: list[dict[str, Any]] = []
    for name, patterns in surface_patterns.items():
        paths = _existing(patterns)
        caps.append(_cap(
            name, observed=bool(paths), installed=None, callable_=None, exercised=False, oracle=False,
            classification="INCONCLUSIVE" if paths else "NEGATIVE_OBSERVATION",
            reason="device/sysfs surface observed; no workload oracle executed"
                   if paths else "no matching device/sysfs surface observed",
            evidence={"paths": paths},
        ))

    pci = _pci_accelerators()
    caps.append(_cap(
        "linux:pci-accelerator-surface", observed=bool(pci), installed=None, callable_=None,
        exercised=False, oracle=False,
        classification="INCONCLUSIVE" if pci else "NEGATIVE_OBSERVATION",
        reason="interesting PCI class observed; not proof of guest usability"
               if pci else "no display/processing-accelerator/InfiniBand PCI class observed",
        evidence={"devices": pci},
    ))

    commands = {
        "nvidia-smi": ["-L"],
        "rocminfo": [],
        "vulkaninfo": ["--summary"],
        "clinfo": ["-l"],
        "rdma": ["link", "show"],
        "ibv_devices": [],
        "vainfo": [],
    }
    for command, args in commands.items():
        exe = shutil.which(command)
        if not exe:
            caps.append(_cap(
                f"command:{command}:query", observed=False, installed=False, callable_=False,
                exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                reason=f"{command} is not installed",
            ))
            continue
        code, out, err = _run([exe, *args], timeout=20)
        ok = code == 0
        caps.append(_cap(
            f"command:{command}:query", observed=True, installed=True, callable_=ok,
            exercised=True, oracle=ok,
            classification="SUPPORTED" if ok else "ORACLE_FAILURE",
            reason=f"{command} query succeeded" if ok else f"{command} exists but query failed",
            evidence={"exit_code": code, "stdout": out[:3000] or None, "stderr": err[:1200] or None},
        ))
    return caps



def probe_linux_rdma_uverbs() -> dict[str, Any]:
    if platform.system() != "Linux":
        return _cap("linux:rdma-uverbs-active-port", observed=False, installed=False,
                    callable_=False, exercised=False, oracle=False,
                    classification="SKIPPED_GUARDRAIL", reason="RDMA uverbs probe is Linux-only")
    devices = _existing(["/dev/infiniband/uverbs*"])
    if not devices:
        return _cap("linux:rdma-uverbs-active-port", observed=False, installed=False,
                    callable_=False, exercised=False, oracle=False,
                    classification="NEGATIVE_OBSERVATION", reason="no uverbs device observed")

    opens: dict[str, str] = {}
    for path in devices:
        try:
            fd = os.open(path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
            os.close(fd)
            opens[path] = "OPEN"
        except OSError as exc:
            opens[path] = f"{type(exc).__name__}:{exc.errno}"

    ports: list[dict[str, str | None]] = []
    root = pathlib.Path("/sys/class/infiniband")
    if root.exists():
        for dev in sorted(root.iterdir()):
            port_root = dev / "ports"
            if not port_root.exists():
                continue
            for port in sorted(port_root.iterdir()):
                def read(name: str) -> str | None:
                    try:
                        return (port / name).read_text(errors="replace").strip()
                    except OSError:
                        return None
                ports.append({
                    "device": dev.name,
                    "port": port.name,
                    "state": read("state"),
                    "phys_state": read("phys_state"),
                })

    opened = any(value == "OPEN" for value in opens.values())
    active = any(
        item.get("state") and "ACTIVE" in str(item.get("state"))
        for item in ports
    )
    ok = opened and active
    return _cap(
        "linux:rdma-uverbs-active-port",
        observed=True, installed=True, callable_=opened, exercised=True, oracle=ok,
        classification="SUPPORTED" if ok else "ORACLE_FAILURE",
        reason=("ordinary runner user opened uverbs and an RDMA port reports ACTIVE; "
                "this proves control-path access, not RDMA data transfer")
               if ok else
               "uverbs device exists but ordinary-user open + active-port oracle was not satisfied",
        evidence={"uverbs": opens, "ports": ports},
    )


_METAL_SWIFT = r'''
import Foundation
import Metal
import CoreGraphics

var result: [String: Any] = ["metal_device": false, "oracle": false]
if let device = MTLCreateSystemDefaultDevice() {
    result["metal_device"] = true
    result["name"] = device.name
    result["registryID"] = String(device.registryID)
    result["lowPower"] = device.isLowPower
    result["removable"] = device.isRemovable
    if let queue = device.makeCommandQueue(),
       let src = device.makeBuffer(length: 8, options: .storageModeShared),
       let dst = device.makeBuffer(length: 8, options: .storageModeShared),
       let command = queue.makeCommandBuffer(),
       let blit = command.makeBlitCommandEncoder() {
        let nonce: UInt64 = 0x43454E5355534D54
        src.contents().bindMemory(to: UInt64.self, capacity: 1).pointee = nonce
        dst.contents().bindMemory(to: UInt64.self, capacity: 1).pointee = 0
        blit.copy(from: src, sourceOffset: 0, to: dst, destinationOffset: 0, size: 8)
        blit.endEncoding()
        command.commit()
        command.waitUntilCompleted()
        let got = dst.contents().bindMemory(to: UInt64.self, capacity: 1).pointee
        result["commandStatus"] = command.status.rawValue
        result["oracle"] = (got == nonce && command.status == .completed)
    }
}
let data = try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
print(String(data: data, encoding: .utf8)!)
'''


_METAL_COMPUTE_SWIFT = r'''
import Foundation
import Metal
import CoreGraphics

let kernelSource = """
#include <metal_stdlib>
using namespace metal;
kernel void add_one(device const uint *input [[buffer(0)]],
                    device uint *output [[buffer(1)]],
                    uint id [[thread_position_in_grid]]) {
    output[id] = input[id] + 1;
}
"""

var result: [String: Any] = ["metal_device": false, "oracle": false]
if let device = MTLCreateSystemDefaultDevice() {
    result["metal_device"] = true
    result["name"] = device.name
    do {
        let library = try device.makeLibrary(source: kernelSource, options: nil)
        if let function = library.makeFunction(name: "add_one") {
            let pipeline = try device.makeComputePipelineState(function: function)
            if let queue = device.makeCommandQueue(),
           let src = device.makeBuffer(length: 4, options: .storageModeShared),
           let dst = device.makeBuffer(length: 4, options: .storageModeShared),
           let command = queue.makeCommandBuffer(),
           let encoder = command.makeComputeCommandEncoder() {
            let nonce: UInt32 = 0x13572468
            src.contents().bindMemory(to: UInt32.self, capacity: 1).pointee = nonce
            dst.contents().bindMemory(to: UInt32.self, capacity: 1).pointee = 0
            encoder.setComputePipelineState(pipeline)
            encoder.setBuffer(src, offset: 0, index: 0)
            encoder.setBuffer(dst, offset: 0, index: 1)
            encoder.dispatchThreads(
                MTLSize(width: 1, height: 1, depth: 1),
                threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1)
            )
            encoder.endEncoding()
            command.commit()
            command.waitUntilCompleted()
            let got = dst.contents().bindMemory(to: UInt32.self, capacity: 1).pointee
            result["commandStatus"] = command.status.rawValue
            result["expected"] = UInt64(nonce) + 1
            result["observed"] = UInt64(got)
            result["oracle"] = (got == nonce + 1 && command.status == .completed)
            }
        } else {
            result["error"] = "kernel function missing"
        }
    } catch {
        result["error"] = String(describing: error)
    }
}
let data = try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
print(String(data: data, encoding: .utf8)!)
'''

_COREML_OBJC = r'''
#import <Foundation/Foundation.h>
#import <CoreML/CoreML.h>
int main(void) {
  @autoreleasepool {
    NSMutableArray *names = [NSMutableArray array];
    if (@available(macOS 14.0, *)) {
      for (id device in MLAllComputeDevices()) {
        [names addObject:NSStringFromClass([device class]) ?: @"unknown"];
      }
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:@{@"classes": names}
                                                   options:NSJSONWritingSortedKeys error:nil];
    puts([[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] UTF8String]);
  }
  return 0;
}
'''

_VT_OBJC = r'''
#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
int main(void) {
  @autoreleasepool {
    CFArrayRef encoders = NULL;
    OSStatus status = VTCopyVideoEncoderList(NULL, &encoders);
    NSUInteger hw = 0;
    NSUInteger total = 0;
    if (status == noErr && encoders) {
      NSArray *array = CFBridgingRelease(encoders);
      total = array.count;
      for (NSDictionary *item in array) {
        if ([item[(NSString *)kVTVideoEncoderList_IsHardwareAccelerated] boolValue]) hw++;
      }
    }
    NSDictionary *result = @{
      @"encoder_status": @(status),
      @"encoder_count": @(total),
      @"hardware_encoder_count": @(hw),
      @"h264_hw_decode": @(VTIsHardwareDecodeSupported(kCMVideoCodecType_H264)),
      @"hevc_hw_decode": @(VTIsHardwareDecodeSupported(kCMVideoCodecType_HEVC))
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:result
                                                   options:NSJSONWritingSortedKeys error:nil];
    puts([[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] UTF8String]);
  }
  return 0;
}
'''


def _compile_run_macos(source: str, suffix: str, compile_args: list[str],
                       timeout: int = 60) -> tuple[str, dict[str, Any]]:
    if platform.system() != "Darwin":
        return "SKIPPED_GUARDRAIL", {"reason": "macOS-only"}
    xcrun = shutil.which("xcrun")
    if not xcrun:
        return "NEGATIVE_OBSERVATION", {"reason": "xcrun not installed"}
    with tempfile.TemporaryDirectory(prefix="runner-latent-") as td:
        src = pathlib.Path(td) / f"probe{suffix}"
        exe = pathlib.Path(td) / "probe"
        src.write_text(source, encoding="utf-8")
        code, out, err = _run([xcrun, *compile_args, str(src), "-o", str(exe)], timeout=timeout)
        if code != 0:
            return "HARNESS_FAILURE", {
                "compile_exit": code, "compile_stdout": out[:1200] or None,
                "compile_stderr": err[:2000] or None,
            }
        code, out, err = _run([str(exe)], timeout=timeout)
        if code != 0:
            return "ORACLE_FAILURE", {
                "run_exit": code, "stdout": out[:1500] or None, "stderr": err[:1500] or None,
            }
        try:
            return "OK", json.loads(out.splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return "HARNESS_FAILURE", {"run_exit": code, "stdout": out[:2000] or None}


def probe_macos_metal() -> dict[str, Any]:
    if platform.system() != "Darwin":
        return _cap("macos:metal-blit-nonce", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Metal probe is macOS-only")
    state, evidence = _compile_run_macos(
        _METAL_SWIFT, ".swift",
        ["--sdk", "macosx", "swiftc", "-O", "-framework", "Metal", "-framework", "CoreGraphics"],
    )
    if state != "OK":
        return _cap("macos:metal-blit-nonce", observed=None, installed=True, callable_=False,
                    exercised=state == "ORACLE_FAILURE", oracle=False, classification=state,
                    reason=evidence.get("reason", "Metal probe could not complete"), evidence=evidence)
    has_device = bool(evidence.get("metal_device"))
    oracle = bool(evidence.get("oracle"))
    if not has_device:
        classification, reason = "NEGATIVE_OBSERVATION", "Metal framework callable but no default MTLDevice exposed"
    elif oracle:
        classification, reason = "SUPPORTED", "default Metal device completed a GPU blit nonce oracle"
    else:
        classification, reason = "ORACLE_FAILURE", "Metal device exists but blit nonce oracle failed"
    return _cap("macos:metal-blit-nonce", observed=has_device, installed=True, callable_=has_device,
                exercised=has_device, oracle=oracle, classification=classification,
                reason=reason, evidence=evidence)



def probe_macos_metal_compute() -> dict[str, Any]:
    if platform.system() != "Darwin":
        return _cap("macos:metal-compute-nonce", observed=False, installed=False,
                    callable_=False, exercised=False, oracle=False,
                    classification="SKIPPED_GUARDRAIL", reason="Metal compute probe is macOS-only")
    state, evidence = _compile_run_macos(
        _METAL_COMPUTE_SWIFT, ".swift",
        ["--sdk", "macosx", "swiftc", "-O", "-framework", "Metal", "-framework", "CoreGraphics"],
    )
    if state != "OK":
        return _cap("macos:metal-compute-nonce", observed=None, installed=True, callable_=False,
                    exercised=state == "ORACLE_FAILURE", oracle=False, classification=state,
                    reason="Metal compute probe could not complete", evidence=evidence)
    has_device = bool(evidence.get("metal_device"))
    oracle = bool(evidence.get("oracle"))
    if not has_device:
        classification, reason = "NEGATIVE_OBSERVATION", "no default MTLDevice exposed"
    elif oracle:
        classification, reason = "SUPPORTED", "Metal compute kernel transformed a nonce correctly"
    else:
        classification, reason = "ORACLE_FAILURE", "Metal device exists but compute-kernel oracle failed"
    return _cap(
        "macos:metal-compute-nonce", observed=has_device, installed=True, callable_=has_device,
        exercised=has_device, oracle=oracle, classification=classification,
        reason=reason, evidence=evidence,
    )

def probe_macos_coreml_devices() -> list[dict[str, Any]]:
    if platform.system() != "Darwin":
        return []
    state, evidence = _compile_run_macos(
        _COREML_OBJC, ".m",
        ["--sdk", "macosx", "clang", "-fobjc-arc", "-framework", "Foundation", "-framework", "CoreML"],
    )
    if state != "OK":
        return [_cap(
            "macos:coreml-compute-device-enumeration", observed=None, installed=True, callable_=False,
            exercised=state == "ORACLE_FAILURE", oracle=False, classification=state,
            reason="Core ML compute-device enumeration could not complete", evidence=evidence,
        )]
    classes = [str(item) for item in evidence.get("classes", [])]
    caps = [_cap(
        "macos:coreml-compute-device-enumeration", observed=True, installed=True, callable_=True,
        exercised=True, oracle=True, classification="SUPPORTED",
        reason="MLAllComputeDevices returned successfully", evidence={"classes": classes},
    )]
    lowered = " ".join(classes).lower()
    for slug, needle in (("cpu", "cpucomputedevice"), ("gpu", "gpucomputedevice"),
                         ("neural-engine", "neuralenginecomputedevice")):
        present = needle in lowered
        caps.append(_cap(
            f"macos:coreml-{slug}-surface", observed=present, installed=None, callable_=None,
            exercised=False, oracle=False,
            classification="INCONCLUSIVE" if present else "NEGATIVE_OBSERVATION",
            reason=f"Core ML {slug} compute-device object exposed; execution not proven"
                   if present else f"Core ML {slug} compute-device object not observed",
            evidence={"classes": classes},
        ))
    return caps


def probe_macos_videotoolbox() -> dict[str, Any]:
    if platform.system() != "Darwin":
        return _cap("macos:videotoolbox-hardware-surface", observed=False, installed=False,
                    callable_=False, exercised=False, oracle=False,
                    classification="SKIPPED_GUARDRAIL", reason="VideoToolbox probe is macOS-only")
    state, evidence = _compile_run_macos(
        _VT_OBJC, ".m",
        ["--sdk", "macosx", "clang", "-fobjc-arc", "-framework", "Foundation",
         "-framework", "VideoToolbox", "-framework", "CoreMedia"],
    )
    if state != "OK":
        return _cap("macos:videotoolbox-hardware-surface", observed=None, installed=True,
                    callable_=False, exercised=state == "ORACLE_FAILURE", oracle=False,
                    classification=state, reason="VideoToolbox capability query could not complete",
                    evidence=evidence)
    query_ok = evidence.get("encoder_status") == 0
    observed = bool(evidence.get("hardware_encoder_count")) or bool(evidence.get("h264_hw_decode")) or bool(evidence.get("hevc_hw_decode"))
    if not query_ok:
        classification, oracle = "ORACLE_FAILURE", False
        reason = "VideoToolbox hardware capability query returned an error"
    elif observed:
        classification, oracle = "SUPPORTED", True
        reason = "VideoToolbox reports hardware encode/decode capability; codec execution not yet proven"
    else:
        classification, oracle = "NEGATIVE_OBSERVATION", False
        reason = "VideoToolbox query succeeded but reported no hardware encode/decode capability"
    return _cap(
        "macos:videotoolbox-hardware-surface", observed=observed, installed=True, callable_=query_ok,
        exercised=True, oracle=oracle, classification=classification,
        reason=reason, evidence=evidence,
    )


def build_receipt(label: str | None = None) -> dict[str, Any]:
    receipt = passive.build_receipt(label)
    receipt["provenance"]["probe_version"] = PROBE_VERSION
    receipt["capabilities"].append(probe_cpu_features())
    if platform.system() == "Linux":
        receipt["capabilities"].extend(probe_linux_surfaces())
        receipt["capabilities"].append(probe_linux_rdma_uverbs())
    elif platform.system() == "Darwin":
        receipt["capabilities"].append(probe_macos_metal())
        receipt["capabilities"].append(probe_macos_metal_compute())
        receipt["capabilities"].extend(probe_macos_coreml_devices())
        receipt["capabilities"].append(probe_macos_videotoolbox())
    receipt["warnings"].extend([
        "latent hardware observations are not workload-placement claims",
        "device/API presence is not promoted to SUPPORTED unless the named oracle is satisfied",
        "Core ML compute-device presence does not prove a model executed on that device",
        "VideoToolbox capability queries do not prove encode/decode throughput or workload suitability",
    ])
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.label)
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"LATENT_HARDWARE_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
