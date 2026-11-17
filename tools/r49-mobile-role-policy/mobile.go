// Package mobile is a plan-only admission policy for user-consented mobile
// endpoint roles. This is not native app code and cannot attest device state.
// iOS and Android are NOT assumed to be persistent hypervisor hosts.
package mobile

import (
 "errors"
 "regexp"
)

type Device struct {
 OS string `json:"os"` // android, ios, ipados
 VersionMajor int `json:"version_major"`
 EnrollmentVerified bool `json:"enrollment_verified"`
 AppSignatureVerified bool `json:"app_signature_verified"`
 UserConsented bool `json:"user_consented"`
 DeviceGeneration string `json:"device_generation"`
 BatteryPct int `json:"battery_pct"`
 Charging bool `json:"charging"`
 WifiUnmetered bool `json:"wifi_unmetered"`
 ThermalState string `json:"thermal_state"` // nominal, fair, serious, critical, unknown
 Foreground bool `json:"foreground"`
 BackgroundAuthorized bool `json:"background_authorized"`
}
type Task struct {
 Role string `json:"role"`
 Urgent bool `json:"urgent"`
 NeedsNetwork bool `json:"needs_network"`
 NeedsCamera bool `json:"needs_camera"`
 CameraPermission bool `json:"camera_permission"`
 NeedsMicrophone bool `json:"needs_microphone"`
 MicrophonePermission bool `json:"microphone_permission"`
 RequireAlwaysOn bool `json:"require_always_on"`
}
type Result struct {
 Scope string `json:"scope"`
 Role string `json:"role"`
 Execution string `json:"execution"`
}
var generationRE=regexp.MustCompile("^[a-f0-9]{64}$")
func deny(s string)error{return errors.New("DENIED:"+s)}
func Admit(d Device,t Task)(Result,error){
 r:=Result{Scope:"SYNTHETIC_POLICY_ONLY_NO_REAL_MOBILE_APP_ATTESTATION",Role:t.Role}
 if d.OS!="android"&&d.OS!="ios"&&d.OS!="ipados" {return Result{},deny("UNSUPPORTED_MOBILE_OS")}
 if d.VersionMajor<12||d.VersionMajor>99{return Result{},deny("UNKNOWN_MOBILE_RELEASE")}
 if !d.EnrollmentVerified||!d.AppSignatureVerified||!d.UserConsented||
  !generationRE.MatchString(d.DeviceGeneration){return Result{},deny("UNTRUSTED_OR_UNCONSENTED_DEVICE")}
 if d.BatteryPct<0||d.BatteryPct>100{return Result{},deny("UNTRUSTED_BATTERY_OBSERVATION")}
 if d.ThermalState!="nominal"&&d.ThermalState!="fair"&&d.ThermalState!="serious"&&
  d.ThermalState!="critical"&&d.ThermalState!="unknown" {
  return Result{},deny("UNTRUSTED_THERMAL_OBSERVATION")
 }
 if d.ThermalState=="critical"||d.ThermalState=="serious"{
  return Result{},deny("THERMAL_TASK_VETO")
 }
 if t.RequireAlwaysOn{return Result{},deny("MOBILE_NOT_UNRESTRICTED_HOST_OR_GUEST")}
 if t.NeedsCamera&&!t.CameraPermission||t.NeedsMicrophone&&!t.MicrophonePermission{
  return Result{},deny("USER_MEDIA_PERMISSION_MISSING")
 }
 if t.NeedsNetwork&&!d.WifiUnmetered{return Result{},deny("UNQUALIFIED_OR_METERED_NETWORK")}
 switch t.Role {
 case "notification":
  // Push notification delivery is OS-governed, not guaranteed. The planner
  // can accept only opportunistic intent; no on-demand SLA.
  if t.Urgent{return Result{},deny("PUSH_DOES_NOT_GUARANTEE_URGENT_WAKE")}
  r.Execution="PLATFORM_SCHEDULED_DELIVERY_UNGUARANTEED"
 case "interactive_assist","sensor_capture":
  if !d.Foreground {return Result{},deny("USER_PRESENT_FOREGROUND_REQUIRED")}
  r.Execution="FOREGROUND_APP_TASK"
 case "local_inference":
  if !d.Foreground{return Result{},deny("INFERENCE_USER_PRESENT_REQUIRED")}
  if !d.Charging&&d.BatteryPct<50{return Result{},deny("BATTERY_RESERVE_FOR_INFERENCE")}
  if d.ThermalState!="nominal" {return Result{},deny("SUSTAINED_INFERENCE_THERMAL_NOT_PROVEN")}
  r.Execution="FOREGROUND_BOUNDED_INFERENCE"
 case "background_sync":
  if t.Urgent||!d.BackgroundAuthorized{return Result{},deny("BACKGROUND_NOT_ON_DEMAND_OR_UNAUTHORIZED")}
  if !d.Charging&&d.BatteryPct<35{return Result{},deny("BACKGROUND_BATTERY_RESERVE")}
  r.Execution="OS_SCHEDULED_OPPORTUNISTIC_NO_SLA"
 default:
  return Result{},deny("MOBILE_HYPERVISOR_OR_DEVICE_ROLE_PROHIBITED")
 }
 return r,nil
}
