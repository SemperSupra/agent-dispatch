#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
before="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$before" ]] || { echo R10_INPUT_DIRTY=RED; exit 10; }
snapshot(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
local_before="$(snapshot)"
vol_before="$(docker volume ls -q | LC_ALL=C sort)"
case "$R10_TARGET" in
  aarch64) target_libc=arm64 ;;
  riscv64) target_libc=riscv64 ;;
  *) echo R10_TARGET_UNSUPPORTED=RED;exit 11 ;;
esac
tag="public-r10-${R10_TARGET}:${GITHUB_SHA:0:12}"
cleanup(){
 docker image rm -f "$tag" >/dev/null 2>&1 || true
 docker builder prune -af >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull ubuntu:24.04 >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$base" == *@sha256:* ]] || { echo R10_BASE_DIGEST_INVALID=RED;exit 12; }
echo "R10_BASE_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --pull --no-cache -f Dockerfile \
 --build-arg "BASE_IMAGE=$base" --build-arg "TARGET=$R10_TARGET" \
 --build-arg "TARGET_LIBC=$target_libc" -t "$tag" .
python3 - "$tag" "$R10_TARGET" <<'PY'
import json,os,platform,subprocess,time,statistics,re,sys
tag,foreign=sys.argv[1:]
classes=("integer","memory","syscall")
expected={"integer":2000001000000,"memory":4278190080,"syscall":30000}
def run(isa,cls):
 cmd=["docker","run","--rm","--network","none","--read-only",
      "--user","65532:65532","--cap-drop","ALL",
      "--security-opt","no-new-privileges","--memory","192m",
      "--memory-swap","192m","--cpus","1","--pids-limit","64",
      "--entrypoint","/native" if isa=="native" else "/qemu",tag]
 if isa=="foreign":cmd.append("/foreign")
 cmd.append(cls)
 start=time.perf_counter_ns()
 r=subprocess.run(cmd,capture_output=True,text=True,timeout=35)
 launch=time.perf_counter_ns()-start
 m=re.search(r"R10_TASK_RESULT=PASS ISA=([^ ]+) CLASS=([^ ]+) RESULT=([0-9]+) COMPUTE_NS=([0-9]+)",r.stdout)
 if r.returncode!=0 or not m:
  print("R10_ORACLE_FAILED=RED",isa,cls,"rc",r.returncode,"out",r.stdout[-600:],"err",r.stderr[-600:])
  raise SystemExit(13)
 want="native-x86_64" if isa=="native" else foreign
 if m[1]!=want or m[2]!=cls or int(m[3])!=expected[cls] or int(m[4])<=0:
  print("R10_WRONG_RESULT_OR_ISA=RED",isa,cls,m.groups())
  raise SystemExit(14)
 return {"compute_ns":int(m[4]),"launch_ns":launch}
observed={}
for cls in classes:
 for isa in ("native","foreign"):run(isa,cls)
 observed[cls]={"native":[],"foreign":[]}
 for i in range(6):
  for isa in (("native","foreign") if i%2==0 else ("foreign","native")):
   observed[cls][isa].append(run(isa,cls))
def stats(rows):
 vals=[v["compute_ns"] for v in rows]
 mid=statistics.median(vals)
 return {"median_ns":mid,
         "min_ns":min(vals),"max_ns":max(vals),
         "median_abs_deviation_ns":statistics.median(abs(n-mid) for n in vals),
         "samples_ns":vals,
         "container_launch_median_ns":statistics.median(x["launch_ns"] for x in rows)}
report={}
for cls,v in observed.items():
 report[cls]={key:stats(rows) for key,rows in v.items()}
 report[cls]["foreign_to_native_median_ratio"]=round(report[cls]["foreign"]["median_ns"]/report[cls]["native"]["median_ns"],3)
host_model=""
try:
 for line in open("/proc/cpuinfo"):
  if line.startswith("model name"):
   host_model=line.split(":",1)[1].strip()
   break
except OSError:pass
print("R10_REPEATED_MULTICLASS_CORRECTNESS=PASS")
print("R10_EVIDENCE="+json.dumps({
 "scope":"public_synthetic_native_vs_qemu_user_not_full_system",
 "host_class":"github-hosted-standard-ubuntu-24.04","host_isa":platform.machine(),
 "cpu_model":host_model[:150],"visible_cpus":os.cpu_count(),
 "target_isa":foreign,"replicates":6,"warmups":1,
 "native_target_compilers_differ":True,"workloads":report
},sort_keys=True))
print("R10_UNCONTROLLED_CODEGEN_AND_HOST_VARIATION=LIMITATION")
print("R10_GUI_HUMAN_AGENT_WORKLOADS=NOT_TESTED")
print("R10_USABLE_PERFORMANCE_ENVELOPE=NOT_QUALIFIED")
PY
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vol_before" ]] || { echo R10_VOLUME_TAINT=RED;exit 15; }
[[ "$(snapshot)" == "$local_before" ]] || { echo R10_LOCAL_TAINT=RED;exit 16; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$before" ]] || { echo R10_CHECKOUT_TAINT=RED;exit 17; }
cleanup;trap - EXIT
if docker image inspect "$tag" >/dev/null 2>&1;then echo R10_IMAGE_TAINT=RED;exit 18;fi
echo "R10_DISPOSABLE_COMPILERS_AND_GUEST_RUNTIME_CLEANUP=PASS"
echo "R10_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS"
