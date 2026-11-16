#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
root="$(git rev-parse --show-toplevel)"
start="$(git -C "$root" status --porcelain --untracked-files=all)"
[[ -z "$start" ]] || { echo R07_SOURCE_DIRTY=RED; exit 10; }
snapshot(){
 for p in "$HOME/.local" "$GITHUB_WORKSPACE/.local"; do
  if [[ -d "$p" ]];then find "$p" -type f -printf '%P %s %T@\n' | LC_ALL=C sort | sha256sum;else echo ABSENT;fi
 done
}
locals_before="$(snapshot)"
vols_before="$(docker volume ls -q | LC_ALL=C sort)"
case "$R07_TARGET" in
  aarch64) target_libc=arm64 ;;
  riscv64) target_libc=riscv64 ;;
  *) echo R07_TARGET_UNSUPPORTED=RED; exit 11 ;;
esac
image="public-sandbox-r07-${R07_TARGET}:${GITHUB_SHA:0:12}"
cleanup(){ docker image rm -f "$image" >/dev/null 2>&1 || true; docker builder prune -af >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker pull ubuntu:24.04 >/dev/null
base="$(docker image inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04)"
[[ "$base" == *@sha256:* ]] || { echo R07_BASE_NOT_PINNED=RED; exit 12; }
echo "R07_BUILDER_DIGEST=$base"
DOCKER_BUILDKIT=1 docker build --pull --no-cache --build-arg "BASE_IMAGE=$base" --build-arg "TARGET=$R07_TARGET" --build-arg "TARGET_LIBC=$target_libc" -t "$image" .
python3 - "$image" "$R07_TARGET" <<'PY'
import json, platform, subprocess, time, statistics, re, sys, os
image,isa=sys.argv[1:]
def run(kind):
 cmd=["docker","run","--rm","--network","none","--read-only","--user","65532:65532",
 "--cap-drop","ALL","--security-opt","no-new-privileges",
 "--pids-limit","64","--memory","192m","--memory-swap","192m","--cpus","1",
 "--entrypoint","/native" if kind=="native" else "/qemu",image]
 if kind=="foreign":cmd.append("/foreign")
 begin=time.monotonic_ns()
 r=subprocess.run(cmd,text=True,capture_output=True,timeout=30)
 wall=time.monotonic_ns()-begin
 marker=re.search(r"R07_WORKLOAD_RESULT=PASS ISA=([^ ]+) SUM=([0-9]+) COMPUTE_NS=([0-9]+)",r.stdout)
 if r.returncode!=0 or marker is None or int(marker[2])!=50000005000000 or int(marker[3])<=0:
  print("R07_WORKLOAD_ORACLE=RED",kind,"exit",r.returncode,"out",r.stdout[-800:],"err",r.stderr[-800:])
  raise SystemExit(13)
 if marker[1]!=("native-x86_64" if kind=="native" else isa):
  print("R07_REPORTED_ISA_MISMATCH=RED",kind,marker[1]);raise SystemExit(14)
 return {"compute_ns":int(marker[3]),"launch_wall_ns":wall}
# Two uncounted warmup reps per class, followed by eight measured paired reps.
for kind in ("native","foreign"):
 for _ in range(2):run(kind)
observed={"native":[],"foreign":[]}
for i in range(8):
 for kind in (("native","foreign") if i%2==0 else ("foreign","native")):
  observed[kind].append(run(kind))
median={k:statistics.median(x["compute_ns"] for x in v) for k,v in observed.items()}
launch={k:statistics.median(x["launch_wall_ns"] for x in v) for k,v in observed.items()}
assert min(median.values())>0
report={
 "scope":"synthetic_10M_loop_only",
 "host_class":"github-hosted-standard-ubuntu-24.04",
 "host_arch":platform.machine(),"host_visible_cpus":os.cpu_count(),
 "guest_isa":isa,"repetitions":8,"warmup_reps_each":2,
 "native_compute_ns_samples":[r["compute_ns"] for r in observed["native"]],
 "foreign_compute_ns_samples":[r["compute_ns"] for r in observed["foreign"]],
 "native_compute_ns_median":median["native"],
 "foreign_compute_ns_median":median["foreign"],
 "foreign_to_native_compute_ratio_on_same_runner":round(median["foreign"]/median["native"],3),
 "native_container_launch_wall_ns_median":launch["native"],
 "foreign_container_launch_wall_ns_median":launch["foreign"],
}
print("R07_PAIRED_CORRECTNESS_AND_REPEATS=PASS")
print("R07_SAME_RUNNER_COMPUTE_ENVELOPE="+json.dumps(report,sort_keys=True))
print("R07_GUI_AGENT_REAL_WORKLOAD=NOT_TESTED")
print("R07_CROSS_HOST_AND_WYSE_TRANSFER=NOT_QUALIFIED")
PY
[[ "$(docker volume ls -q | LC_ALL=C sort)" == "$vols_before" ]] || { echo R07_VOLUME_TAINT=RED; exit 15; }
[[ "$(snapshot)" == "$locals_before" ]] || { echo R07_LOCAL_TAINT=RED; exit 16; }
[[ "$(git -C "$root" status --porcelain --untracked-files=all)" == "$start" ]] || { echo R07_CHECKOUT_TAINT=RED; exit 17; }
cleanup;trap - EXIT
if docker image inspect "$image" >/dev/null 2>&1;then echo R07_IMAGE_TAINT=RED; exit 18;fi
echo R07_DISPOSABLE_TOOLCHAIN_RUNTIME_TEARDOWN=PASS
echo R07_HOME_PROJECT_LOCAL_AND_SOURCE_ZERO_TAINT=PASS
