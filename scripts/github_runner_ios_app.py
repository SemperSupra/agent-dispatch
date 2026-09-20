#!/usr/bin/env python3
"""Bounded iOS Simulator app lifecycle qualification for macos-26-intel."""
from __future__ import annotations
import argparse,json,os,pathlib,platform,plistlib,shutil,sys,tempfile,time,uuid

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import github_runner_frontier as frontier

BUNDLE_ID="com.sempersupra.runnerfrontier"
SOURCE=r'''
#import <UIKit/UIKit.h>
@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(strong,nonatomic) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window=[[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc=[UIViewController new];
    vc.view.backgroundColor=[UIColor whiteColor];
    self.window.rootViewController=vc;
    [self.window makeKeyAndVisible];
    return YES;
}
@end
int main(int argc,char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc,argv,nil,NSStringFromClass([AppDelegate class]));
    }
}
'''

def main():
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",required=True)
    a=p.parse_args()
    receipt={
      "schema":"github-runner-ios-simulator-app-qualification/v1",
      "provenance":{"requested_label":a.label,"workflow_sha":os.environ.get("GITHUB_SHA",""),
        "run_id":os.environ.get("GITHUB_RUN_ID",""),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
        "image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},
      "runner":{"system":platform.system(),"machine":platform.machine()},
      "workload":{"id":"ios-simulator-app-build-install-launch","bundle_id":BUNDLE_ID},
      "result":{"classification":"INCONCLUSIVE","passed":False,"reason":"not executed","evidence":{}},
      "warnings":["workload qualification is exact-image evidence and does not imply ARM macOS Simulator support"]
    }
    def finish(cls,passed,reason,ev):
        receipt["result"]={"classification":cls,"passed":passed,"reason":reason,"evidence":ev}
        out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print("IOS_APP_RECEIPT="+str(out));print(json.dumps(receipt,indent=2,sort_keys=True));return 0
    if platform.system()!="Darwin" or platform.machine()!="x86_64" or a.label!="macos-26-intel":
        return finish("SKIPPED_GUARDRAIL",False,"qualification is pinned to proven macos-26-intel Simulator lane",{})
    xcrun=shutil.which("xcrun");codesign=shutil.which("codesign")
    if not xcrun or not codesign:
        return finish("SKIPPED_GUARDRAIL",False,"xcrun/codesign entry gate failed",
                      {"xcrun":bool(xcrun),"codesign":bool(codesign)})
    runtime,devtype,entry=frontier._latest_ios_and_iphone(xcrun)
    if not runtime or not devtype:
        return finish("SKIPPED_GUARDRAIL",False,"compatible iOS runtime/device entry gate failed",entry)
    sc,sdk,se=frontier._run([xcrun,"--sdk","iphonesimulator","--show-sdk-path"],20)
    cc,clang,ce=frontier._run([xcrun,"--sdk","iphonesimulator","--find","clang"],20)
    if sc!=0 or cc!=0:
        return finish("ORACLE_FAILURE",False,"Simulator SDK/compiler lookup failed",
                      {"sdk_exit":sc,"clang_exit":cc,"stderr":(se+"\n"+ce)[:1200]})
    with tempfile.TemporaryDirectory(prefix="runner-ios-app-") as td:
        root=pathlib.Path(td);app=root/"RunnerFrontier.app";app.mkdir()
        src=root/"main.m";src.write_text(SOURCE,encoding="utf-8")
        exe=app/"RunnerFrontier"
        plist={
          "CFBundleDevelopmentRegion":"en","CFBundleExecutable":"RunnerFrontier",
          "CFBundleIdentifier":BUNDLE_ID,"CFBundleInfoDictionaryVersion":"6.0",
          "CFBundleName":"RunnerFrontier","CFBundleDisplayName":"RunnerFrontier","CFBundlePackageType":"APPL",
          "CFBundleShortVersionString":"1.0","CFBundleVersion":"1",
          "CFBundleSupportedPlatforms":["iPhoneSimulator"],"DTPlatformName":"iphonesimulator",
          "LSRequiresIPhoneOS":True,"MinimumOSVersion":"18.0","UIDeviceFamily":[1],
          "UILaunchScreen":{},
        }
        with (app/"Info.plist").open("wb") as fh: plistlib.dump(plist,fh)
        build_start=time.monotonic()
        bc,bo,be=frontier._run([clang,"-fobjc-arc","-target","x86_64-apple-ios18.0-simulator",
            "-isysroot",sdk,str(src),"-framework","UIKit","-framework","Foundation","-o",str(exe)],60)
        build_s=time.monotonic()-build_start
        if bc!=0 or not exe.exists():
            return finish("HARNESS_FAILURE",False,"minimal Simulator app failed to compile",
                          {"compile_exit":bc,"stderr":be[-1500:],"sdk":sdk,"clang":clang})
        signc,signo,signe=frontier._run([codesign,"--force","--sign","-","--timestamp=none",str(app)],30)
        verifyc,verifyo,verifye=frontier._run([codesign,"--verify","--strict","--deep",str(app)],20)
        plistc,plisto,pliste=frontier._run(["/usr/bin/plutil","-lint",str(app/"Info.plist")],10)
        if signc!=0 or verifyc!=0 or plistc!=0:
            return finish("HARNESS_FAILURE",False,"app bundle signing/structure validation failed",
                          {"codesign_exit":signc,"verify_exit":verifyc,"plist_exit":plistc,
                           "stderr":"\n".join(x for x in (signe,verifye,pliste) if x)[-1600:]})
        name="RunnerApp-"+uuid.uuid4().hex[:8]
        create,udid,create_err=frontier._run([xcrun,"simctl","create",name,devtype["identifier"],runtime["identifier"]],30)
        udid=udid.strip()
        if create!=0 or not udid:
            return finish("ORACLE_FAILURE",False,"disposable Simulator creation failed",
                          {"create_exit":create,"stderr":create_err[-1200:],"runtime":runtime.get("identifier"),
                           "device_type":devtype.get("identifier")})
        boot=None;state=None;state_err=None;polls=0
        service=guest=install=container=launch=terminate=None
        service_out=guest_out=install_err=container_err=launch_err=terminate_err=""
        container_path=launch_out=""
        try:
            boot,_,boot_err=frontier._run([xcrun,"simctl","boot",udid],30)
            deadline=time.monotonic()+90
            while boot==0 and time.monotonic()<deadline:
                polls+=1;state,state_err=frontier._device_state(xcrun,udid)
                if state=="Booted":break
                time.sleep(2)
            if boot==0 and state=="Booted":
                service,service_out,service_err=frontier._run([xcrun,"simctl","getenv",udid,"HOME"],15)
                guest,guest_out,guest_err=frontier._run([xcrun,"simctl","spawn",udid,"/usr/bin/true"],15)
            if guest==0:
                install,_,install_err=frontier._run([xcrun,"simctl","install",udid,str(app)],30)
            if install==0:
                container,container_path,container_err=frontier._run(
                    [xcrun,"simctl","get_app_container",udid,BUNDLE_ID,"app"],20)
            if container==0:
                launch,launch_out,launch_err=frontier._run(
                    [xcrun,"simctl","launch","--terminate-running-process",udid,BUNDLE_ID],30)
            if launch==0:
                terminate,_,terminate_err=frontier._run([xcrun,"simctl","terminate",udid,BUNDLE_ID],20)
            passed=(boot==0 and state=="Booted" and guest==0 and install==0 and container==0 and bool(container_path.strip()) and
                    launch==0 and terminate==0)
        finally:
            frontier._run([xcrun,"simctl","shutdown",udid],20)
            frontier._run([xcrun,"simctl","delete",udid],20)
        ev={"runtime":runtime.get("identifier"),"runtime_version":runtime.get("version"),
            "device_type":devtype.get("identifier"),"sdk":sdk,"build_elapsed_seconds":round(build_s,3),
            "boot_exit":boot,"final_state":state,"state_polls":polls,"state_error":state_err,
            "service_exit":service,"service_value_nonempty":bool(service_out.strip()),
            "guest_spawn_exit":guest,"install_exit":install,"container_exit":container,
            "container_path_nonempty":bool(container_path.strip()),"launch_exit":launch,
            "launch_output":launch_out[:500] if launch_out else None,"terminate_exit":terminate,
            "stderr":"\n".join(x for x in (locals().get("service_err",""),locals().get("guest_err",""),
                install_err,container_err,launch_err,terminate_err) if x)[:1800] or None}
        return finish("SUPPORTED" if passed else "ORACLE_FAILURE",passed,
                      "built, installed, launched, observed, and terminated a disposable iOS Simulator app"
                      if passed else "iOS Simulator app lifecycle oracle failed",ev)

if __name__=="__main__":raise SystemExit(main())
