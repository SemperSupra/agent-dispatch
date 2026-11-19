package main
import ("path";"strings")

// qualificationMode is only an OFFLINE proposal. It never disables an
// existing workflow. Release heads must always run the FULL gate.
func qualificationMode(changed []string,releaseHead bool)(string,string){
 if releaseHead{return "FULL","release-candidate approval requires complete exact-head regression"}
 if len(changed)==0{return "FULL","missing diff cannot justify fast admission"}
 for _,p:=range changed{
  if p==""||path.IsAbs(p)||path.Clean(p)!=p||p=="."||p==".."||strings.HasPrefix(p,"../")||strings.ContainsRune(p,92){
   return "FULL","ambiguous source path"
  }
  if strings.HasPrefix(p,".github/workflows/"){
   return "FULL","workflow topology changed"
  }
  if strings.HasPrefix(p,"experiments/usb-fabric-r26/integrated/")||
     strings.HasPrefix(p,"experiments/usb-fabric-r26/releasegate/") {
   return "FULL","security-critical QMP, guest, journal or API implementation"
  }
  if !(strings.HasPrefix(p,"experiments/usb-fabric-r26/workcells/")||
       strings.HasPrefix(p,"experiments/usb-fabric-r26/r27h/")) {
   return "FULL","unclassified path"
  }
 }
 return "TARGETED_CANDIDATE","non-runtime research workcell paths only"
}
