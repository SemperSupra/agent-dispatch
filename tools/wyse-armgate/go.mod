module github.com/SemperSupra/agent-dispatch/tools/wyse-armgate

go 1.23.0

require (
 github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan v0.0.0
 github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit v0.0.0
)

replace github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan => ../../../policy-src/tools/wyse-modeplan
replace github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit => ../../../permit-src/tools/wyse-planpermit
