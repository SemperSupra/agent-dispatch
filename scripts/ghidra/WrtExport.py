# WRT3200ACM Ghidra headless evidence exporter
# @category WRT3200ACM

import json
from ghidra.program.util import DefinedDataIterator

args = getScriptArgs()
if len(args) < 1:
    raise Exception("output path argument required")
out_path = args[0]

program = currentProgram
listing = program.getListing()
fm = program.getFunctionManager()
mem = program.getMemory()
symtab = program.getSymbolTable()

functions = []
fit = fm.getFunctions(True)
while fit.hasNext() and len(functions) < 20000:
    f = fit.next()
    functions.append({
        "name": f.getName(),
        "entry": str(f.getEntryPoint()),
        "size": int(f.getBody().getNumAddresses()),
        "thunk": bool(f.isThunk())
    })

blocks = []
for b in mem.getBlocks():
    blocks.append({
        "name": b.getName(),
        "start": str(b.getStart()),
        "end": str(b.getEnd()),
        "size": int(b.getSize()),
        "read": bool(b.isRead()),
        "write": bool(b.isWrite()),
        "execute": bool(b.isExecute())
    })

entry_points = []
eit = symtab.getExternalEntryPointIterator()
while eit.hasNext() and len(entry_points) < 1024:
    entry_points.append(str(eit.next()))

strings = []
try:
    sit = DefinedDataIterator.definedStrings(program)
    while sit.hasNext() and len(strings) < 2000:
        d = sit.next()
        val = d.getValue()
        strings.append({"address": str(d.getAddress()), "value": str(val)[:512]})
except Exception as exc:
    strings = [{"export_error": str(exc)}]

instruction_count = 0
iit = listing.getInstructions(True)
while iit.hasNext():
    iit.next()
    instruction_count += 1

report = {
    "schema": "wrt8964-ghidra-analysis/v1",
    "program_name": program.getName(),
    "language_id": str(program.getLanguageID()),
    "compiler_spec_id": str(program.getCompilerSpec().getCompilerSpecID()),
    "image_base": str(program.getImageBase()),
    "executable_format": program.getExecutableFormat(),
    "function_count": int(fm.getFunctionCount()),
    "instruction_count": instruction_count,
    "memory_blocks": blocks,
    "external_entry_points": entry_points,
    "functions": functions,
    "defined_strings": strings
}
f = open(out_path, "w")
json.dump(report, f, indent=2, sort_keys=True)
f.write("\n")
f.close()
print("WRTEXPORT functions=%d instructions=%d strings=%d" % (len(functions), instruction_count, len(strings)))
