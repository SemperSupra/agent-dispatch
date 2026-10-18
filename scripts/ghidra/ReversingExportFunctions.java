// Public-safe Ghidra headless exporter: JSON metadata only, no binaries or bytes.
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ReversingExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || currentProgram == null) {
            throw new IllegalArgumentException("expected single headless output path and loaded program");
        }
        JsonObject output = new JsonObject();
        output.addProperty("schema", "ghidra-function-ranges/v1");
        output.addProperty("image_base", Long.toUnsignedString(currentProgram.getImageBase().getOffset()));
        output.addProperty("executable_format", currentProgram.getExecutableFormat());
        JsonArray functions = new JsonArray();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            if (function.isExternal() || function.isThunk()) {
                continue;
            }
            if (++count > 1024) {
                throw new IllegalStateException("bounded function census exceeded");
            }
            JsonObject f = new JsonObject();
            f.addProperty("name", function.getName());
            f.addProperty("entry", Long.toUnsignedString(function.getEntryPoint().getOffset()));
            JsonArray intervals = new JsonArray();
            AddressRangeIterator ranges = function.getBody().getAddressRanges();
            while (ranges.hasNext()) {
                AddressRange range = ranges.next();
                long start = range.getMinAddress().getOffset();
                long end = range.getMaxAddress().getOffset();
                if (Long.compareUnsigned(end, -1L) == 0) {
                    throw new IllegalStateException("range cannot be represented half-open");
                }
                JsonObject interval = new JsonObject();
                interval.addProperty("start", Long.toUnsignedString(start));
                interval.addProperty("end_exclusive", Long.toUnsignedString(end + 1));
                intervals.add(interval);
            }
            f.add("ranges", intervals);
            functions.add(f);
        }
        output.add("functions", functions);
        Path path = Path.of(args[0]).toAbsolutePath();
        Files.writeString(path, output.toString() + "\n", StandardCharsets.UTF_8);
        println("REVERSING_GHIDRA_EXPORT_FUNCTION_COUNT=" + count);
    }
}
