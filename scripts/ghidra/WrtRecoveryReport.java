// Derived-evidence reporter for Ghidra headless analysis of 88W8964.
// @category WRT3200ACM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.util.*;

public class WrtRecoveryReport extends GhidraScript {
    private static final Map<Long,String> COMMANDS = new LinkedHashMap<>();
    static {
        COMMANDS.put(0x0003L,"GET_HW_SPEC");
        COMMANDS.put(0x0004L,"SET_HW_SPEC");
        COMMANDS.put(0x0014L,"802_11_GET_STAT");
        COMMANDS.put(0x001aL,"BBP_REG_ACCESS");
        COMMANDS.put(0x001bL,"RF_REG_ACCESS");
        COMMANDS.put(0x001cL,"802_11_RADIO_CONTROL");
        COMMANDS.put(0x001dL,"MEM_ADDR_ACCESS");
        COMMANDS.put(0x001fL,"802_11_TX_POWER");
        COMMANDS.put(0x0020L,"802_11_RF_ANTENNA");
        COMMANDS.put(0x0050L,"BROADCAST_SSID_ENABLE");
        COMMANDS.put(0x008fL,"SET_CFG");
        COMMANDS.put(0x010aL,"SET_RF_CHANNEL");
        COMMANDS.put(0x010dL,"SET_AID");
        COMMANDS.put(0x010eL,"SET_INFRA_MODE");
        COMMANDS.put(0x0113L,"802_11_RTS_THSD");
        COMMANDS.put(0x0115L,"SET_EDCA_PARAMS");
        COMMANDS.put(0x0120L,"802_11H_DETECT_RADAR");
        COMMANDS.put(0x0123L,"SET_WMM_MODE");
        COMMANDS.put(0x0124L,"HT_GUARD_INTERVAL");
        COMMANDS.put(0x0126L,"SET_FIXED_RATE");
        COMMANDS.put(0x0127L,"SET_IES");
        COMMANDS.put(0x0129L,"SET_LINKADAPT_CS_MODE");
        COMMANDS.put(0x0142L,"DUMP_OTP_DATA");
        COMMANDS.put(0x0202L,"SET_MAC_ADDR");
        COMMANDS.put(0x0203L,"SET_RATE_ADAPT_MODE");
        COMMANDS.put(0x0205L,"GET_WATCHDOG_BITMAP");
        COMMANDS.put(0x0206L,"DEL_MAC_ADDR");
        COMMANDS.put(0x1100L,"BSS_START");
        COMMANDS.put(0x1101L,"AP_BEACON");
        COMMANDS.put(0x1111L,"SET_NEW_STN");
        COMMANDS.put(0x1114L,"SET_APMODE");
        COMMANDS.put(0x1121L,"SET_SWITCH_CHANNEL");
        COMMANDS.put(0x1122L,"UPDATE_ENCRYPTION");
        COMMANDS.put(0x1125L,"BASTREAM");
        COMMANDS.put(0x1128L,"SET_SPECTRUM_MGMT");
        COMMANDS.put(0x1129L,"SET_POWER_CONSTRAINT");
        COMMANDS.put(0x1130L,"SET_COUNTRY_CODE");
        COMMANDS.put(0x1133L,"SET_OPTIMIZATION_LEVEL");
        COMMANDS.put(0x1136L,"SET_WSC_IE");
        COMMANDS.put(0x1137L,"GET_RATETABLE");
        COMMANDS.put(0x1143L,"GET_SEQNO");
        COMMANDS.put(0x1144L,"DWDS_ENABLE");
        COMMANDS.put(0x1148L,"FW_FLUSH_TIMER");
        COMMANDS.put(0x1150L,"SET_CDD");
        COMMANDS.put(0x1155L,"SET_BFTYPE");
        COMMANDS.put(0x1157L,"CAU_REG_ACCESS");
        COMMANDS.put(0x1159L,"GET_TEMP");
        COMMANDS.put(0x1169L,"LED_CTRL");
        COMMANDS.put(0x116aL,"GET_FW_REGION_CODE");
        COMMANDS.put(0x116bL,"GET_DEVICE_PWR_TBL");
        COMMANDS.put(0x1172L,"SET_RATE_DROP");
        COMMANDS.put(0x1189L,"NEWDP_DMATHREAD_START");
        COMMANDS.put(0x118aL,"GET_FW_REGION_CODE_SC4");
        COMMANDS.put(0x118bL,"GET_DEVICE_PWR_TBL_SC4");
        COMMANDS.put(0x1201L,"QUIET_MODE");
        COMMANDS.put(0x1202L,"CORE_DUMP_DIAG_MODE");
        COMMANDS.put(0x1203L,"SLOT_TIME_OR_CORE_DUMP");
        COMMANDS.put(0x1204L,"EDMAC_CTRL");
        COMMANDS.put(0x1211L,"TXPWRLMT_CFG");
        COMMANDS.put(0x4001L,"MCAST_CTS");
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r");
    }

    @Override
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("output JSON path required");
        File out=new File(args[0]);
        out.getParentFile().mkdirs();
        Listing listing=currentProgram.getListing();
        FunctionManager fm=currentProgram.getFunctionManager();

        List<String> hits=new ArrayList<>();
        InstructionIterator it=listing.getInstructions(true);
        long instructionCount=0;
        while (it.hasNext()) {
            Instruction ins=it.next();
            instructionCount++;
            for (int op=0; op<ins.getNumOperands(); op++) {
                Object[] objs=ins.getOpObjects(op);
                for (Object obj: objs) {
                    if (obj instanceof Scalar) {
                        long v=((Scalar)obj).getUnsignedValue();
                        String name=COMMANDS.get(v);
                        if (name != null) {
                            Function fn=fm.getFunctionContaining(ins.getAddress());
                            String fne=fn==null ? "" : fn.getEntryPoint().toString();
                            String fnn=fn==null ? "" : fn.getName();
                            hits.add("{\"command\":\""+esc(name)+"\",\"value\":"+v+
                                ",\"instruction_address\":\""+ins.getAddress()+"\",\"mnemonic\":\""+
                                esc(ins.getMnemonicString())+"\",\"operands\":\""+esc(ins.toString())+
                                "\",\"function_entry\":\""+esc(fne)+"\",\"function_name\":\""+esc(fnn)+"\"}");
                        }
                    }
                }
            }
        }

        List<String> funcs=new ArrayList<>();
        FunctionIterator fit=fm.getFunctions(true);
        while (fit.hasNext() && funcs.size()<2000) {
            Function fn=fit.next();
            funcs.add("{\"entry\":\""+fn.getEntryPoint()+"\",\"name\":\""+esc(fn.getName())+
                "\",\"body_size\":"+fn.getBody().getNumAddresses()+"}");
        }

        try (PrintWriter pw=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),"UTF-8"))) {
            pw.println("{");
            pw.println("  \"schema\": \"wrt3200acm-ghidra-report/v1\",");
            pw.println("  \"language\": \""+esc(currentProgram.getLanguage().getLanguageID().toString())+"\",");
            pw.println("  \"compiler_spec\": \""+esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString())+"\",");
            pw.println("  \"image_base\": \""+currentProgram.getImageBase()+"\",");
            pw.println("  \"instruction_count\": "+instructionCount+",");
            pw.println("  \"function_count\": "+fm.getFunctionCount()+",");
            pw.println("  \"memory_blocks\": [");
            MemoryBlock[] blocks=currentProgram.getMemory().getBlocks();
            for (int i=0;i<blocks.length;i++) {
                MemoryBlock b=blocks[i];
                pw.print("    {\"name\":\""+esc(b.getName())+"\",\"start\":\""+b.getStart()+"\",\"end\":\""+b.getEnd()+"\",\"size\":"+b.getSize()+"}");
                pw.println(i+1<blocks.length?",":"");
            }
            pw.println("  ],");
            pw.println("  \"command_immediate_hits\": [");
            for (int i=0;i<hits.size();i++) pw.println("    "+hits.get(i)+(i+1<hits.size()?",":""));
            pw.println("  ],");
            pw.println("  \"functions_sample\": [");
            for (int i=0;i<funcs.size();i++) pw.println("    "+funcs.get(i)+(i+1<funcs.size()?",":""));
            pw.println("  ]");
            pw.println("}");
        }
        println("Wrote "+out+" with "+hits.size()+" command-immediate hits and "+fm.getFunctionCount()+" functions");
    }
}
