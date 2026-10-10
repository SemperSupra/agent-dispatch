// High-specificity structural candidate reporter for 88W8964 command recovery.
// Emits derived addresses/call-graph/context only; no firmware payload.
// @category WRT3200ACM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.util.*;

public class WrtCandidateReport extends GhidraScript {
    private static final Map<Long,String> COMMANDS = new LinkedHashMap<>();
    static {
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

    private static final Set<String> DISPATCH_MNEMONICS =
        new HashSet<>(Arrays.asList("cmp","cmn","mov","movw","movt","sub","subw"));

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r");
    }

    private String context(Listing listing, Instruction center, int radius) {
        List<Instruction> before=new ArrayList<>();
        Instruction p=center;
        for (int i=0;i<radius;i++) {
            p=listing.getInstructionBefore(p.getAddress());
            if (p==null) break;
            before.add(p);
        }
        Collections.reverse(before);
        List<Instruction> all=new ArrayList<>(before);
        all.add(center);
        p=center;
        for (int i=0;i<radius;i++) {
            p=listing.getInstructionAfter(p.getAddress());
            if (p==null) break;
            all.add(p);
        }
        StringBuilder sb=new StringBuilder();
        for (Instruction ins: all) {
            if (sb.length()>0) sb.append(" | ");
            sb.append(ins.getAddress()).append(": ").append(ins.toString());
        }
        return sb.toString();
    }

    private List<String> functionEntries(Set<Function> fs) {
        List<String> out=new ArrayList<>();
        for (Function f:fs) out.add(f.getEntryPoint().toString());
        Collections.sort(out);
        return out;
    }

    @Override
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if (args.length!=1) throw new IllegalArgumentException("output JSON path required");
        File out=new File(args[0]); out.getParentFile().mkdirs();

        Listing listing=currentProgram.getListing();
        FunctionManager fm=currentProgram.getFunctionManager();
        Map<String,List<String>> hitsByFn=new TreeMap<>();
        Map<String,String> fnNames=new TreeMap<>();
        Map<String,Long> fnSizes=new TreeMap<>();

        InstructionIterator it=listing.getInstructions(true);
        while (it.hasNext()) {
            Instruction ins=it.next();
            String m=ins.getMnemonicString().toLowerCase(Locale.ROOT);
            if (!DISPATCH_MNEMONICS.contains(m)) continue;
            for (int op=0;op<ins.getNumOperands();op++) {
                Object[] objs=ins.getOpObjects(op);
                for (Object obj:objs) {
                    if (!(obj instanceof Scalar)) continue;
                    long v=((Scalar)obj).getUnsignedValue();
                    String name=COMMANDS.get(v);
                    if (name==null) continue;
                    Function fn=fm.getFunctionContaining(ins.getAddress());
                    if (fn==null) continue;
                    String entry=fn.getEntryPoint().toString();
                    fnNames.put(entry,fn.getName());
                    fnSizes.put(entry,fn.getBody().getNumAddresses());
                    String hit="{\"command\":\""+esc(name)+"\",\"value\":"+v+
                        ",\"instruction\":\""+ins.getAddress()+"\",\"mnemonic\":\""+esc(m)+
                        "\",\"text\":\""+esc(ins.toString())+"\",\"context\":\""+
                        esc(context(listing,ins,6))+"\"}";
                    hitsByFn.computeIfAbsent(entry,k->new ArrayList<>()).add(hit);
                }
            }
        }

        try (PrintWriter pw=new PrintWriter(new OutputStreamWriter(new FileOutputStream(out),"UTF-8"))) {
            pw.println("{");
            pw.println("  \"schema\":\"wrt3200acm-command-candidates/v1\",");
            pw.println("  \"filter\":\"known command scalars >=0x0100 in cmp/cmn/mov/movw/movt/sub/subw instructions\",");
            pw.println("  \"functions\":[");
            int fi=0;
            for (String entry:hitsByFn.keySet()) {
                Function fn=fm.getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(entry));
                Set<Function> callers=fn==null?Collections.emptySet():fn.getCallingFunctions(monitor);
                Set<Function> callees=fn==null?Collections.emptySet():fn.getCalledFunctions(monitor);
                Set<String> uniqueCommands=new TreeSet<>();
                for (String h:hitsByFn.get(entry)) {
                    for (Map.Entry<Long,String> e:COMMANDS.entrySet())
                        if (h.contains("\"command\":\""+e.getValue()+"\"")) uniqueCommands.add(e.getValue());
                }
                pw.println("    {");
                pw.println("      \"entry\":\""+esc(entry)+"\",");
                pw.println("      \"name\":\""+esc(fnNames.get(entry))+"\",");
                pw.println("      \"body_size\":"+fnSizes.get(entry)+",");
                pw.println("      \"unique_command_count\":"+uniqueCommands.size()+",");
                pw.println("      \"commands\":[\""+String.join("\",\"",uniqueCommands)+"\"],");
                pw.println("      \"callers\":[\""+String.join("\",\"",functionEntries(callers))+"\"],");
                pw.println("      \"callees\":[\""+String.join("\",\"",functionEntries(callees))+"\"],");
                pw.println("      \"hits\":[");
                List<String> hs=hitsByFn.get(entry);
                for (int i=0;i<hs.size();i++) pw.println("        "+hs.get(i)+(i+1<hs.size()?",":""));
                pw.println("      ]");
                pw.print("    }");
                fi++;
                pw.println(fi<hitsByFn.size()?",":"");
            }
            pw.println("  ]");
            pw.println("}");
        }
        println("Wrote high-specificity candidates for "+hitsByFn.size()+" functions");
    }
}
