/** Independent external authored REA known-answer experiment.
 * Copied into the pinned upstream checkout at execution; not upstream test code.
 * Source fixture is inert and must never be executed by its static analyzer.
 */
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { analyzeJavaScriptApplication } from "../../../src/application/javascript/JavaScriptApplicationService.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";

const roots: string[] = [];
const original = {
  "package.json": '{"name":"requal-inert-electron","version":"1.0.0","main":"main.js"}\n',
  "main.js": [
    'const {BrowserWindow, ipcMain} = require("electron");',
    'new BrowserWindow({webPreferences:{preload:require("node:path").join(__dirname,"preload.js"),contextIsolation:true,sandbox:true}});',
    'ipcMain.handle("profile:read", (_event,id)=>({id}));',
    ""
  ].join("\n"),
  "preload.js": [
    'const {contextBridge,ipcRenderer}=require("electron");',
    'contextBridge.exposeInMainWorld("profileApi",{read:(id)=>ipcRenderer.invoke("profile:read",id)});',
    ""
  ].join("\n"),
  "renderer.js": 'globalThis.__rea_external_fixture_executed = true; window.profileApi.read("fixture");\n',
};
const fixture = async () => {
  const directory = await mkdtemp(join(tmpdir(), "requal-rea-"));
  roots.push(directory);
  await Promise.all(Object.entries(original).map(([file, content]) =>
    writeFile(join(directory, file), content)));
  return directory;
};
afterEach(async () => {
  await Promise.all(roots.splice(0).map(r => rm(r, {recursive:true,force:true})));
});

const parse = async (path: string) => {
  const run = await analyzeJavaScriptApplication({input_path: path});
  if (!run.ok) throw run.error;
  return { evidence: run.value,
           graph: javascriptApplicationAnalysisResultSchema.parse(run.value.normalized_result).graph };
};

describe("external authored REA static analysis", () => {
  it("recovers known contextBridge, IPC and preload boundaries without executing fixture", async () => {
    const root = await fixture();
    Reflect.deleteProperty(globalThis, "__rea_external_fixture_executed");
    const sourceBefore = await readFile(join(root, "renderer.js"), "utf8");
    const run = await parse(root);
    const kinds = new Set(run.graph.nodes.map(node => node.kind));
    expect(kinds.has("context-bridge-api")).toBe(true);
    expect(kinds.has("ipc-channel")).toBe(true);
    expect(kinds.has("electron-preload")).toBe(true);
    const channels = run.graph.nodes.filter(node => node.kind === "ipc-channel")
      .flatMap(node => node.observations.map(o => o.properties.channel));
    expect(channels).toContain("profile:read");
    expect(run.evidence.operation).toBe("analyze_javascript_application");
    expect(run.evidence.confidence).toBe("derived");
    expect(run.evidence.authority).toBe("shipped-artifact");
    expect(Reflect.has(globalThis, "__rea_external_fixture_executed")).toBe(false);
    expect(await readFile(join(root, "renderer.js"), "utf8")).toBe(sourceBefore);
  });

  it("provides stable evidence for unchanged inputs", async () => {
    const root = await fixture();
    const a = await parse(root);
    const b = await parse(root);
    expect(a.graph).toEqual(b.graph);
    expect(a.evidence.evidence_id).toEqual(b.evidence.evidence_id);
    expect(a.evidence.evidence_id).toMatch(/^ev_[a-f0-9]{64}$/);
  });

  it("changes recovered graph after mutation and does not reuse stale evidence", async () => {
    const root = await fixture();
    const before = await parse(root);
    await writeFile(join(root, "preload.js"),
      original["preload.js"].replace("profile:read", "profile:write"));
    const after = await parse(root);
    expect(after.evidence.evidence_id).not.toEqual(before.evidence.evidence_id);
    expect(after.graph).not.toEqual(before.graph);
    const channels = after.graph.nodes.filter(node => node.kind === "ipc-channel")
      .flatMap(node => node.observations.map(o => o.properties.channel));
    expect(channels).toContain("profile:write");
  });
});
