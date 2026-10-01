#!/usr/bin/env python3
import argparse, collections, gzip, hashlib, json, os, pathlib, re, stat, subprocess

SAFE_PACKAGE_KEYS = (
    'name','version','license','type','main','module','bin','engines','repository','homepage',
    'dependencies','optionalDependencies','peerDependencies','peerDependenciesMeta'
)
SAFE_PLUGIN_KEYS = (
    'id','name','version','type','entrypoint','entrypoints','skills','mcp','hooks','capabilities',
    'platforms','targets','requires','dependencies','package'
)
COMPONENT_MARKERS = {
    'codex': ('/resources/codex','/resources/codex-cli','/resources/codex-code-mode-host'),
    'cua': ('/resources/cua_node','/@oai/cua/','/@oai/sky/','/unified-computer-use/'),
    'plugins': ('/resources/plugins/','/.codex-plugin/'),
    'playwright': ('/playwright-core/','/playwright/'),
    'native': ('/resources/native/','.node'),
    'asar': ('app.asar',),
    'browser': ('/browser/','/chrome/','chromium','chrome_'),
}

def sha256(path, chunk=1024*1024):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while True:
            b=f.read(chunk)
            if not b: break
            h.update(b)
    return h.hexdigest()

def run(args, timeout=8):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
        text=(p.stdout+'\n'+p.stderr).strip()
        return {'exit_code':p.returncode,'output':text[:8000]}
    except Exception as e:
        return {'error':f'{type(e).__name__}: {e}'}

def read_json(path):
    try:
        return json.loads(path.read_text(errors='replace'))
    except Exception:
        return None

def safe_subset(obj, keys):
    if not isinstance(obj,dict): return None
    out={'keys':sorted(str(k) for k in obj.keys())}
    for k in keys:
        if k not in obj: continue
        v=obj[k]
        if isinstance(v,(str,int,float,bool)) or v is None:
            if not isinstance(v,str) or len(v)<=500: out[k]=v
        elif isinstance(v,list):
            vals=[]
            for x in v[:200]:
                if isinstance(x,(str,int,float,bool)) or x is None: vals.append(x)
                elif isinstance(x,dict): vals.append({'keys':sorted(str(q) for q in x.keys())})
            out[k]=vals
        elif isinstance(v,dict):
            out[k]={'keys':sorted(str(q) for q in v.keys()),
                    'scalar_values':{str(q):x for q,x in v.items()
                                     if isinstance(x,(str,int,float,bool)) and len(str(x))<=300}}
    return out

def normalize_mcp(obj):
    if not isinstance(obj,dict): return {'type':type(obj).__name__}
    result={'keys':sorted(obj.keys())}
    servers=obj.get('mcpServers') or obj.get('servers') or obj
    if isinstance(servers,dict):
        norm={}
        for name,cfg in servers.items():
            if not isinstance(cfg,dict):
                norm[str(name)]={'type':type(cfg).__name__}; continue
            cmd=cfg.get('command')
            norm[str(name)]={
                'keys':sorted(cfg.keys()),
                'command_basename': pathlib.PurePath(cmd).name if isinstance(cmd,str) else None,
                'arg_count': len(cfg.get('args',[])) if isinstance(cfg.get('args'),list) else None,
                'env_keys': sorted(cfg.get('env',{}).keys()) if isinstance(cfg.get('env'),dict) else [],
                'url_host': None,
            }
            url=cfg.get('url')
            if isinstance(url,str):
                m=re.match(r'^[a-zA-Z][\\w+.-]*://([^/:?#]+)',url)
                norm[str(name)]['url_host']=m.group(1) if m else None
        result['servers']=norm
    return result

def component_for(rel):
    q='/'+rel.lower()
    hits=[]
    for name,markers in COMPONENT_MARKERS.items():
        if any(m.lower() in q for m in markers): hits.append(name)
    return hits or ['other']

def component_digest(records):
    h=hashlib.sha256(); total=0
    for r in sorted(records,key=lambda x:x['path']):
        line=f"{r['path']}\\0{r['size']}\\0{r['sha256']}\\n".encode()
        h.update(line); total+=r['size']
    return {'file_count':len(records),'bytes':total,'manifest_sha256':h.hexdigest()}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('output_dir')
    ap.add_argument('--label',default='desktop-bundle')
    ap.add_argument('--platform',default='unknown')
    args=ap.parse_args()
    root=pathlib.Path(args.root).resolve(); out=pathlib.Path(args.output_dir)
    out.mkdir(parents=True,exist_ok=True)

    packages=[]; plugins=[]; mcps=[]; playwright=[]; natives=[]; executables=[]; licenses=[]; asars=[]
    skills=[]; hooks=[]; app_maps=[]; marketplaces=[]; extension_manifests=[]; component_executables=[]
    components=collections.defaultdict(list)
    inventory_path=out/'files.ndjson.gz'

    with gzip.open(inventory_path,'wt',encoding='utf-8') as inv:
        for p in sorted(root.rglob('*')):
            if not p.is_file() or p.is_symlink(): continue
            rel=p.relative_to(root).as_posix()
            try: size=p.stat().st_size; digest=sha256(p)
            except Exception as e:
                inv.write(json.dumps({'path':rel,'error':f'{type(e).__name__}: {e}'},sort_keys=True)+'\\n'); continue
            rec={'path':rel,'size':size,'sha256':digest,'suffix':p.suffix.lower()}
            cats=component_for(rel); rec['components']=cats
            inv.write(json.dumps(rec,sort_keys=True)+'\\n')
            for cat in cats: components[cat].append(rec)

            low=p.name.lower()
            if low=='package.json':
                obj=read_json(p); packages.append({'path':rel,'sha256':digest,'metadata':safe_subset(obj,SAFE_PACKAGE_KEYS)})
            if low=='plugin.json' and ('.codex-plugin' in rel or '/plugins/' in '/'+rel.lower()):
                obj=read_json(p); plugins.append({'path':rel,'sha256':digest,'metadata':safe_subset(obj,SAFE_PLUGIN_KEYS)})
            if low in {'.mcp.json','mcp.json'} or low.endswith('.mcp.json'):
                obj=read_json(p); mcps.append({'path':rel,'sha256':digest,'metadata':normalize_mcp(obj)})
            if low=='skill.md':
                text=p.read_text(errors='replace')
                frontmatter={}
                if text.startswith('---'):
                    parts=text.split('---',2)
                    if len(parts)>=3:
                        for line in parts[1].splitlines():
                            if ':' in line:
                                k,v=line.split(':',1)
                                if k.strip() in {'name','description','version'}:
                                    frontmatter[k.strip()]=v.strip()[:500]
                skills.append({'path':rel,'size':size,'sha256':digest,'frontmatter':frontmatter})
            if low=='hooks.json' or ('/hooks/' in '/'+rel.lower() and low.endswith('.json')):
                obj=read_json(p)
                event_names=[]
                handler_types=[]
                if isinstance(obj,dict):
                    h=obj.get('hooks',obj)
                    if isinstance(h,dict):
                        event_names=sorted(str(k) for k in h.keys())
                        def walk(v):
                            if isinstance(v,dict):
                                if isinstance(v.get('type'),str): handler_types.append(v['type'])
                                for x in v.values(): walk(x)
                            elif isinstance(v,list):
                                for x in v: walk(x)
                        walk(h)
                hooks.append({'path':rel,'sha256':digest,'keys':sorted(obj.keys()) if isinstance(obj,dict) else [],
                              'events':event_names,'handler_types':sorted(set(handler_types))})
            if low in {'.app.json','app.json'} and ('plugin' in rel.lower() or '/resources/' in '/'+rel.lower()):
                obj=read_json(p)
                app_maps.append({'path':rel,'sha256':digest,'metadata':safe_subset(obj,('apps','id','name','version'))})
            if low=='marketplace.json':
                obj=read_json(p)
                marketplaces.append({'path':rel,'sha256':digest,'metadata':safe_subset(obj,('name','version','plugins'))})
            if low=='manifest.json' and any(x in rel.lower() for x in ('extension','chrome','browser')):
                obj=read_json(p)
                extension_manifests.append({'path':rel,'sha256':digest,
                    'metadata':safe_subset(obj,('name','version','manifest_version','permissions','host_permissions','background','content_scripts','externally_connectable'))})
            if low=='browsers.json' and 'playwright' in rel.lower():
                obj=read_json(p); rows=[]
                if isinstance(obj,dict) and isinstance(obj.get('browsers'),list):
                    for b in obj['browsers']:
                        if isinstance(b,dict):
                            rows.append({k:b.get(k) for k in ('name','revision','installByDefault','browserVersion') if k in b})
                playwright.append({'path':rel,'sha256':digest,'browsers':rows})
            if p.suffix.lower()=='.node':
                info=run(['file','-b',str(p)])
                deps=run(['otool','-L',str(p)]) if args.platform=='macos' else run(['ldd',str(p)])
                natives.append({'path':rel,'size':size,'sha256':digest,'file':info,'dependencies':deps})
            if os.access(p,os.X_OK) and any(marker in ('/'+rel.lower()) for marker in (
                '/resources/cua_node/','/resources/native/','/resources/plugins/','/resources/codex','/app.asar.unpacked/')):
                component_executables.append({
                    'path':rel,'size':size,'sha256':digest,
                    'file':run(['file','-b',str(p)]),
                    'dependencies': run(['otool','-L',str(p)]) if args.platform=='macos' else run(['ldd',str(p)])
                })
            if low.startswith('license') or low in {'copying','notice','third_party_licenses','third-party-licenses.txt'}:
                licenses.append({'path':rel,'size':size,'sha256':digest})
            if low.endswith('.asar'):
                asars.append({'path':rel,'size':size,'sha256':digest})

            if low in {'codex','codex-cli','codex-code-mode-host','codex.exe','codex-cli.exe','codex-code-mode-host.exe'}:
                mode=p.stat().st_mode
                version=run([str(p),'--version']) if (os.access(p,os.X_OK) or args.platform=='windows') else {'not_executable':True}
                executables.append({'path':rel,'size':size,'sha256':digest,'mode':oct(stat.S_IMODE(mode)),'version_probe':version})

    summary={
        'schema':'cdr-desktop-runtime-component-census/v1',
        'label':args.label,'platform':args.platform,'root_name':root.name,
        'component_digests':{k:component_digest(v) for k,v in sorted(components.items())},
        'package_manifest_count':len(packages),'plugin_manifest_count':len(plugins),
        'mcp_manifest_count':len(mcps),'native_module_count':len(natives),
        'skill_count':len(skills),'hook_manifest_count':len(hooks),'app_map_count':len(app_maps),
        'marketplace_manifest_count':len(marketplaces),'extension_manifest_count':len(extension_manifests),
        'component_executable_count':len(component_executables),
        'license_file_count':len(licenses),'asar_count':len(asars),
        'claim_boundary':'Full path/hash/component census plus normalized metadata. Proprietary source bodies and opaque manifest payloads are not published.'
    }
    docs={
        'summary.json':summary,'packages.json':packages,'plugins.json':plugins,'mcp.json':mcps,
        'playwright.json':playwright,'native-modules.json':natives,'executables.json':executables,
        'licenses.json':licenses,'asar-containers.json':asars,
        'skills.json':skills,'hooks.json':hooks,'app-maps.json':app_maps,
        'marketplaces.json':marketplaces,'browser-extension-manifests.json':extension_manifests,
        'component-executables.json':component_executables,
    }
    for name,obj in docs.items():
        (out/name).write_text(json.dumps(obj,indent=2,sort_keys=True)+'\\n')

if __name__=='__main__': main()
