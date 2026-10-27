"""Bounded independent Blender Cycles Metal probe: no real character assets."""
import bpy, hashlib, json, pathlib, sys, traceback
args=sys.argv[sys.argv.index("--")+1:]
blend=pathlib.Path(args[0]); out=pathlib.Path(args[1]); out.mkdir(parents=True,exist_ok=True)
r={"schema":"github-runner-blender-metal/v1","result":"UNKNOWN","blender_version":bpy.app.version_string,"devices":[],"gpu_pixel_sha256":None}
try:
    p=bpy.context.preferences.addons["cycles"].preferences
    p.compute_device_type="METAL"
    p.get_devices()
    r["devices"]=[{"type":str(d.type),"name":str(d.name)} for d in p.devices]
    selected=[d for d in p.devices if d.type not in {"CPU","NONE"}]
    for d in p.devices: d.use=(d in selected)
    if not selected:
        r["result"]="NEGATIVE_OBSERVATION_NO_BLENDER_METAL_DEVICE"
    else:
        bpy.ops.wm.open_mainfile(filepath=str(blend))
        s=bpy.context.scene;s.render.engine="CYCLES";s.cycles.device="GPU";s.cycles.samples=4
        s.render.resolution_x=256;s.render.resolution_y=144;s.render.resolution_percentage=100
        s.frame_set(9)
        image=out/"metal_frame_0009.png";s.render.filepath=str(image)
        bpy.ops.render.render(write_still=True)
        if image.stat().st_size<1000: raise RuntimeError("GPU render PNG missing/empty")
        r["gpu_pixel_sha256"]=hashlib.sha256(image.read_bytes()).hexdigest()
        r["result"]="METAL_RENDER_COMPLETED_HARDWARE_ATTESTATION_PENDING"
        r["selected_devices"]=[str(d.name) for d in selected]
except Exception as e:
    r["result"]="METAL_RUNTIME_FAILURE";r["error_type"]=type(e).__name__;r["error"]=str(e)[:400]
    traceback.print_exc()
finally:
    (out/"metal_probe.json").write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
    print("BLENDER_MACOS_METAL_PROBE="+json.dumps(r,sort_keys=True))
