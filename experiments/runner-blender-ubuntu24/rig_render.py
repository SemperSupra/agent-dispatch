"""Public-safe Blender 4.5 LTS headless articulated CPU render oracle.

Original synthetic geometry only. Never import source character assets or secrets.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path

import bpy
from mathutils import Vector


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args(
        __import__("sys").argv[__import__("sys").argv.index("--") + 1:]
    )
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    bpy.ops.wm.read_factory_settings(use_empty=True)
    scene = bpy.context.scene
    scene.render.engine = "CYCLES"
    scene.cycles.device = "CPU"
    scene.cycles.samples = 8
    scene.render.resolution_x = 256
    scene.render.resolution_y = 144
    scene.render.resolution_percentage = 100
    scene.render.image_settings.file_format = "PNG"
    scene.render.film_transparent = False
    scene.frame_start = 1
    scene.frame_end = 17
    scene.render.fps = 12
    scene.world = bpy.data.worlds.new("synthetic-world")
    scene.world.color = (0.12, 0.12, 0.12)

    arm_data = bpy.data.armatures.new("two-bone-fixture-data")
    rig = bpy.data.objects.new("rig-original-synthetic", arm_data)
    scene.collection.objects.link(rig)
    bpy.ops.object.select_all(action="DESELECT")
    rig.select_set(True)
    bpy.context.view_layer.objects.active = rig
    bpy.ops.object.mode_set(mode="EDIT")
    base = arm_data.edit_bones.new("base")
    base.head = (0.0, 0.0, 0.1)
    base.tail = (0.0, 0.0, 0.9)
    hinge = arm_data.edit_bones.new("hinge")
    hinge.head = (0.0, 0.0, 0.9)
    hinge.tail = (0.0, 0.0, 1.75)
    hinge.parent = base
    bpy.ops.object.mode_set(mode="OBJECT")

    # Mesh vertices are baked into armature-local rest coordinates.
    bpy.ops.mesh.primitive_cube_add(size=1, location=(0, 0, 1.36))
    lever = bpy.context.object
    lever.name = "skinned-original-synthetic-lever"
    lever.scale = (0.32, 0.27, 0.92)
    bpy.ops.object.transform_apply(location=True, rotation=True, scale=True)
    weights = lever.vertex_groups.new(name="hinge")
    weights.add(list(range(len(lever.data.vertices))), 1.0, "REPLACE")
    modifier = lever.modifiers.new("actual-armature-deformation", "ARMATURE")
    modifier.object = rig

    material = bpy.data.materials.new("synthetic-orange")
    material.diffuse_color = (0.95, 0.38, 0.08, 1.0)
    material.use_nodes = True
    material.node_tree.nodes.get("Principled BSDF").inputs["Base Color"].default_value = (
        0.95, 0.38, 0.08, 1.0
    )
    lever.data.materials.append(material)

    pb = rig.pose.bones["hinge"]
    pb.rotation_mode = "XYZ"
    for frame, angle in [(1, -0.55), (9, 0.05), (17, 0.65)]:
        pb.rotation_euler = (angle, 0.0, 0.0)
        pb.keyframe_insert(data_path="rotation_euler", frame=frame, group="Hinge")
    assert len(rig.data.bones) == 2
    assert len(lever.vertex_groups) == 1
    assert modifier.type == "ARMATURE"

    bpy.ops.mesh.primitive_cube_add(size=1, location=(0, 0, 0.1))
    pedestal = bpy.context.object
    pedestal.name = "fixed-pedestal"
    pedestal.scale = (0.65, 0.55, 0.2)
    bpy.ops.mesh.primitive_plane_add(size=200, location=(0, 0, -0.03))

    bpy.ops.object.camera_add(location=(2.6, -4.1, 2.55))
    camera = bpy.context.object
    target = Vector((0, 0, 1.02))
    camera.rotation_euler = (target - camera.location).to_track_quat("-Z", "Y").to_euler()
    scene.camera = camera
    bpy.ops.object.light_add(type="AREA", location=(-2, -3, 4.0))
    light = bpy.context.object
    light.data.energy = 750
    light.data.size = 3.0

    scene.frame_set(1)
    save = output / "synthetic_rig.blend"
    bpy.ops.wm.save_as_mainfile(filepath=str(save))

    hashes = []
    evaluated_vertices = []
    all_evaluated_positions = []
    for frame in (1, 9, 17):
        scene.frame_set(frame)
        depsgraph = bpy.context.evaluated_depsgraph_get()
        obj = lever.evaluated_get(depsgraph)
        sampled = obj.to_mesh()
        try:
            coords = [
                [round(float(v), 5) for v in (obj.matrix_world @ vertex.co)]
                for vertex in sampled.vertices
            ]
            all_evaluated_positions.append(coords)
            evaluated_vertices.append(coords[0])
        finally:
            obj.to_mesh_clear()
        dest = output / ("frame_%04d.png" % frame)
        scene.render.filepath = str(dest)
        bpy.ops.render.render(write_still=True)
        blob = dest.read_bytes()
        assert len(blob) > 1000, "empty render"
        hashes.append(hashlib.sha256(blob).hexdigest())

    # Check every skinned vertex; vertex 0 happens to sit near the hinge pivot.
    delta = max(
        math.dist(a, b)
        for sample in all_evaluated_positions[1:]
        for a, b in zip(all_evaluated_positions[0], sample)
    )
    print("BLENDER_DEFORMATION_MAX_METERS=" + str(delta))
    assert delta > 0.20, "armature has not deformed the evaluated mesh"
    assert len(set(hashes)) == 3, "three keyframes generated identical images"

    receipt = {
        "schema": "github-runner-blender-smoke/v1",
        "source_revision": os.environ.get("GITHUB_SHA", ""),
        "runner_label": os.environ.get("RUNNER_LABEL", ""),
        "runner_image": os.environ.get("ImageOS", ""),
        "blender_version": bpy.app.version_string,
        "engine": scene.render.engine,
        "compute_device": scene.cycles.device,
        "native_bones": len(rig.data.bones),
        "armature_modifier_verified": True,
        "frames": [1, 9, 17],
        "pixel_sha256": hashes,
        "evaluated_mesh_vertex_0": evaluated_vertices,
        "max_evaluated_vertex_displacement_m": round(delta, 5),
        "rig_blend_sha256": hashlib.sha256(save.read_bytes()).hexdigest(),
        "claim": "synthetic CPU rig/deformation/render exercised; not GPU or R009 asset acceptance",
        "result": "PASS",
    }
    (output / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("BLENDER_SMOKE_RECEIPT=" + json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
