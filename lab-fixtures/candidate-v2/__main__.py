import argparse

p = argparse.ArgumentParser()
p.add_argument("--version", action="store_true")
args = p.parse_args()
if args.version:
    print("candidate-probe 2.0")
else:
    print("candidate-probe:v2:ok")
