from glob import glob
from os import environ, makedirs
from os.path import join
from subprocess import run

wast2json = environ.get("WAST2JSON", "wast2json")

makedirs("specdata", exist_ok=True)

for filename in glob("spec/test/core/*.wast"):
    run([wast2json, "--debug-names", join("..", filename)], cwd="specdata", check=True)
