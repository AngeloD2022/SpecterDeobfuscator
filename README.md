# SpecterDeobfuscator

Deobfuscation utility for python files protected with Specter.


# How to Use

This project relies on a built binary of pycdc [Decompyle++](https://github.com/zrax/pycdc).
Place the decompiler inside of a directory named `decompylepp` on the same level as the script. It will invoke it as a subprocess and read stdout to get the result.

Other than the decompiler, it does not have any dependencies. Place your obfuscated script (`obfuscated.py`) in the same directory as the script and run main.py.
