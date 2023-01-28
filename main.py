"""
Deobfuscation utility for python files obfuscated with Specter (https://github.com/billythegoat356/Specter).
Written by Angelo DeLuca (https://github.com/AngeloD2022)
"""

import ast
from _ast import AST, Assign, Name, Tuple, Call, Constant, Module
from pathlib import Path
from typing import Any, Dict
import io
import tempfile
import subprocess


"""
Disclaimer: 
This procedure is almost certainly overcomplicated in some aspects. 
In hindsight, I probably did not need to rely on Decompyle++ for interpreting the marshalled bytecode. 
Deobfuscation Process
STAGE A - Creating Initial Bytecode
    1. parse original source
    2. concatenate all of the bytes objects in the `Func.define()` parameters (should be the 2nd parameter).
        Concatenate them in order of occurrence in the file. This results in marshalled python bytecode.
STAGE B - Decompilation
    1. Save marshalled bytecode to a temporary file location
    2. invoke pycdc from the decompilepp directory by opening a subprocess 
        Make sure to use the flags: -c -v 3.9
    3. store the source result from stdout into a string variable
STAGE C - Deobfuscating the Decompiler Output
    1. There are three important parts of the source that presumably vary with each run of the obfuscator:
            * the giant tuple definition at the beginning of the file
            * the integer key in the decode lambda
            * the order of concatenation as given by the large array definition at the bottom of the file.
        To extract this, do the following:
            obf_split = obfuscated_source.split('\n\n')
            del obf_split[0] # this is just a comment added by the decompiler.
            
            scrambled_source_tup = obf_split[0].split("\n")[-1]
            
            source_order_list = obf_split[-1].split(")(")[-1]
            source_order = [line.strip().replace(',','') for line in source_order_list.splitlines()[1:-1]]
    2. parse the tuple assignment into a dictionary mapping of <variable_name> -> literal value using the `ast` package
    3. extract the integer key placed in the decoding lambda.
    4. decode and concatenate the source in the order provided by iterating through `source_order`.
    5. done!
    
"""


PYCDC_LOCATION = Path('./decompylepp/pycdc')


class DeobASTWalk(ast.NodeVisitor):

    def __init__(self):
        self.node_stack = []
        self.marshalled_code_table: Dict[str, bytes] = dict()

    def visit(self, node: AST) -> Any:
        self.node_stack.append(node)
        super().visit(node)
        self.node_stack.pop()

    def visit_Assign(self, node: Assign) -> Any:

        # Store the values of all __####__ fields...
        if len(node.targets) != 1 or type(node.targets[0]) != Name:
            return

        field_name: str = node.targets[0].id

        if not field_name.startswith('__') or not field_name.endswith('__'):
            return

        if type(node.value) != Tuple:
            return

        # get the marshalled code.
        tup_val: Tuple = node.value

        if len(tup_val.elts) != 2 or type(tup_val.elts[1]) != Call:
            return

        fcall: Call = tup_val.elts[1]

        if len(fcall.args) != 2 or type(fcall.args[-1]) != Constant or type(fcall.args[1].value) != bytes:
            return

        # store the mapping...
        marshalled_code = fcall.args[1].value
        self.marshalled_code_table.update({field_name: marshalled_code})


class SpecterDeobfuscator:

    SIGNATURE = """
    ################# WARNING ##################
    #   THIS FILE WAS PREVIOUSLY OBFUSCATED!   #
    # DO NOT RUN IT UNLESS YOU TRUST THE CODE. #
    ############################################
    \n"""[1:].replace('    ', '')


    def __init__(self, code: str):
        self.code = code
        self.parsed_code = ast.parse(code)

        self._marshalled_bytecode = bytes()
        self._decompiled_source = str()
        self._scramble_order = list()
        self._deobfuscation_result = str()

    def __stage_a(self):
        # retrieve all symbol definitions and place them in the table
        stage_a_analysis = DeobASTWalk()
        stage_a_analysis.visit(self.parsed_code)

        symcount = len(stage_a_analysis.marshalled_code_table)

        if symcount == 0:
            return False

        print(f"[INFO] Derived bytecode from {symcount} symbols.")
        self._marshalled_bytecode = b''.join(stage_a_analysis.marshalled_code_table.values())

        return True

    def __stage_b(self):
        print('[INFO] Checking for pycdc...')

        if not PYCDC_LOCATION.exists():
            print("[ERROR] Couldn't find pycdc.")
            return False

        print('[INFO] Storing marshalled bytecode to a temporary location.')
        with tempfile.TemporaryDirectory() as tmpdir:
            marshalled_path = Path(tmpdir) / 'marshalled.pym'

            with open(marshalled_path, 'wb') as f:
                f.write(self._marshalled_bytecode)

            print('[INFO] Started decompilation...')

            decompiler_arguments = "-c -v 3.9".split()
            pycdc_proc = subprocess.Popen(
                [PYCDC_LOCATION, marshalled_path] + decompiler_arguments,
                stdout=subprocess.PIPE
            )

            output = [l for l in io.TextIOWrapper(pycdc_proc.stdout, encoding='utf-8')]

            if len(output) <= 5:
                print('[ERROR] Decompilation Failed.')
                return False

            self._decompiled_source = ''.join(output)

        return True

    def __stage_c(self):

        if len(self._decompiled_source) == 0:
            return False

        obf_split = self._decompiled_source.split('\n\n')
        del obf_split[0]

        # data source...
        scrambled_source_tup = obf_split[0].split("\n")[-1]

        # data order...
        source_order_list = obf_split[-1].split(")(")[-1]
        order = [line.strip().replace(',', '') for line in source_order_list.splitlines()[1:]]
        order[-1] = order[-1][:-2]

        # get the integer key...
        decode_fxn = obf_split[1].splitlines()[1]
        KEY_SUBSTR_START, KEY_SUBSTR_END = "int(b'", "')))"
        start, end = decode_fxn.index(KEY_SUBSTR_START) + len(KEY_SUBSTR_START), decode_fxn.index(KEY_SUBSTR_END)
        decoding_key = int(decode_fxn[start:end])

        # convert the scrambled tuple into a state table...
        module: Module = ast.parse(scrambled_source_tup)
        if type(module.body[0]) != Assign:
            return False

        assignment: Assign = module.body[0]
        if type(assignment.targets[0]) != Tuple or type(assignment.value) != Tuple:
            return False

        target_tuple: Tuple = assignment.targets[0]
        value_tuple: Tuple = assignment.value

        state_table = dict()
        for index, name in enumerate(target_tuple.elts):
            v_name = name.id

            if type(value_tuple.elts[index]) != Constant:
                continue

            v: Constant = value_tuple.elts[index]
            state_table.update({v_name: v.value})

        # decode and concatenate the entries...
        def _decode_entry(b: bytes):
            return "".join(list(map(lambda n: chr(int(n) - decoding_key), b.decode().split('\x00'))))

        result = "".join([_decode_entry(state_table[name]) for name in order])

        self._deobfuscation_result = result

        return True

    def deobfuscate(self) -> str:
        analyze_result = self.__analyze()

        if not analyze_result:
            raise Exception

        deob_result = self.__stage_c()

        if not deob_result:
            print('[ERROR] Stage C failed!')
            raise Exception

        print('[INFO] Stage C successful!')
        return self.SIGNATURE + self._deobfuscation_result

    def __analyze(self):

        # Perform Stage A and Stage B
        success = self.__stage_a()
        if not success:
            print("[ERROR] Stage A failed!")
            return False

        print("[INFO] Stage A successful!")

        success = self.__stage_b()
        if not success:
            print("[ERROR] Stage B failed!")
            return False

        print("[INFO] Stage B successful!")

        return True


if __name__ == '__main__':
    path = 'obfuscated.py'

    with open(path, 'r') as f:
        contents = f.read()

    deobfuscator = SpecterDeobfuscator(contents)
    source_code = deobfuscator.deobfuscate()

    print('[INFO] Deobfuscation finished.')

    with open('deobfuscated.py', 'w') as f:
        f.write(source_code)
