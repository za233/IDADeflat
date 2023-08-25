import angr
import idaapi
import pyvex
import claripy
import capstone
import keystone 
from .core_base import DeflatCore



class RelocBlock:
    def __init__(self, cs : capstone.Cs, ks : keystone.Ks, addr : int, asm_data : bytes):
        self.cs = cs
        self.ks = ks
        self.addr = addr
        self.asm_data = asm_data
        self.disasm()

    def disasm(self):
        self.insns = [insn for insn in self.cs.disasm(self.asm_data, self.addr)]

    def size(self):
        return len(self.asm_data)

    def reloc_to(self, new_addr):
        self.disasm()
        new_code = b''
        ptr = new_addr
        offset = 0
        for insn in self.insns:
            try:
                encoding, _ = self.ks.asm(insn.mnemonic + " " + insn.op_str, ptr)
            except:
                print('[AngrCore] invalid instruction(%s) detected, unable to relocation...' % (insn.mnemonic + " " + insn.op_str))
                encoding = self.asm_data[offset:offset+insn.size]

            offset += len(encoding)
            ptr += len(encoding)
            new_code += bytes(encoding)
        self.addr = new_addr
        self.asm_data = new_code

ARCH_X86 = {"X86", "AMD64"}
ARCH_ARM = {"ARMEL", "ARMHF"}
ARCH_ARM64 = {'AARCH64'}

def is_jump(arch, name):
    if arch in ARCH_X86:
        return name in [
        "jmp", "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz",
        "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe",
        "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl",
        "jle", "jng", "jg", "jnle", "jp", "jpe", "jnp",
        "jpo", "jcxz", "jecxz"
    ]
    elif arch in ARCH_ARM or arch in ARCH_ARM64:
        return name in [
        "b", "br", "beq", "bne", "bcs", "bhs",
        "bcc", "blo", "bmi", "bpl", "bvs", "bvc", "bhi",
        "bls", "bge", "blt", "bgt", "ble", "cbz", "cbnz",
        "tbb", "tbh"
    ]
    assert False, 'unsupported arch...'

def is_call(arch, name):
    if arch in ARCH_X86:
        return name == "call"
    elif arch in ARCH_ARM or arch in ARCH_ARM64:
        return name in [
            "bl", "blr", "blx"
        ]
    assert False, 'unsupported arch...'

def build_jump(arch, target, cond):
    if arch in ARCH_X86:
        if cond:
            return 'j' + cond + ' ' + hex(target)
        else:
            return 'jmp' + ' ' + hex(target)
    elif arch in ARCH_ARM or arch in ARCH_ARM64:
        if cond:
            return 'b' + cond + ' ' + hex(target)
        else:
            return 'b' + ' ' + hex(target)

def extract_cond_flag(arch, insn):
    arm_cond = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le']
    x86_cond = ['e', 'ne', 'g', 'ge', 'l', 'le', 'b', 'be', 'a', 'ae', 'o', 'no', 's', 'ns', 'p', 'np', 'cxz', 'ecxz', 'rcxz']
    if arch in ARCH_X86:
        for c in x86_cond:
            if insn.mnemonic == 'cmov' + c:
                return c
    if arch in ARCH_ARM or arch in ARCH_ARM64:
        for c in arm_cond:
            if c in insn.mnemonic + ' ' + insn.op_str:
                return c
    return None

    
class AngrDeflatCore(DeflatCore):
    def __init__(self):
        DeflatCore.__init__(self, 'AngrDeflatCore')
        self.graph = {}
        

    def get_block_node(self, addr):
        func = idaapi.get_func(addr)
        if not func:
            return None
        graph = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
        for node in graph:
            if addr >= node.start_ea and addr < node.end_ea:
                return node
        return None
    
    def execute(self, proj, init_block_start, init_block_end, process_block_start, process_block_end, other_blocks, apply_value):
        entry_state = proj.factory.blank_state(addr=init_block_start, remove_options={
                                        angr.sim_options.LAZY_SOLVES})
        sm = proj.factory.simulation_manager(entry_state)
        if init_block_start != process_block_start:
            while True:
                len(sm.active) == 1
                cur = sm.active[0]
                pc = cur.solver.eval(cur.regs.ip)
                if pc >= init_block_end:
                    break
                sm.step()
            
            entry_state = sm.active[0]
            entry_state.regs.ip = process_block_start
        apply_place = None
        def statement_inspect(state):
            nonlocal apply_place
            pc = state.solver.eval(state.regs.ip)
            if pc < process_block_start or pc >= process_block_end:
                return None
            expressions = list(
                state.scratch.irsb.statements[state.inspect.statement].expressions)
            if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
                print('[AngrCore] apply value to address: ' + hex(state.scratch.ins_addr))
                apply_place = state.solver.eval(state.scratch.ins_addr)
                state.scratch.temps[expressions[0].cond.tmp] = apply_value
                # If the first ITE statement of the basic block is not related to the switchvar, will there be a problem?
                state.inspect._breakpoints['statement'] = []   
        entry_state.inspect.b('statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
        
        sm.step()
        while len(sm.active) > 0:
            for active_state in sm.active:
                if active_state.addr in other_blocks:
                    return apply_place, active_state.addr
            sm.step()
        return None
    

    def process(self, entry : int, blocks : list[int]):
        self.graph.clear()
        file_path = idaapi.get_input_file_path()
        load_base = idaapi.get_imagebase()
        graph = {}
        proj = angr.Project(file_path, main_opts={'base_addr': load_base})
        assert proj.arch.name in ARCH_X86 or proj.arch.name in ARCH_ARM or proj.arch.name in ARCH_ARM64, 'unsupported arch...'
        entry_node = self.get_block_node(entry)
        process_bb = [entry] + blocks

        def retn_procedure(state):
            ip = state.solver.eval(state.regs.ip)
            print('[AngrCore] call from ' + hex(ip))
            return
        for b in process_bb:
            node = self.get_block_node(b)
            block = proj.factory.block(b, size=node.end_ea - node.start_ea)
            for ins in block.capstone.insns:
                if is_call(proj.arch.name, ins.mnemonic):
                    print('[AngrCore] ignored call instruction at ' + hex(ins.address))
                    proj.hook(ins.address, retn_procedure, length=ins.size)
        
        cond_map = {}
        for b in process_bb:
            graph[b] = list()
            node = self.get_block_node(b)
            print(hex(b))
            bb0 = self.execute(proj, entry_node.start_ea, entry_node.end_ea, b, node.end_ea, process_bb, claripy.BVV(0, 1))
            bb1 = self.execute(proj, entry_node.start_ea, entry_node.end_ea, b, node.end_ea, process_bb, claripy.BVV(1, 1))
            
            print(bb0)
            print(bb1)
            if bb0 == bb1 and bb0:
                graph[b].append((bb0[1], None))
            elif bb0 and bb1:
                assert bb0[0] == bb1[0]
                cond_map[b] = bb0[0]
                graph[b].append((bb0[1], True))
                graph[b].append((bb1[1], False))
        print(graph)
        ## todo: do patch
        
        cs = proj.arch.capstone
        ks = proj.arch.keystone
        block_map = {}
        for b in process_bb:
            node = self.get_block_node(b)
            assert b == node.start_ea
            
            ptr = 0
            cond = None
            if len(graph[b]) == 1:
                block = proj.factory.block(b, size=node.end_ea - node.start_ea)
                last = block.capstone.insns[-1]
                if is_jump(proj.arch.name, last.mnemonic):
                    ptr = last.address
                else:
                    ptr = node.end_ea
            elif len(graph[b]) == 2:
                block = proj.factory.block(cond_map[b], size=node.end_ea - cond_map[b])
                ptr = cond_map[b]
                cond = None
                for insn in block.capstone.insns:
                    cond = extract_cond_flag(proj.arch.name, insn)
                    if cond:
                        break
                assert cond, 'fail to extract condition type...'
                cond_map[b] = cond
            else:
                ptr = node.end_ea
            raw_code = idaapi.get_bytes(node.start_ea, ptr - node.start_ea)
            reloc_block = RelocBlock(cs, ks, b, raw_code)
            block_map[b] = reloc_block
        #proj.factory.block(addr, size=parent.size)

        allocator = entry
        padding_size = 8
        allocate_map = {}
        visited = set()
        
        def realloc(cur_block):
            nonlocal allocator
            cur_addr = allocator
            block_map[cur_block].reloc_to(allocator)
            cur_size = block_map[cur_block].size() + padding_size
            allocator += cur_size
            for son, _ in graph[cur_block]:
                if son not in visited:
                    visited.add(son)
                    realloc(son)
            allocate_map[cur_block] = cur_addr
            
            
        visited.add(entry)
        realloc(entry)
        patches = []
        print(allocate_map)
        for b in process_bb:
            if b not in allocate_map.keys():
                print('[AngrCore] isolate block detected, the result maybe wrong...')
                continue
            raw_data = block_map[b].asm_data
            if len(graph[b]) == 1:
                succ = graph[b][0][0]
                data = bytes(ks.asm(build_jump(proj.arch.name, allocate_map[succ], None), allocate_map[b] + block_map[b].size())[0])
                data += b'\x00' * (padding_size - len(data))
                raw_data += data

            elif len(graph[b]) == 2:
                succ0 = graph[b][0][0]
                succ1 = graph[b][1][0]
                data = bytes(ks.asm(build_jump(proj.arch.name, allocate_map[succ0], cond_map[b]), allocate_map[b] + block_map[b].size())[0])
                data += bytes(ks.asm(build_jump(proj.arch.name, allocate_map[succ1], None), allocate_map[b] + block_map[b].size() + len(data))[0])
                data += b'\x00' * (padding_size - len(data))
                raw_data += data
            else:
                raw_data += b'\x00' * padding_size
            for insn in cs.disasm(raw_data, allocate_map[b]):
                print(insn)
            print()
            patches.append((allocate_map[b] ,raw_data))
        self.graph = graph
        return patches
            

        
        

    def get_result(self) -> dict[int, int]:
        return self.graph