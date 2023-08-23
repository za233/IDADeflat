import angr
import idaapi
import pyvex
import claripy
from .core_base import DeflatCore

class AngrDeflatCore(DeflatCore):
    def __init__(self):
        DeflatCore.__init__(self, 'AngrDeflatCore')
        self.graph = {}

    def get_block_node(addr):
        func = idaapi.get_func(addr)
        if not func:
            return None
        graph = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
        for node in graph:
            if addr >= node.start_ea and addr < node.end_ea:
                return node
        return None
    
    def execute(self, proj, entry, blocks, apply_value):
        entry_state = proj.factory.blank_state(addr=entry, remove_options={
                                        angr.sim_options.LAZY_SOLVES})
        def ignore_call(state):
            if not state.solver.symbolic(state.regs.ip):
                proj.hook(state.solver.eval(state.regs.ip), angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
        entry_state.inspect.b('call', when = angr.BP_BEFORE, action = ignore_call)

        def statement_inspect(state):
            expressions = list(
                state.scratch.irsb.statements[state.inspect.statement].expressions)
            if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
                state.scratch.temps[expressions[0].cond.tmp] = apply_value
                state.inspect._breakpoints['statement'] = []
        entry_state.inspect.b('statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
        sm = proj.factory.simulation_manager(entry_state)
        sm.step()
        while len(sm.active) > 0:
            for active_state in sm.active:
                if active_state.addr in blocks:
                    return active_state.addr
            sm.step()
        return None

    def process(self, entry : int, blocks : list[int]):
        self.graph.clear()
        file_path = idaapi.get_input_file_path()
        load_base = idaapi.get_imagebase()
        graph = {}
        proj = angr.Project(file_path, main_opts={'base_addr': load_base})
        process_bb = [entry] + blocks
        for b in process_bb:
            graph[b] = set()
            bb0 = self.execute(proj, b, process_bb, claripy.BVV(0, 1))
            bb1 = self.execute(proj, b, process_bb, claripy.BVV(1, 1))
            if bb0:
                graph[b].add(bb0)
            if bb1:
                graph[b].add(bb1)
        print(graph)
        ## todo: do patch
        
        

    def get_result(self) -> dict[int, int]:
        return self.graph