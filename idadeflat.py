import idaapi
import idc
import json
from idadeflat_cores.core_base import DeflatCore
from idadeflat_cores.angr_core import AngrDeflatCore
ADD_BLOCK_ACTION = ('IDADeflat:add_block', 'Add Relevant Block', 'add_working_blocks')
SET_ENTRY_ACTION = ('IDADeflat:set_entry', 'Set Function Entry', 'set_entry_block')
DO_DEFLAT_ACTION = ('IDADeflat:do_deflat', 'Deflat GOGOGO', 'do_deflat')
RESET_ACTION = ('IDADeflat:reset', 'Reset Plugin State', 'reset_state')
SHOW_BLOCK_ACTION = ('IDADeflat:show', 'Show State Info', 'show_state')
REMOVE_BLOCK_ACTION = ('IDADeflat:del_block', 'Delete Relevant Block', 'del_working_blocks')
IMPORT_BLOCK_ACTION = ('IDADeflat:import_block', 'Import Blocks From File', 'import_blocks')
UNDO_PATCH_ACTION = ('IDADeflat:undo_patch', 'Undo Last Patching', 'undo_patch')
BASIC_ACTIONS = [SET_ENTRY_ACTION, ADD_BLOCK_ACTION, REMOVE_BLOCK_ACTION, DO_DEFLAT_ACTION, RESET_ACTION, UNDO_PATCH_ACTION, SHOW_BLOCK_ACTION, IMPORT_BLOCK_ACTION]
SWITCH_ACTIONS = []


def get_block_node(addr):
    func = idaapi.get_func(addr)
    if not func:
        return None
    graph = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
    for node in graph:
        if addr >= node.start_ea and addr < node.end_ea:
            return node
    return None

def set_color_to_block(node, color):
    ptr = node.start_ea
    while ptr < node.end_ea:
        idc.set_color(ptr, idc.CIC_ITEM, color)
        ptr = idaapi.next_head(ptr, node.end_ea)

class ActionHandler(idaapi.action_handler_t):

    def __init__(self, host, name, label, callback, metadata : dict=None, shortcut=None, tooltip=None, icon=-1, flags=0):
        idaapi.action_handler_t.__init__(self)
        self.callback = callback
        self.name = name
        self.host = host
        self.metadata =metadata
        self.action_desc = idaapi.action_desc_t(name, label, self, shortcut, tooltip, icon, flags)

    def unregister_action(self):
        idaapi.unregister_action(self.name)

    def register_action(self, menupath=None):
        if not idaapi.register_action(self.action_desc):
            return False
        if menupath and not idaapi.attach_action_to_menu(menupath, self.name, idaapi.SETMENU_APP):
            return False
        return True

    def activate(self, ctx):
        self.callback(host=self.host, meta=self.metadata, ctx=ctx)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    

class UIHooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idx = 0
            for action in BASIC_ACTIONS:
                idaapi.attach_action_to_popup(widget, popup, action[0], "Deflat/")
                if idx == 2 or idx == 6:
                    idaapi.attach_action_to_popup(widget, popup, "-", 'Deflat/')
                idx += 1
            for action in SWITCH_ACTIONS:
                idaapi.attach_action_to_popup(widget, popup, action[0], "Deflat/Cores/")


class StateChoose(idaapi.Choose):
    
    def __init__(self, title, items, embedded=False):
        idaapi.Choose.__init__(self, title, [["Address", 20], ["Function", 30], ["Type", 30]], embedded=embedded)
        self.items = items
        self.icon = 46

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        idaapi.jumpto(int(self.items[n][0], 16))

class IDADeflatMain:
    
    def __init__(self):
        self.working_entry = -1
        self.working_blocks = []
        self.process_cores : list[DeflatCore] = []
        self.using_core :DeflatCore = None
        self.registered_actions = []
        self.ui_hook = None
        self.last_patch = []

    def add_core(self, core : DeflatCore):
        self.process_cores.append(core)

    def set_core(self, core_name):
        for core in self.process_cores:
            if core.get_name() == core_name:
                self.using_core = core
                return True
        return False


    @staticmethod
    def add_working_blocks(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        if main_obj.working_entry < 0:
            print('[IDADeflat] please set function entry address first!')
            return
        ea = idaapi.get_screen_ea()
        block = get_block_node(ea)
        if not block:
            print('[IDADeflat] unable to locate basic block for %s' % hex(ea))
            return
        ea = block.start_ea
        func = idaapi.get_func(ea)
        if func is None or func.start_ea != main_obj.working_entry:
            print('[IDADeflat] invalid basic block address for Function: %s' % idaapi.get_func_name(main_obj.working_entry))
            return
        main_obj.working_blocks.append(ea)
        set_color_to_block(get_block_node(ea), 0xffcc33)
        print('[IDADeflat] relevant block at %s has been added to working list...' % hex(ea))
        
    @staticmethod
    def import_blocks(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        IDADeflatMain.reset_state(host=main_obj)
        file = open('blocks.json', 'rb')
        blocks_info = json.load(file)
        main_obj.working_entry = blocks_info['entry_block']
        for addr in blocks_info['relevant_blocks']:
            main_obj.working_blocks.append(addr)
        file.close()


    @staticmethod
    def del_working_blocks(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        ea = idaapi.get_screen_ea()
        block = get_block_node(ea)
        if not block:
            print('[IDADeflat] unable to locate basic block for %s' % hex(ea))
            return
        ea = block.start_ea
        if ea in main_obj.working_blocks:
            main_obj.working_blocks.remove(ea)
            set_color_to_block(get_block_node(ea), 0xffffff)
            print('[IDADeflat] remove relevant block successfully...')

    @staticmethod
    def set_entry_block(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        if func is None:
            print('[IDADeflat] invalid entry point')
            return
        if main_obj.working_entry > 0:
            set_color_to_block(get_block_node(main_obj.working_entry), 0xffffff)
        main_obj.working_entry = func.start_ea
        set_color_to_block(get_block_node(func.start_ea), 0xffcc33)
        print('[IDADeflat] entry point set to %s in %s' % (hex(func.start_ea), idaapi.get_func_name(func.start_ea)))

    @staticmethod
    def do_deflat(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        if main_obj.working_entry < 0 or len(main_obj.working_blocks) == 0:
            print('[IDADeflat] nothing to do, please specify a function and relevant blocks....')
            return
        target_func = idaapi.get_func(main_obj.working_entry)
        if not target_func:
            print('[IDADeflat] invalid function address...')
            return
        for block in main_obj.working_blocks:
            if idaapi.get_func(block) != target_func:
                print('[IDADeflat] blocks are not in the same function!...')
                return
        patches = main_obj.using_core.process(main_obj.working_entry, main_obj.working_blocks.copy())
        main_obj.reset_state(host=main_obj)
        graph = idaapi.FlowChart(target_func, flags=idaapi.FC_PREDS)
        for node in graph:
            main_obj.last_patch.append((node.start_ea, idaapi.get_bytes(node.start_ea, node.end_ea - node.start_ea)))
            idaapi.patch_bytes(node.start_ea, (node.end_ea - node.start_ea) * b'\x00')
        for patch_addr, patch_data in patches:
            idaapi.patch_bytes(patch_addr, patch_data)
            
    @staticmethod
    def undo_patch(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        for patch_addr, patch_data in main_obj.last_patch:
            idaapi.patch_bytes(patch_addr, patch_data)
        main_obj.last_patch.clear()

    @staticmethod
    def switch_core(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        metadata : dict = kwargs['meta']
        core_name = metadata['core_name']
        if main_obj.set_core(core_name):
            print('[IDADeflat] switch core to %s' % core_name)
        else:
            print('[IDADeflat] fail to set core....')

    @staticmethod
    def reset_state(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        if main_obj.working_entry > 0:
            set_color_to_block(get_block_node(main_obj.working_entry), 0xffffff)
        for ea in main_obj.working_blocks:
            set_color_to_block(get_block_node(ea), 0xffffff)
        main_obj.working_entry = -1
        main_obj.working_blocks.clear()
        main_obj.last_patch.clear()
        print('[IDADeflat] reset state successfully..')
        

    @staticmethod
    def show_state(**kwargs):
        main_obj : IDADeflatMain = kwargs['host']
        if main_obj.working_entry > 0:
            items = []
            items.append((hex(main_obj.working_entry), idaapi.get_func_name(main_obj.working_entry), 'EntryBlock'))
            for addr in main_obj.working_blocks:
                func = idaapi.get_func(addr)
                items.append((hex(addr), idaapi.get_func_name(func.start_ea), 'RelevantBlock'))
            ch = StateChoose('Deflat Info', items)
            ch.Show()
        else:
            print('[IDADeflat] no state...')

    def init(self):
        self.add_core(AngrDeflatCore())
        self.using_core = self.process_cores[0]
        for action in BASIC_ACTIONS:
            handler = ActionHandler(self, action[0], action[1], getattr(IDADeflatMain, action[2]))
            handler.register_action()
            self.registered_actions.append(handler)
        for core in self.process_cores:
            core_name = core.get_name()
            name = 'IDADeflat:' + core_name
            label_name = 'Use ' + core_name
            handler = ActionHandler(self, name, label_name, 
                                    getattr(IDADeflatMain, 'switch_core'), 
                                    metadata={
                                        'core_name' : core_name
                                    })
            handler.register_action()
            SWITCH_ACTIONS.append((name, label_name))
            self.registered_actions.append(handler)

        self.ui_hook = UIHooks()
        self.ui_hook.hook()

    def term(self):
        if self.ui_hook:
            self.ui_hook.unhook()
        for action in self.registered_actions:
            action.unregister_action()
        self.registered_actions.clear()

    
def check_ida_version():
    if idaapi.IDA_SDK_VERSION < 700:
        print("[-] IDADeflat support 7.x IDA, please update your IDA version.")
        return False
    return True


class IDADeflat_t(idaapi.plugin_t):
    comment = "IDADeflat plugin for IDA Pro (using angr framework)"
    help = "todo"
    wanted_name = "IDADeflat"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP
    def init(self):
        if not check_ida_version():
             return idaapi.PLUGIN_SKIP
        self.main = IDADeflatMain()
        self.main.init()
        print('[IDADeflat] IDADeflat plugin initialized!')
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        if self.main:
            self.main.term()
        pass

def PLUGIN_ENTRY():
    return IDADeflat_t()

