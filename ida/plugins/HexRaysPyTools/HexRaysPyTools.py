import HexRaysPyTools.Actions as Actions
from HexRaysPyTools.Core.TemporaryStructure import *
import HexRaysPyTools.Forms as Forms
import idaapi
import HexRaysPyTools.Core.NegativeOffsets as NegativeOffsets
import HexRaysPyTools.Core.Helper as Helper
import HexRaysPyTools.Core.Const as Const
from HexRaysPyTools.Core.SpaghettiCode import SpaghettiVisitor, SwapThenElseVisitor

# import Core.QtShim as QtShim

potential_negatives = {}


def hexrays_events_callback(*args):
    global potential_negatives

    hexrays_event = args[0]

    if hexrays_event == idaapi.hxe_populating_popup:
        form, popup, hx_view = args[1:]
        item = hx_view.item  # current ctree_item_t

        if Actions.RecastItemRight.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.RecastItemRight.name, None)

        if Actions.RecastItemLeft.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.RecastItemLeft.name, None)

        if Actions.RenameOther.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.RenameOther.name, None)

        if Actions.RenameInside.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.RenameInside.name, None)

        if Actions.RenameOutside.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.RenameOutside.name, None)

        if Actions.SwapThenElse.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.SwapThenElse.name, None)

        if Actions.ShallowScanVariable.check(item):
            idaapi.attach_action_to_popup(form, popup, Actions.ShallowScanVariable.name, None)
            idaapi.attach_action_to_popup(form, popup, Actions.DeepScanVariable.name, None)
            idaapi.attach_action_to_popup(form, popup, Actions.RecognizeShape.name, None)

        if Actions.CreateNewField.check(hx_view.cfunc, item):
            idaapi.attach_action_to_popup(form, popup, Actions.CreateNewField.name, None)

        if item.citype == idaapi.VDI_FUNC:
            # If we clicked on function
            if not hx_view.cfunc.entry_ea == idaapi.BADADDR:  # Probably never happen
                idaapi.attach_action_to_popup(form, popup, Actions.AddRemoveReturn.name, None)
                idaapi.attach_action_to_popup(form, popup, Actions.ConvertToUsercall.name, None)
                idaapi.attach_action_to_popup(form, popup, Actions.DeepScanReturn.name, None)

        elif item.citype == idaapi.VDI_LVAR:
            # If we clicked on argument
            local_variable = hx_view.item.get_lvar()          # idaapi.lvar_t
            if local_variable.is_arg_var:
                idaapi.attach_action_to_popup(form, popup, Actions.RemoveArgument.name, None)

        elif item.citype == idaapi.VDI_EXPR:
            if item.e.op == idaapi.cot_num:
                # number_format = item.e.n.nf                       # idaapi.number_format_t
                # print "(number) flags: {0:#010X}, type_name: {1}, opnum: {2}".format(
                #     number_format.flags,
                #     number_format.type_name,
                #     number_format.opnum
                # )
                idaapi.attach_action_to_popup(form, popup, Actions.GetStructureBySize.name, None)
            elif item.e.op == idaapi.cot_var:
                # Check if we clicked on variable that is a pointer to a structure that is potentially part of
                # containing structure
                if item.e.v.idx in potential_negatives:
                    idaapi.attach_action_to_popup(form, popup, Actions.SelectContainingStructure.name, None)
                if Actions.ResetContainingStructure.check(hx_view.cfunc.get_lvars()[item.e.v.idx]):
                    idaapi.attach_action_to_popup(form, popup, Actions.ResetContainingStructure.name, None)

    elif hexrays_event == idaapi.hxe_double_click:

        hx_view = args[1]
        item = hx_view.item
        if item.citype == idaapi.VDI_EXPR and item.e.op == idaapi.cot_memptr:
            # Look if we double clicked on expression that is member pointer. Then get tinfo_t of  the structure.
            # After that remove pointer and get member name with the same offset

            if item.e.x.op == idaapi.cot_memref and item.e.x.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.x.m
            elif item.e.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.m
            else:
                return 0

            udt_member = idaapi.udt_member_t()
            udt_member.offset = method_offset * 8
            vtable_tinfo.find_udt_member(idaapi.STRMEM_OFFSET, udt_member)

            func_ea = Helper.get_virtual_func_address(udt_member.name, class_tinfo, vtable_offset)
            if func_ea:
                idaapi.open_pseudocode(func_ea, 0)
                return 1

    elif hexrays_event == idaapi.hxe_maturity:
        cfunc, level_of_maturity = args[1:]

        if level_of_maturity == idaapi.CMAT_BUILT:
            # print '=' * 40
            # print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            # print '=' * 40
            # print cfunc

            # First search for CONTAINING_RECORD made by Ida
            visitor = NegativeOffsets.SearchVisitor(cfunc)
            visitor.apply_to(cfunc.body, None)
            negative_lvars = visitor.result

            # Second get saved information from comments
            lvars = cfunc.get_lvars()
            for idx in xrange(len(lvars)):
                result = NegativeOffsets.parse_lvar_comment(lvars[idx])
                if result and result.tinfo.equals_to(lvars[idx].type().get_pointed_object()):
                    negative_lvars[idx] = result

            # Third make an analysis of local variables that a structure pointers and have reference that pass
            # through structure boundaries. This variables will be considered as potential pointers to substructure
            # and will get a menu on right click that helps to select Containing Structure from different libraries

            structure_pointer_variables = {}
            for idx in set(range(len(lvars))) - set(negative_lvars.keys()):
                if lvars[idx].type().is_ptr():
                    pointed_tinfo = lvars[idx].type().get_pointed_object()
                    if pointed_tinfo.is_udt():
                        structure_pointer_variables[idx] = pointed_tinfo

            if structure_pointer_variables:
                visitor = NegativeOffsets.AnalyseVisitor(structure_pointer_variables, potential_negatives)
                visitor.apply_to(cfunc.body, None)

            if negative_lvars:
                visitor = NegativeOffsets.ReplaceVisitor(negative_lvars)
                visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == idaapi.CMAT_TRANS1:

            visitor = SwapThenElseVisitor(cfunc.entry_ea)
            visitor.apply_to(cfunc.body, None)

        elif level_of_maturity == idaapi.CMAT_TRANS2:
            # print '=' * 40
            # print '=' * 15, "LEVEL", level_of_maturity, '=' * 16
            # print '=' * 40
            # print cfunc
            visitor = SpaghettiVisitor()
            visitor.apply_to(cfunc.body, None)
    return 0


class MyPlugin(idaapi.plugin_t):
    # flags = idaapi.PLUGIN_HIDE
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "This is help"
    wanted_name = "HexRaysPyTools"
    wanted_hotkey = "Alt-F8"

    @staticmethod
    def init():
        if not idaapi.init_hexrays_plugin():
            print "[ERROR] Failed to initialize Hex-Rays SDK"
            return idaapi.PLUGIN_SKIP

        Helper.temporary_structure = TemporaryStructureModel()
        # Actions.register(Actions.CreateVtable)
        Actions.register(Actions.ShowGraph)
        Actions.register(Actions.ShowClasses)
        Actions.register(Actions.GetStructureBySize)
        Actions.register(Actions.RemoveArgument)
        Actions.register(Actions.AddRemoveReturn)
        Actions.register(Actions.ConvertToUsercall)
        Actions.register(Actions.ShallowScanVariable, Helper.temporary_structure)
        Actions.register(Actions.DeepScanVariable, Helper.temporary_structure)
        Actions.register(Actions.DeepScanReturn, Helper.temporary_structure)
        Actions.register(Actions.DeepScanFunctions, Helper.temporary_structure)
        Actions.register(Actions.RecognizeShape)
        Actions.register(Actions.CreateNewField)
        Actions.register(Actions.SelectContainingStructure, potential_negatives)
        Actions.register(Actions.ResetContainingStructure)
        Actions.register(Actions.RecastItemRight)
        Actions.register(Actions.RecastItemLeft)
        Actions.register(Actions.RenameOther)
        Actions.register(Actions.RenameInside)
        Actions.register(Actions.RenameOutside)
        Actions.register(Actions.SwapThenElse)

        idaapi.attach_action_to_menu('View/Open subviews/Local types', Actions.ShowClasses.name, idaapi.SETMENU_APP)
        idaapi.install_hexrays_callback(hexrays_events_callback)

        Helper.touched_functions.clear()
        Const.init()

        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(arg):
        tform = idaapi.find_tform("Structure Builder")
        if tform:
            idaapi.switchto_tform(tform, True)
        else:
            Forms.StructureBuilder(Helper.temporary_structure).Show()

    @staticmethod
    def term():
        if Helper.temporary_structure:
            Helper.temporary_structure.clear()
        # Actions.unregister(Actions.CreateVtable)
        Actions.unregister(Actions.ShowGraph)
        Actions.unregister(Actions.ShowClasses)
        Actions.unregister(Actions.GetStructureBySize)
        Actions.unregister(Actions.RemoveArgument)
        Actions.unregister(Actions.AddRemoveReturn)
        Actions.unregister(Actions.ConvertToUsercall)
        Actions.unregister(Actions.ShallowScanVariable)
        Actions.unregister(Actions.DeepScanVariable)
        Actions.unregister(Actions.DeepScanReturn)
        Actions.unregister(Actions.DeepScanFunctions)
        Actions.unregister(Actions.RecognizeShape)
        Actions.unregister(Actions.CreateNewField)
        Actions.unregister(Actions.SelectContainingStructure)
        Actions.unregister(Actions.ResetContainingStructure)
        Actions.unregister(Actions.RecastItemRight)
        Actions.unregister(Actions.RecastItemLeft)
        Actions.unregister(Actions.RenameOther)
        Actions.unregister(Actions.RenameInside)
        Actions.unregister(Actions.RenameOutside)
        Actions.unregister(Actions.SwapThenElse)
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    idaapi.notify_when(idaapi.NW_OPENIDB, Helper.init_demangled_names)
    idaapi.notify_when(idaapi.NW_OPENIDB, Helper.init_imported_ea)
    return MyPlugin()
