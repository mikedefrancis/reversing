'''
Created on Oct 16, 2017

@author: MPD

@description: sark utilities

@src: https://github.com/tmr232/Sark

@note: NOTE! all calls into this external library should be handled here.
Additionally, all dependencies for this library that needed to be installed
in order to use the features therein should be documented here.

@purpose: Purpose of this is to have very basic python functions wrapping IDA Python API calls
Not too much logic in here. Idea is to reduce errors and extra duplicated code in other places 
'''

import idautils
import idaapi
import idc

from lib_ida import *
import lib_ida
from lib_external import *

### SARK IMPORTS
### @MPD HACK importing sark internals for fun stuff
#import sark
from sark.code.segment import Segment
from sark.code.function import Function
from sark.codeblock import CodeBlock
from sark.code.switch import Switch
from sark.code.line import Line
from sark.code.xref import Xref
from sark.code.instruction import Instruction
from sark.code.base import get_func, demangle
from sark.core import set_name, get_ea, fix_addresses, is_same_function,add_func
#from sark.ui import updates_ui
#from sark import exceptions

##############


# extend the SARK Line class
class MIDA_LINE(Line):
    
    def __init__(self, ea=None, name=None):
        if ea != None:
            super(MIDA_LINE, self).__init__(ea=ea)
        elif name != None:
            super(MIDA_LINE, self).__init__(name=name)
        else:
            breakx("Error defining MIDA_LINE. NO ARGS SUPPLIED.")
            
        #self.utils = ida_utils_inst            
        self.utils = lib_ida.ida_utils.MidaIdaUtils.GET_INSTANCE()
    ########## INSTANCE METHODS #############
    # add our own instance methods here
    # ...
    @property
    def mida_instruction(self):
        return MIDA_INSTRUCTION(self.ea)    
        
    ########## STATIC METHODS #############   
    
    @staticmethod
    def get_lines(start=None, end=None, reverse=False):
        start, end = fix_addresses(start, end)
        if not reverse:
            item = idaapi.get_item_head(start)
            while item < end:
                yield MIDA_LINE(ea=item)
                item += idaapi.get_item_size(item)
        else:  # if reverse:
            item = idaapi.get_item_head(end - 1)
            while item >= start:
                yield MIDA_LINE(ea=item)
                item = idaapi.get_item_head(item - 1)
       
    
# extend the SARK Switch class
# designed to maximize IDA switch/case detection 
class MIDA_SWITCH(Switch):
    
    def __init__(self, ida_utils_inst=None, ea=None):
        if ea != None:
            super(MIDA_SWITCH, self).__init__(ea=ea)                 
        else:
            breakx("Error defining MIDA_SWITCH. NO ARGS SUPPLIED.")
            
        #self.utils = ida_utils_inst            
        self.utils = lib_ida.ida_utils.MidaIdaUtils.GET_INSTANCE()     
    ########## INSTANCE METHODS #############
    # add our own instance methods here
    # ...
    # TODO: Define some ARM / X86 specific handling
    # self.indexing_mode() does some ARM specific stuff
        
    ########## STATIC METHODS #############   
    @staticmethod
    def is_switch(ea):
        return sark.is_switch(ea)
    
    
    
# extend the SARK Segment class
class MIDA_SEGMENT(Segment):
    
    def __init__(self, ea=None, name=None, index=None, segment_t=None):
        if ea != None:
            super(MIDA_SEGMENT, self).__init__(ea=ea)
        elif name != None:
            super(MIDA_SEGMENT, self).__init__(name=name)
        elif index != None:
            super(MIDA_SEGMENT, self).__init__(index=index)       
        elif segment_t != None:
            super(MIDA_SEGMENT, self).__init__(segment_t=segment_t)                            
        else:
            breakx("Error defining MIDA_SEGMENT. NO ARGS SUPPLIED.")
            
        if self.segm is None:
            breakx("Error finding segment with specified args! " + hex(ea))
            
        #self.utils = ida_utils_inst            
        self.utils = lib_ida.ida_utils.MidaIdaUtils.GET_INSTANCE()         
    ########## INSTANCE METHODS #############
    # add our own instance methods here
    # ...
    @property
    def segm(self):
        return self.segment_t
        
    @property
    def functions(self):
        return MIDA_FUNCTION.get_functions(self.startEA, self.endEA)
        
    #overwrite existing sark segment property
    @property
    def lines(self):
        return MIDA_LINE.get_lines(self.startEA, self.endEA)
    ########## STATIC METHODS #############   
    
    @staticmethod
    def get_segments(seg_type=None):
        for index in xrange(idaapi.get_segm_qty()):
            seg = MIDA_SEGMENT(index=index)
            if (seg_type is None) or (seg.type == seg_type):
                yield MIDA_SEGMENT(index=index)
                
# extend the SARK Instruction class
class MIDA_INSTRUCTION(Instruction):#sark.Instruction):
    
    def __init__(self, ea=None):
        if ea != None:
            super(MIDA_INSTRUCTION, self).__init__(ea=ea)                 
        else:
            breakx("Error defining MIDA_INSTRUCTION. NO ARGS SUPPLIED.")
            
        #self.utils = ida_utils_inst            
        self.utils = lib_ida.ida_utils.MidaIdaUtils.GET_INSTANCE()
    ########## INSTANCE METHODS #############
    # add our own instance methods here
    # ...
    # TODO: Define some ARM / X86 specific handling in ida_utilsARM/x86 and call from here
    # NOTE self.indexing_mode() does some ARM specific stuff
    def get_condition(self):
        if self.utils is not None:
            return self.utils.getInsnCond(self.insn_t)
    
    def is_conditional_jump(self):      
        if self.utils is not None:
            return self.utils.isConditionalJump(self.insn_t)
    
    def is_unconditional_jump(self):      
        if self.utils is not None:
            return self.utils.isUnconditionalJump(self.insn_t)
                    
    def is_trap(self):
        if self.utils is not None:        
            return self.utils.is_trap(self.insn_t)

    def isCall(self):
        if self.utils is not None:        
            return self.utils.isCall(self.insn_t)
 
    def isRet(self):
        if self.utils is not None:        
            return self.utils.isRet(self.insn_t)
 
    def isMov(self):
        if self.utils is not None:        
            return self.utils.isMov(self.insn_t)
    
    def isJmp(self):
        if self.utils is not None:        
            return self.utils.isJmp(self.insn_t)

    def isIndirectJmpCall(self):
        if self.utils is not None:        
            return self.utils.isIndirectJmpCall(self.insn_t)
    
    def IsDereferenced(self):
        if self.utils is not None:        
            return self.utils.isTrap(self.ea)
    
    def IsDereferencedMem(self):
        if self.utils is not None:        
            return self.utils.isTrap(self.ea)
                        
    ########## STATIC METHODS #############   
    # @MPD return a list of all instructions within the range specified
    # note that this may give error if range contains invalid instructions
    @staticmethod
    def get_instructions(start, end):
        lines = MIDA_LINE.get_lines(start, end)
        for line in lines:
            yield MIDA_INSTRUCTION(line.ea)
             
    # x86 specific way of doing this @
    # https://github.com/trailofbits/mcsema/blob/master/tools/mcsema_disass/ida/get_cfg.py             
    @staticmethod
    def isConditionalJump(ea):
        return MIDA_INSTRUCTION(ea).is_conditional_jump()
    
    # x86 specific way of doing this @
    # https://github.com/trailofbits/mcsema/blob/master/tools/mcsema_disass/ida/get_cfg.py
    @staticmethod
    def isUnconditionalJump(ea):
        return MIDA_INSTRUCTION(ea).is_unconditional_jump()
    
    # note this is overloading the existing sark instruction isCall which might be sufficient for our purposes
    @staticmethod
    def isCall(ea):
        return MIDA_INSTRUCTION(ea).is_call()
    
    # note this is overloading the existing sark instruction isCall which might be sufficient for our purposes
    @staticmethod
    def isRet(ea):
        return MIDA_INSTRUCTION(ea).is_ret()
    
    @staticmethod
    def isTrap(ea):
        return MIDA_INSTRUCTION(ea).is_trap()
    
    @staticmethod
    def isIndirectJump(ea):
        return MIDA_INSTRUCTION(ea).is_indirect_jump()
    
#     @staticmethod
#     def isFarJump(ea):
#         int     is_far_jump (int icode)
#         return MIDA_INSTRUCTION(ea).is_indirect_jump()

#     # @MPD replace with MIDA_INSTRUCTION in SARK components
#     class MidaInstruction:        
#         def __init__(block, addr, insn_t, inst_bytes, true_target=None, false_target=None):
#             self.inst = block.insts.add()
#             self.inst.addr = addr
#             self.inst.bytes = inst_bytes
#             self.inst.len = len(inst_bytes)
#             if true_target != None: 
#                 self.inst.true_target = true_target
#             if false_target != None: 
#                 self.inst.false_target = false_target
#             
#         def handleJmpTable(self):
#             si = idaapi.get_switch_info_ex(self.inst.addr)
#             jsize = si.get_jtable_element_size()
#             jstart = si.jumps
# 
#             valid_sizes = [4, getBitness()/8]
#             readers = { 4: readDword, 8: readQword }
#             print "\tJMPTable Start: {0:x}".format(jstart)
#             seg_start = idc.SegStart(jstart)
#             if seg_start != idc.BADADDR:
#                 self.inst.jump_table.offset_from_data = jstart - seg_start
#             print "\tJMPTable offset from data: {:x}".format(self.inst.jump_table.offset_from_data)
# 
#             self.inst.jump_table.zero_offset = 0
#             i = 0
#             entries = si.get_jtable_size()
#             entries = sanityCheckJumpTableSize(inst, entries)
#             for i in xrange(entries):
#                 je = readers[jsize](jstart+i*jsize)
#                 # check if this is an offset based jump table
#                 if si.flags & idaapi.SWI_ELBASE == idaapi.SWI_ELBASE:  # adjust jump target based on offset in table
#                     je = 0xFFFFFFFF & (je + si.elbase)
#                     self.inst.jump_table.table_entries.append(je)           
#             print "\t\tAdding JMPTable {0}: {1:x}".format(i, je)           
#             return je
# 
#         def ProcessIt(self):
#             insn_t = idautils.DecodeInstruction(self.inst)
#             if insn_t is None:
#                 return None              
#             for (idx, op) in enumerate(insn_t.Operands):
#                 if op.value == dref:
#                 # IDA sometime interpret an immediate operand as a memory operand if it references memory.
#                 # its the first operand (probably a destination) and IDA thinks its o_mem
#                 # in this case, IDA is probably right; don't mark it as an immediate
#                     if idx == 0 and op.type == idaapi.o_mem:
#                         continue
#                     if op.type in [idaapi.o_imm, idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
#                         if op.reg > 0:
#                             self.inst.mem_reloc_offset = op.offb # "MEM"
#                         self.inst.imm_reloc_offset = op.offb # "IMM"
# 
#             for op in insn_t.Operands:
#                 if op.type in [idaapi.o_displ, idaapi.o_phrase]:
#                     self.inst.mem_reloc_offset = op.offb # "MEM"
#     # @MPD @ARM needs to be handled differently for x86
#     def process_instr(self, basic_block, addr, new_eas):
#         insn_t, inst_bytes = self.decode_instr(addr)
#         if not insn_t:
#             # handle jumps after noreturn functions
#             if idc.Byte(addr) == 0xCC:
#                 return True, MidaInstruction(basic_block, addr, insn_t, inst_bytes)
#             else:
#                 raise Exception("Cannot read instruction at: {0:x}".format(addr))
#         if self.isHlt(insn_t): # skip HLTs -- they are  used in ELFs after a noreturn call
#             return False, None 
#         print  "\t\tinst: {0}".format(idc.GetDisasm(addr))
#         print  "\t\tBytes: {0}".format(inst_bytes)
# 
#         instr =  MidaInstruction(basic_block, addr, insn_t, inst_bytes)
# 
#         if self.isJmpTable(addr):
#             print "jump table"
#             je = instr.handleJmpTable(addr)
#             if je not in recovered_ea and isStartOfFunction(je):           
#                 new_eas.add(je)
#             print "\t\tAdding JMPTable {0}: {1:x}".format(i, je)
#             return False
    
#     def findRelocOffset(self, ea, size):
#         for i in xrange(ea,ea+size):
#             if idc.GetFixupTgtOff(i) != -1:
#                 return i-ea
#         return -1
# 
#     def GetOperandValue(self, ea, n):
#         """
#         Get number used in the operand
#         This function returns an immediate number used in the operand
#         @param ea: linear address of instruction
#         @param n: the operand number
#         @return: value
#             operand is an immediate value  => immediate value
#             operand has a displacement     => displacement
#             operand is a direct memory ref => memory address
#             operand is a register          => register number
#             opeand is a register phrase   => phrase number
#             otherwise                      => None
#        """
#         inslen = idaapi.decode_insn(ea)
#         if inslen == 0:
#             return -1
#         op = idaapi.cmd.Operands[n]
#         if not op:
#             return -1
#         if op.type == idaapi.o_reg:
#             value = op.reg
#         elif op.type == idaapi.o_displ:
#             value = op.addr 
#         elif op.type == idaapi.o_imm:
#             # we aren't sure what we have, but it use a register... probably not an immediate but instead a memory reference
#             if n > 0 and op.reg > 0: # McSema:  # IDA will do stupid things like say an immediate operand is a memory operand if it references memory."we aren't sure  what we have, but if it uses a register... probably not an immediate but instead a memory reference""
#                 value = op.addr
#             else:    
#                 value = op.value                    
#         elif op.type == idaapi.o_phrase:
#             value = op.phrase
#         elif op.type in [ idaapi.o_mem, idaapi.o_far, idaapi.o_near, idaapi.o_displ ]:
#             value = op.addr
#         else:          
#             value = None
#         return value    




#        

    
    
# extend the SARK Function class    
class MIDA_FUNCTION(Function):
    
    def __init__(self, ea=None, name=None):
        if ea != None:
            super(MIDA_FUNCTION, self).__init__(ea=ea)
        elif name != None:
            super(MIDA_FUNCTION, self).__init__(name=name)
        else:
            breakx("Error defining MIDA_FUNCTION. NO ARGS SUPPLIED.")
            
            
            
        self.utils = lib_ida.ida_utils.MidaIdaUtils.GET_INSTANCE()
        
    ########## INSTANCE METHODS #############
    # add our own function instance methods here
    # ...
    def get_blocks(self):
        return MIDA_BLOCK.get_blocks(self.startEA, self.endEA)
        
    def get_lines(self):
        return MIDA_FUNCTION.iter_function_lines(self.startEA)
    
    def get_instructions(self):
        return MIDA_INSTRUCTION.get_instructions(self.startEA, self.endEA)
    
    ########## STATIC METHODS #############        
        
    # wrap the SARK static utility methods 
    @staticmethod
    def get_functions(start=None, end=None):
        start, end = fix_addresses(start, end)
        for func_t in idautils.Functions(start, end):
            yield MIDA_FUNCTION(ea = func_t)

    
    @staticmethod
    def iter_function_lines(func_ea):
        for line in idautils.FuncItems(get_ea(func_ea)):
            yield MIDA_LINE(ea = line)
        
    
    ####### CUSTOM STATIC METHODS ################
    # add our own static utility methods
    @staticmethod
    def get_name(addr):
        addr = idc.GetFunctionAttr(addr, idc.FUNCATTR_START)
        return idc.GetTrueNameEx(addr,addr)
    
    @staticmethod
    def get_bounds_by_name(name):
        func_ea = idaapi.get_name_ea(-1, name)
        if func_ea == idaapi.BADADDR:
            breakx("Unable to find function named " + name)
        else:
            return MIDA_FUNCTION.getFunctionBoundsByAddr(func_ea)
    
    @staticmethod
    def get_bounds_by_addr(addr):
        func = idaapi.get_func(addr)
        return func.startEA, func.endEA

    @staticmethod
    def get_flags(addr):
        flags = idc.GetFunctionFlags(addr)
        return flags
    
    @staticmethod
    def is_thunk(addr):
        flags = idc.GetFunctionFlags(addr)
        return flags == idc.FUNC_THUNK 
    
    @staticmethod
    def is_lib(addr):
        flags = idc.GetFunctionFlags(addr)
        return flags == idc.FUNC_LIB     
    ######################################
    
 
class MIDA_BLOCK(CodeBlock): 
    def __init__(self, id_ea=None, bb=None, fc=None):
        if id_ea != None:
            super(MIDA_BLOCK, self).__init__(id_ea, bb, fc)
        elif bb != None:
            super(MIDA_BLOCK, self).__init__(id_ea, bb, fc)
        elif fc != None:
            super(MIDA_BLOCK, self).__init__(id_ea, bb, fc)            
        else:
            breakx("Error defining MIDA_BLOCK. NO ARGS SUPPLIED.")
    
        self.start_ea = self.startEA
        self.end_ea = self.endEA
            
        #self.utils = ida_utils_inst            
        self.utils = lib_ida.ida_utils.MidaIdaUtils.GET_INSTANCE()
        # @MPD QUESTION self.succs already provided by idaapi.BasicBlock used by sark.CodeBlock
        # self.succs = []     
    
    ########## INSTANCE METHODS #############
    # add our own function instance methods here
    # ...
    
    
    ########## STATIC METHODS #############       
    @staticmethod
    # simplified version of sark.codeblocks
    # returns MIDA_BLOCK versions
    def get_blocks(start, end):
        start, end = fix_addresses(start, end)

        # todo! determine if this list is sorted!
        for code_block in FlowChart(bounds=(start, end)):
            yield MIDA_BLOCK(id_ea=code_block.startEA)
 
# @MPD TODO: convert this code to MIDA components inside of this file
# CONSIDER: change the name of this file to MIDA_COMPONENTS.py
#     # return the basic block at the specified address
#     def recover_block(self, start_ea):
#         b = self.MidaBlock(start_ea, start_ea)
#         cur_ea = start_ea
# 
#         while True:
#             insn_t, instr_bytes = self.decode_instr(cur_ea)
#             if insn_t is None:
#                 if idc.Byte(cur_ea) == 0xCC:
#                     b.end_ea = cur_ea + 1
#                     return b
#                 else:
#                     print("Couldn't decode instruction at: {0:x}.".format(cur_ea))
#                     b.end_ea = cur_ea
#                     return b
# 
#             # find ea of next inst
#             next_ea = cur_ea + insn_t.size
#             crefs = idautils.CodeRefsFrom(cur_ea, 1)
#             # get cur_ea 
#             follows = [cref for cref in crefs]
# 
#             if follows == [next_ea] or isCall(insn_t):
#                 # there is only one following branch, to the next instruction
#                 # check if this is a JMP 0; in that case, make a new block
#                 if isUnconditionalJump(insn_t):
#                     b.endEA = next_ea
#                 for f in follows:
#                     # do not decode external code refs
#                     if not isExternalReference(f):
#                         b.succs.append(f)
#                 return b
# 
#                 # check if we need to make a new block
#             elif len(follows) == 0: # this is a ret, no follows
#                 b.end_ea = next_ea
#                 return b
#             else: # this block has several follow blocks
#                 b.end_ea = next_ea
#                 for f in follows:   # do not decode external code refs
#                     if not isExternalReference(f):
#                         b.succs.append(f)
#                 return b
# 
#             # right now we know this block has one follows ...but does something else go there? We may need to split the block anyway
#             orefs = idautils.CodeRefsTo(nextEA, 0)
#             # who else calls us?
# 
#             orefs_list = [oref for oref in orefs]
#             if len(orefs_list) > 0:
#                 b.end_ea = next_ea
#                 b.succs.append(next_ea)
#                 return b
# 
#             # if its not JMP0 or call 0, add next instruction to current block
#             cur_ea = next_ea
#             # else continue with instruction
#     
#     def get_pos_change(self, funcBBsMap, ea_pos):
#         for bb_ea, bb in funcBBsMap.items():
#             bb_size =  bb.end_ea - bb.start_ea
#             if ea_pos >= bb_ea and  ea_pos < (bb_ea + bb_size):
#                 return bb.start_ea - bb_ea            
#     
#     def IsPrefixType(self, inst):        
#         return False
#     
#     def decode_instr(self, ea):
#     ###  Read the bytes of and handle  combining the bytes of an instruction with its prefix. 
#         inst = idautils.DecodeInstruction(ea)
#         if not inst:
#             return None, tuple()
# 
#         assert inst.ea == ea
#         end_ea = ea + inst.size
#         bytes = "".join(chr(idc.Byte(byte_ea)) for byte_ea in range(ea, end_ea))
# 
#         # If instruction has a prefix, IdaPro treats prefix as independent.
#         if (1 == inst.size and self.IsPrefixType(inst)):
#             inst, extra_bytes = self.decode_instr(end_ea)
#             dout("Extended instruction at {:08x} by {} bytes".format(ea, len(extra_bytes)))
#             bytes.extend(extra_bytes)
# 
#         return inst, bytes 
# 
#     def MidaBlock(self, start_ea):
#         to_recover = [start_ea]
# 
#         blocks = {}
# 
#         while len(to_recover) > 0:
#             # get new block start to recover
#             bstart = to_recover.pop()
#             # recover the block
#             newb = self.recover_block(bstart)
#             # save to our recovered block list
#             blocks[newb.start_ea] = newb            
#             for fba in newb.succs:
#                 if fba not in blocks:
#                     to_recover.append(fba)
# 
#         rv = []
#         for k in sorted(blocks.keys()):
#             rv.append(blocks[k])
#         vout(rv)
#         return rv    
#  
#          
#     def get_entry_points(self):
#         entrypoints = idautils.Entries()
#         exports = {}
#         for index,ordinal,exp_ea, exp_name in entrypoints:
#             exports[exp_name] = exp_ea
#         return exports
            
            
            
            
    
