from idaapi import *
from idc import *

# @MPD this script tries to get the names of stack variables in the stack frame for the current function 
# Then this script gets the offsets for each stack variable and then tries to return the value of the offset 
# for the specified stack variable


def main():
    return get_stack_arg("counter")


def get_stack_arg(arg, base='ebp'):
    # find the stack frame
    stack = GetFrame(here())
    size  = GetStrucSize(stack)

    # figure out all of the variable names
    try:
        adjusted = size - (size-GetMemberOffset(stack, 'var_s0'))
    except: 
        print "cannot find stack var var_s0"
    
    names = []
    for i in xrange(size):
        n = GetMemberName(stack, i)
        if n and not n in names:
            names.append(n)
            print n + " || offset: " + str(GetMemberOffset(stack,n)) + " || adjusted: " + str(adjusted - GetMemberOffset(stack,n))
    print "size of stack frame is " + str(size)
    print "top of script got names: " + str(names)
    return -1

    # The stack offsets can be negative
    # GetFrame and GetStrucSize are not
    #-0000000A var_A dw ?
    #+00000000  s db 4 dup(?) ; s is always at 0x0 
    #+00000004  r db 4 dup(?)
    #+00000008 arg_0 dd ?
    #+0000000C arg_4 dd
    # there has got too be a better way (hax)
    #if (' s' in names or 'var_s0' in names) and arg in names:
    #    if ' s' in names:
    #        adjusted = size - (size - GetMemberOffset(stack, ' s'))
    #    elif 'var_s0' in names:
    #        adjusted = size - (size - GetMemberOffset(stack, 'var_s0'))
    #
    #    offset = GetMemberOffset(stack, arg) - adjusted
    #    retval=offset
        #if base:
        #   
        #    retval = GetRegValue(base) + offset 

    #    print "return value for offset of " + str(arg) + " is " +str(retval)
    #    return retval


# @MPD this is a nice class for storing all of the relevant infos for working
# with stack frames within IDA
class MIDA_STACK_FRAME(object):
    # need to give address of the function whose stack frame this object represents
    def __init__(self, func_ea):
        self.pFunc = get_func(func_ea)
        self.pFrame = get_frame(pFunc)
        self.size  = GetStrucSize(pFrame)
        # store a dictionary of all of the stack vars, sorted by name
        self.mida_stack_vars = dict()


# @MPD this is a nice class for storing all of the relevant infos needed when working
# with stack variables in IDA
# note this is deisnged to be able to be used independently of the MIDA_STACK_FRAME above
class MIDA_STACK_VAR(object):
    def __init__(self, func_ea, var_name):
        self.pFunc = get_func(func_ea)
        self.pFrame = get_frame(pFunc)
        x = 0
        while(x < pFrame.memqty):
            if GetMemberName(pFrame.id, pFrame.get_member(x).soff) == var_name:
               self.pMember = pFrame.get_member(x)
               break; 
            x = x+1
        if pMember:
            self.xrefs = xreflist_t()
            # populate self.xrefs with all of the xrefs that ida can identify
            # hopefully not missing any but you can never be certain!
            build_stkvar_xrefs(self.xrefs, self.pFunc, self.pMember)
        else:
            raise Exception("cannot find stack variable with name " + var_name)


def get_stack_xrefs(func_ea, var_name):
    pFunc = get_func(func_ea)
    pFrame = get_frame(pFunc)
    pMember = None
    result = []
    while(x < pFrame.memqty):
        if GetMemberName(pFrame.id, pFrame.get_member(x).soff) == var_name:
           pMember = pFrame.get_member(x)
           break; 
        x = x+1
    if pMember: 
        xrefs = xreflist_t()
        build_stkvar_xrefs(xrefs, pFunc, pMember)
        for each in xrefs:
            result.append(each.ea)
    return result


# https://reverseengineering.stackexchange.com/questions/16055/idapython-get-xrefs-to-a-stack-variable
# There is one function that does this: build_stkvar_xrefs, defined in C++ but exposed via the Python SWIG bindings. IDA builds stack xrefs dynamically when you ask for it. In order to use the function, it requires a little bit of setup.

# You'll need to use a few functions to get what you need:

# get_func(ea): retrieves the func_t structure for the function at ea
# get_frame(func_t foo): returns the struct_t structure for the function frame specified by foo
# DecodeInstruction(ea): returns the inst_t representing instruction at ea
# get_stkvar(op_t op, sval_t v): op is a reference to an instruction, v is the immediate value in the operand. Usually you just use op.addr. It returns a tuple, (member_t, val). member_t is a pointer to the stack variable, which is what we need. val is the same value as the soff field in the member_t for the stack var. More on this later.
# xreflist_t(): creates a new xreflist of xreflist_entry_t
# build_stkvar_xrefs(xreflist_t xrefs, func_t func, member_t member): fills xrefs with xreflist_entry_t's that represent the stack var xrefs given by member in func.
# struct_t.get_member(x): You can use this method to iterate all stack variables in a frame to retrieve all member_t's. If you want to build xrefs for all stack variables, this is usually easier.
# Here's an example of how this all ties together:

# # 0x4012d0 is the function address
# # 0x4012dc is an instruction address referencing
# # a stack variable. It looks like:
# # mov [ebp - 4], ecx

# pFunc = get_func(0x4012d0)
# pFrame = get_frame(pFunc)
# inst = DecodeInstruction(0x4012dc)
# op = inst[0] #first operand references stack var
# pMember, val = get_stkvar(op, op.addr)
# xrefs = xreflist_t()
# build_stkvar_xrefs(xrefs, pFunc, pMember)
# for xref in xrefs:
#     print hex(xref.ea) #print xref address

# # Contrived member dictionary example.
# dictMem = dict()
# x = 0
# while(x < pFrame.memqty):
#     dictMem[GetMemberName(pFrame.id, pFrame.get_member(x).soff)] = pFrame.get_member(x)
#     x = x+1
# # given var name you can now use the
# # dictionary to grab the member_t to pass
# # to build_stkvar_xrefs
# pMem = dictMem["var_4"]
# xrefs = xreflist_t()
# build_stkvar_xrefs(xrefs, pFunc, pMem)
# for xref in xrefs:
#     print hex(xref.ea) #print xrefs to var_4
# soff isn't a stack offset. I think it means "structure offset", and it's an offset into the frame structure so you can retrieve other bits of information. You'll need this field to use other stack variable related functions such as: SetMemberType, SetMemberName, GetMemberName, DelStrucMember, etc.

# So, for a simple on the fly variable name to xref lookup, you can do something like:

# def get_stack_xrefs(func_ea, var_name):
#     pFunc = get_func(func_ea)
#     pFrame = get_frame(pFunc)
#     pMember = None
#     result = []
#     while(x < pFrame.memqty):
#         if GetMemberName(pFrame.id, pFrame.get_member(x).soff) == var_name:
#            pMember = pFrame.get_member(x)
#            break; 
#         x = x+1
#     if pMember: 
#         xrefs = xreflist_t()
#         build_stkvar_xrefs(xrefs, pFunc, pMember)
#         for each in xrefs:
#             result.append(each.ea)
#     return result
# If you want more information on these functions, I recommend taking a look at the following modules from the IDA SDK documentation (in no particular order):

# funcs.hpp
# frame.hpp
# struct.hpp
# Reference: https://www.hex-rays.com/products/ida/support/sdkdoc/files.html


if __name__ == "__main__":
    main()

