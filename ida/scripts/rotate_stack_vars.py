from idaapi import *
from idc import *

# @MPD this script tries to get the names of stack variables in the stack frame for the current function 
# Then this script gets the offsets for each stack variable and then tries to return the value of the offset 
# for the specified stack variable


def main():
    #  return print_stack_args("counter")
    # Create an object to store every piece of information
    # about the stack frame for the current function
    # and all of its variables and print most of it to the output window
    mida_frame = MIDA_STACK_FRAME(here())
    print "initial stack frame for function @ " + hex(here())
    print mida_frame
    mida_frame.calculate_var_rotation()
    mida_frame.translate_rotation_offsets()
    print "theoretical stack frame after proposed stack var rotation for function @ " + hex(here())
    print mida_frame


# get the offset of the stack variable that is at 0 relative address offset 
def get_stack_frame_base(func_ea):
    stack = GetFrame(here())
    size  = GetStrucSize(stack)

    names = []
    for i in xrange(size):
        n = GetMemberName(stack, i)
        if n and not n in names:
            names.append(n)

    # ' s' is the name that IDA assigns to the var at the offset 0 of the stack fram for x86
    if ' s' in names:
        frame_base = size - (size - GetMemberOffset(stack, ' s'))
    # ' s' is the name that IDA assigns to the var at the offset 0 of the stack fram for x86
    elif 'var_s0' in names:
        frame_base = size - (size - GetMemberOffset(stack, 'var_s0'))
    else:
        print "cannot find stack var at stack frame offset 0 ' s' or 'var_s0'"
        raise Exception("error finding stack frame base for func @ addr " + hex(func_ea))

    return frame_base



# @MPD this is a nice class for storing all of the relevant infos for working
# with stack frames within IDA
class MIDA_STACK_FRAME(object):
    # need to give address of the function whose stack frame this object represents
    def __init__(self, func_ea):
        self.func_ea = func_ea
        self.pFunc = get_func(func_ea)
        self.stack = GetFrame(func_ea)
        self.size  = GetStrucSize(self.stack)
        # store a dictionary of all of the stack vars, sorted by name
        self.frame_base = get_stack_frame_base(func_ea)
        self.mida_stack_vars = dict()
        names = []
        for i in xrange(self.size):
            n = GetMemberName(self.stack, i)
            if n and not n in names:
                names.append(n)
                self.mida_stack_vars[n] = MIDA_STACK_VAR(func_ea, n)

    def __str__(self):
        retstring = 'STACK FRAME FOR FUNC @ ' + hex(self.func_ea) + "\n"
        for varname, var in self.mida_stack_vars.iteritems():
            retstring = retstring + str(var)
        retstring = retstring + '\n'
        return retstring

    # a function that calculates new stack and frame offsets
    # for each stack frame variable
    # does not update the actual binary, but populates each
    # MIDA_STACK_VAR object with rot_ parameters that may be used to
    # perform a real translation

    # { -- vard -- varc - varb vara - s r } changes to ->
    # { -- varc - varb vara - vard -- s r }

    def calculate_var_rotation(self):
        var_stack_offsets = []
        for name, var in self.mida_stack_vars.iteritems():
            var_stack_offsets.append(var.stack_offset)
        # first, find the 'first' regular stack variable
        lowest_stack_offset = 0
        lowest_stack_var = None
        for name, var in self.mida_stack_vars.iteritems():
            if var.stack_offset < lowest_stack_offset:
                # note that the lowest stack offset will be negative
                lowest_stack_offset = var.stack_offset
                lowest_stack_var = var
        if lowest_stack_var is None:
            print "Function has no regular stack vars"
            return -1
        # now we have the 'lowest_offset'
        second_lowest_stack_offset = 0 
        for name, var in self.mida_stack_vars.iteritems():
            # don't look at the lowest stack offset
            if var.stack_offset != lowest_stack_offset:
                if var.stack_offset < second_lowest_stack_offset:
                    second_lowest_stack_offset = var.stack_offset
        # now we have the second lowest stack offset
        # the rotation is equal to the byte difference between these two
        rotation_in_bytes = second_lowest_stack_offset - lowest_stack_offset
        for name, var in self.mida_stack_vars.iteritems():
            # go through each stack var and update its stack offset
            # NOTE: only go through the 'regular' vars for which
            # their stack offset is negative
            # also, do not update the lowest stack var until last
            # because that one needs to be treated separately
            if (var.stack_offset < 0) and (var.stack_offset != lowest_stack_offset):
                var.rot_frame_offset = var.frame_offset - rotation_in_bytes
                var.rot_stack_offset = var.stack_offset - rotation_in_bytes
        # now that we have rotated the other stack vars, rotate the lowest stack var
        # so that it begins 'after' the others
        lowest_stack_var.rot_frame_offset = self.frame_base - rotation_in_bytes
        lowest_stack_var.rot_stack_offset = (-1)*rotation_in_bytes

        return 0

    # goal of this function is to translate actual addresses of the stack vars
    # using the precalculated addresses from calculate_var_rotation
    def translate_rotation_offsets(self):
        for name, var in self.mida_stack_vars.iteritems():
            if var.rot_frame_offset is not None:
                var.frame_offset = var.rot_frame_offset
            if var.rot_stack_offset is not None:
                var.stack_offset = var.rot_stack_offset
        return

# @MPD this is a nice class for storing all of the relevant infos needed when working
# with stack variables in IDA
# note this is deisnged to be able to be used independently of the MIDA_STACK_FRAME above
class MIDA_STACK_VAR(object):
    def __init__(self, func_ea, var_name):
        #  print "looking up stack var " + str(var_name)
        self.rot_frame_offset = None # this rotated frame offset used later for scrambling stack
        self.rot_stack_offset = None # this rotated stack offset used later for scrambling stack
        self.func_ea = func_ea
        self.name = var_name
        self.pFunc = get_func(func_ea)
        self.pFrame = get_frame(self.pFunc)
        # not super efficient to recalculat ethe stack base for every var,
        # but it is my attempt at presenting a simple API
        frame_base = get_stack_frame_base(func_ea)
        # offset from the 'start' of the ida stack frame for this var
        self.frame_offset =  GetMemberOffset(self.pFrame.id,var_name)
        # offset from the top of the stack for this var
        #  self.stack_offset = frame_base - self.frame_offset
        # the frame base is always bigger than the location of the "regular" stack vars
        # the stack vars are therefore located at negative locations relative to the 
        # frame base
        self.stack_offset = self.frame_offset - frame_base  
        self.xrefsto = []
        x = 0
        while(x < self.pFrame.memqty):
            #  print GetMemberName(self.pFrame.id, self.pFrame.get_member(x).soff)
            if GetMemberName(self.pFrame.id, self.pFrame.get_member(x).soff) == var_name:
               self.pMember = self.pFrame.get_member(x)
               break; 
            x = x+1
        if self.pMember:
            self.xrefs = xreflist_t()
            # populate self.xrefs with all of the xrefs that ida can identify
            # hopefully not missing any but you can never be sure
            # there has got to be a better way (hax)
            build_stkvar_xrefs(self.xrefs, self.pFunc, self.pMember)
            for each in self.xrefs:
                self.xrefsto.append(each.ea)
        else:
            raise Exception("cannot find stack variable with name " + var_name)
        
    def __str__(self):
        xrefstring = ''
        for ref in self.xrefsto:
            xrefstring = xrefstring + hex(ref) + ' | '
        retstring = self.name + " || frame offset: " + hex(self.frame_offset) + " || stack offset: " + hex(self.stack_offset) + ' {{xrefsto: ' + xrefstring + ' }} \n' 
        return retstring



# reference function from stackexchange.com
#  def get_stack_xrefs(func_ea, var_name):
#      pFunc = get_func(func_ea)
#      pFrame = get_frame(pFunc)
#      pMember = None
#      result = []
#      while(x < pFrame.memqty):
#          if GetMemberName(pFrame.id, pFrame.get_member(x).soff) == var_name:
#             pMember = pFrame.get_member(x)
#             break;
#          x = x+1
#      if pMember:
#          xrefs = xreflist_t()
#          build_stkvar_xrefs(xrefs, pFunc, pMember)
#          for each in xrefs:
#              result.append(each.ea)
#      return result


# more reference function content (this one from github.com)
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



if __name__ == "__main__":
    main()







