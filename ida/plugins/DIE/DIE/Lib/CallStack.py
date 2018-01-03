from DIE.Lib.DIE_Exceptions import DieCallStackPushError, DieCallStackPopError
from DIE.Lib.FunctionContext import *
import idautils
from collections import defaultdict

class CallStack():
    """
    DIE Call stack Implementation
    """

    def __init__(self):
        """
        Ctor
        """
        self.logger = logging.getLogger(__name__)

        self.callStack = []  # A basic dynamic call stack
        self.callTree = []   # A global function context list (e.g the entire CFG)

        self.function_list = list(idautils.Functions())

        # Function counter counts the number of time a specific function have been called (pushed to the call-stack)
        self.function_counter = defaultdict(int)

    def push(self, ea, iatEA=None, library_name=None, calling_ea=None):
        """
        Push a function into the callsatck and get call context
        @param ea: The function start address
        @param iatEA: If the function is imported, the address of the function IAT entry.
        @param library_name: Name of containing library (for library functions)
        @param: calling_ea: The calling function ea
        @return: Total number of occurrences of this function in the call-stack, or -1 on failure
        """
        try:
            is_new_func = self.check_if_new_func(ea, iatEA)

            # Get calling function context
            parent_func_context = None
            if self.callStack:
                parent_func_context = self.callStack[-1][1]

            funcContext = FunctionContext(ea,
                                          iatEA,
                                          is_new_func, library_name=library_name,
                                          parent_func_context=parent_func_context,
                                          calling_ea=calling_ea)

            # Add function context to the global function_context list
            callTree_Indx = len(self.callTree)
            self.callTree.append(funcContext)

            # Add flink for this function in parent function context
            if parent_func_context:
                parent_func_context.child_func_context.append(funcContext)

            if funcContext.empty:
                self.logger.debug("Could not generate function context for ea: %s", hex(ea))
                callStackTup = (callTree_Indx, funcContext)
                self.callStack.append(callStackTup)
                return -1

            self.count_function(funcContext.function.funcName)
            funcContext.get_arg_values_call()

            # Each callstack element is a tuple containing the index into the calltree, and the function context object.
            callStackTup = (callTree_Indx, funcContext)
            self.callStack.append(callStackTup)

            return self.function_counter[funcContext.function.funcName]

        except Exception as ex:
            self.logger.exception("Error while pushing function at address %s to callstack", hex(ea))
            raise DieCallStackPushError(ea)

    def pop(self):
        """
        Pop the top most function from the callstack and get return context
        @rtype : Returns True if function was succesfully poped from callstack. otherwise False
        """
        try:
            if not self.callStack:
                # Error: cannot pop value from empty callstack
                return

            (callTree_Indx, funcContext) = self.callStack.pop()

            if funcContext is None:
                self.logger.error("Error while poping function from callstack, "
                                  "no function context available for this function")
                return False

            funcContext.get_arg_values_ret()  # Update the call-tree context
            #self.callTree.append(funcContext)
            return True

        except Exception as ex:
           raise DieCallStackPopError("Error while poping function from callstack")

    def check_if_new_func(self, ea, iatEA):
        """
        Check if this function was created at runtime (or unknown in static analysis).
        @param ea: effective address of function
        @return: True if this function was part of the function list initialized at program start time.
        """
        # if iatEA has a value, this is probably a library function.
        if iatEA is not None:
            return False

        # Check if function in original function_list
        if ea in self.function_list:
            return False

        # This must be a new function!
        return True

    def count_function(self, func_name):
        """
        Add function to function counter
        @param func_name: Function Name
        @return: True if added sucessfully, otherwise False
        """
        try:
            self.function_counter[func_name] += 1
            return True

        except Exception as ex:
            self.logger.exception("Failed while add function %s to function counter: %s", func_name, ex)
            return False

    def get_top_func_data(self):
        """
        Get the topmost call-stack item function name.
        @return: Returns a tuple of (Function Adress, Function Name) for the topmost function. returns None on failure.
        """
        try:
            func_ea = None
            func_name = None

            if self.callStack is not None:
                (callTree_Indx, funcContext) = self.callStack[-1]
                if not funcContext.empty:
                    func_name = funcContext.function.funcName
                    func_ea = funcContext.function.ea

                return (func_ea, func_name)

            return None

        except Exception as ex:
            self.logger.exception("Error while retrieving function data for top-of-call-stack item:", ex)
            return None






