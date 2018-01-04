from idaapi import *
import re
import logging
idaapi.require("arithmetic_heuristics") # Because normal imports don't reload in IDA when the script is reloaded
idaapi.require("procinfo_heuristics")

logging.basicConfig(level=logging.DEBUG)


def analyze_all_functions():
    funcs = Functions()
    for f in funcs:
        analyze_function(f)


def analyze_function(f):
    f_entry = f
    f_exit = FindFuncEnd(f_entry)
    disasm_ins = list() # List of instructions as strings
    disasm_addr = list() # List of instructions as addresses


    heuristic_vals = {"_arith": 0, "_crypto": 0, "_strmanip": 0}

    f_new_name = Name(f) # New name for the subroutine; the address is preserved but the prefix is shortened
    if "sub_" in f_new_name:
        f_new_name = f_new_name.replace("sub_", "s_")
    

   # iterate through each assembly instruction in the function
    for (startea, endea) in Chunks(f_entry):
        for head in Heads(startea, endea):
            disasm_ins.append(re.sub("\s+"," ", GetDisasm(head))) #Compress excess whitespace
            disasm_addr.append(head)

    
    heuristic_vals["_arith"] = arithmetic_heuristics.arithmetic_heuristic(disasm_ins)

    if heuristic_vals["_arith"] >= arithmetic_heuristics.calc_percent_threshold(len(disasm_ins)):
        f_new_name = f_new_name + "_arith"

    logging.debug("Threshold is " + str(arithmetic_heuristics.calc_percent_threshold(len(disasm_ins))))

    anti_vm = (procinfo_heuristics.procinfo_heuristic(disasm_ins, disasm_addr))
    if anti_vm is True:
        f_new_name = f_new_name + "_PEB"

    logging.debug("arithmetic heuristic returned " + str(heuristic_vals["_arith"]))
    logging.debug("procinfo heuristic returned " + str(anti_vm))


    #AP added 12/12/17
    found = ""
    final = "_"
    for line in disasm_ins:
        found = identify_key_things(line)
        if "internet" in found or "url" in found:
            final = found + "_"
            break
        elif "crypt" in found:
            final = "crypt" + "_"
            break
        elif "dll" in found:
            final = "dll" + "_"
            break
        elif found not in final:
            final = final + "_" + found
            
    f_new_name = f_new_name + final
    #End AP added 12/12/17   
        
    renameFunction(f, f_new_name)

    logging.debug("Old name is: " + Name(f) + " , New name is: " + f_new_name)


def renameFunction(f, new_name): 
    if not f is None:
        if not MakeNameEx(f, new_name, 0): # Since func returned by get_func isn't an address, startEA is used so name functions print
            Warning("Could not change name.")
    else:
        Warning("No function found at location %x" % f)

#AP
def identify_key_things(line):
        found = ""
        #AP fixed xor 12/12/17
    
        if "URLDownloadToFile" in line:
            found = found + "internet_download"
            
        if "InternetReadFile" in line:
            found = found + "read_from_internet"
            
        if "InternetOpenUrl" in line or  "FtpOpenFile" in line or "HttpOpenRequest" in line:
            found = found + "connect2internet"
    
        if "http://" in line:
            found = found + "url"
            
        if "xor" in line:
            for s in line.split():
                 if not re.findall(r'0x[0-9A-F]+', line, re.I):
                    found = found + "crypt"
            
        if "rand" in line:
            found = found + "rand"
            
        if "ticks" in line:
            found = found + "ticks"
            
            
        #AP added 12/12/17
        if "int 0x80" in line or "syscall" in line or "sysenter" in line:
            found = found + "syscall"
            
        if "Win" in line or "win" in line or "WIN" in line:
            found = found + "windows"
            
        if "dll" in line:
            found = found + "dll"
            
        #End AP added 12/12/17  
        return found

