import logging
logging.basicConfig(level=logging.DEBUG)

PERCENT_THRESHOLD = 25.0


def arithmetic_heuristic(f):
    asm_weights = {"div":4, "idiv":4, "mul":4, "imul":4, "add":1, "sub":2}

    # How heavily floating-point values should be weighted
    FLOAT_WEIGHT = 5

    # Keep track of the number of each instruction encountered for debugging
    # purposes; this is done dynamically so only the list above needs to be
    # changed when adding new instructions
    ins_count = dict()
    for key, value in asm_weights.items():
        ins_count[key] = 0
    
    ins_count["float"] = 0 # Additional entry for floating-point values
    
    total = 0

    for line in f:
        op = line.split(' ')[0] # Get operation of current instruction
        if op in asm_weights:
            ins_count[op] += 1
            total += asm_weights[op]
        elif op[0] == 'f':
            ins_count["float"] += 1
            total += FLOAT_WEIGHT

    logging.debug("arithmetic_heuristic() counted: " + str(ins_count))

    return total


# Calculates a threshold for how large a number the sum of arithmetic instructions must be in order
# for the function to be considered heavily using arithmetic instructions. This number is based off 
# of the length of the function. 
def calc_percent_threshold(size):
    return (PERCENT_THRESHOLD/100.0)*float(size)