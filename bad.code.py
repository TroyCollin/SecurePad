import os, sys # ❌ Bad: Multiple imports on one line
from math import * # ❌ Bad: Wildcard import (pollutes the namespace)

def Do_Stuff(X,y): # ❌ Bad: Wrong naming style (should be snake_case: do_stuff)
  # ❌ Bad: Poor indentation (uses 2 spaces instead of standard 4)
  # ❌ Bad: No docstring explaining what this function does
  Z = X+y # ❌ Bad: Missing spaces around operators
  print("result is", Z)
  return Z

def main():
    # ❌ Bad: Highly descriptive but terrible variable names
    unUsedVariable = 10 # ❌ Bad: camelCase (not Pythonic) and completely unused
    
    a = input("Enter password: ") # ❌ Bad: Storing secrets in plain text variables
    
    if a=="secret":
        # ❌ Bad: Running a system command directly from user input (Security Risk!)
        os.system("echo " + a) 
    else:
        pass # ❌ Bad: Useless empty block

    # ❌ Bad: Deeply nested code block that is hard to read
    if True:
        if True:
            if True:
                print("Too deep!")

main()

