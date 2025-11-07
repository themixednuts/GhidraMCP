# -*- coding: utf-8 -*-
# Launcher script for Java-based test runner
# @category Testing

import sys
import os
from java.io import File

# Find and add the test JAR to the classpath
# Try multiple environment variables
ghidra_home = os.environ.get('GHIDRA_HOME') or os.environ.get('GHIDRA_INSTALL_DIR')

# If not found, try to derive from common paths
if not ghidra_home:
    import glob
    home = os.path.expanduser('~')
    candidates = glob.glob(os.path.join(home, 'ghidra_*_PUBLIC'))
    if candidates:
        ghidra_home = candidates[0]

if ghidra_home:
    extension_lib = os.path.join(ghidra_home, 'Ghidra', 'Extensions', 'GhidraMCP', 'lib')
    print("[DEBUG] Looking for test JAR in: " + extension_lib)
    
    if os.path.exists(extension_lib):
        # Find the test JAR (matches *-tests.jar pattern)
        for filename in os.listdir(extension_lib):
            if filename.endswith('-tests.jar'):
                test_jar = os.path.join(extension_lib, filename)
                print("[INFO] Adding test JAR to classpath: " + test_jar)
                sys.path.append(test_jar)
                break
        else:
            print("[WARN] Test JAR not found in: " + extension_lib)
            print("[WARN] Available files: " + str(os.listdir(extension_lib)))
    else:
        print("[WARN] Extension lib directory not found: " + extension_lib)
else:
    print("[WARN] Could not determine Ghidra home directory")

# Now import and run
from com.themixednuts.headless import TestRunner

# Create the test runner
runner = TestRunner()

# Run the tests, passing this script's context
# This script is a proper GhidraScript with all fields initialized
runner.run(this, currentProgram, state.getTool())
