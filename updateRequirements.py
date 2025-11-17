# -*- coding: utf-8 -*-
import shlex,  subprocess



print("Updating requirements.txt..")
# TODO: correct Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
#       Severity: Low   Confidence: High
# Note: with shell=True it's even worse, we get then:
#       Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
#       Severity: High   Confidence: High
#########################################
p1 = subprocess.Popen(shlex.split("pipreqs --force ./ --ignore backups --mode compat"), shell=False) # shell=True)
p1.wait()
p1.terminate()
p1.kill()



                
