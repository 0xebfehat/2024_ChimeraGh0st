# Ghosts from the past: Become Gh0stbusters in 2024
Here is Indicators and python scripts I wrote during our research on Gh0st RAT variatns.

You can check our research at [Virus Bulletin 2024 website.](https://www.virusbulletin.com/conference/vb2024/abstracts/ghosts-past-become-gh0stbusters-2024/)

- ioc.csv
  - Indicators of Gh0st RAT variants of the research
- decrypt-sl.py
  - Python script to decrypt Stage 3 shellcode of GhimeraGh0st infection chain
- decrypt-dat.py
  - Python script to decrypt encrypted ChimeraGh0st file
- decrypt-string,py
  - Python script to decrypt the configuration and strings in the ChimeraGhost
- idapython-flow-fixer.py (Confirmed on IDA 8.3)
  - IDAPython script to deobfuscate jcc control flow of ChimeraGh0st, BlackDLL.
  - This script is for IDA Debugger
  - Usage: Set the breakpoint at the function in which jcc obfuscation starts, and run this script. 

