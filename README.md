# PE_Reader


This project is a foray into C++ for me. I cannot guarantee correctness. Use this at your own discretion.

# Usage

PE_Reader.exe C:\Full\Path\To\Executable.exe

# Notes
* Writes the .text section to a file
* Notes different PE Header data
* Uses Zydis for the disassembly (I hope to one day implement my own disassembler for this project)

# Dependencies
* Zydis (https://github.com/zyantific/zydis)