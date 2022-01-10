# LittleXrefS
FInd what methods and instructions access and write an offset of a class in the libil2cpp binary.

to use this tool, you need a valid dump from the game using any dumper that gives you an json of the metadata.

it currently support just arm for now.

How to use:
*load libil2cpp.so and json of the dump
*Input the full class name and its sub namespaces
*Input the offset

Dependecies:
Capstone
