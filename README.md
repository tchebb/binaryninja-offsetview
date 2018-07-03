Binary Ninja `BinaryView` to display a binary file with a nonzero base address.

Open a file of machine code for analysis in a `BinaryView` that has a given base
address. This allows pieces of code such as bootloaders and ROMs to be analyzed
correctly without writing a custom view.
