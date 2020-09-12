**NOTE**: As of [Binary Ninja 1.2.1904][1] (released 2019-10-01), rebasing is
built in via the "Open with Options" dialog and the `Mapped` BinaryView type.
You should only use this plugin if your version of BN is older than that or if
you have existing analysis databases that were created using this plugin. (As I
understand it, it is not easy to migrate analysis data between two different
BinaryView types; I don't have the expertise to write a tool that migrates from
an existing `OffsetView` to a `Mapped`.)

[1]: https://binary.ninja/changelog/#1-2-1904

Binary Ninja `BinaryView` to display a binary file with a nonzero base address.

Open a file of machine code for analysis in a `BinaryView` that has a given base
address. This allows pieces of code such as bootloaders and ROMs to be analyzed
correctly without writing a custom view.
