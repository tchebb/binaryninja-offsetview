import time

from binaryninja import PluginCommand, interaction
from binaryninja.binaryview import BinaryView, AnalysisCompletionEvent
from binaryninja.enums import SegmentFlag

ADDR_METADATA_KEY = 'loadataddr'
FLAGS_METADATA_KEY = 'loadatflags'

FLAG_OPTIONS = ["R", "RX", "RW", "RWX"]
FLAG_MAP = {
    'R': SegmentFlag.SegmentReadable,
    'W': SegmentFlag.SegmentWritable,
    'X': SegmentFlag.SegmentExecutable,
}

class OffsetView(BinaryView):
    name = "OffsetView"
    long_name = "Raw (with custom base address)"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)

    def init(self):
        def do_reloc(_evt):
            addr = self.parent_view.query_metadata(ADDR_METADATA_KEY)
            try:
                flags = self.parent_view.query_metadata(FLAGS_METADATA_KEY)
            except KeyError:
                # Database from old version of plugin
                flags = (
                    SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentWritable |
                    SegmentFlag.SegmentExecutable
                )

            length = len(self.parent_view)
            self.add_auto_segment(
                addr, length,
                0, length,
                flags
            )

        # In Binary Ninja 1.1.1338-dev, the segment creation needs to happen in
        # an AnalysisCompletionEvent callback because otherwise querying the
        # address from metadata fails when a relocated bndb is loaded. On
        # version 2.1.2263, however, it's the opposite: the callback now runs
        # after functions have been added and so we get a "not backed by file"
        # error when the core tries to add function. The metadata now seems to
        # reliably load directly from init(), though. So we have this ugly
        # check to see which behavior we need.
        try:
            self.parent_view.query_metadata(ADDR_METADATA_KEY)
        except KeyError:
            print(
                "Could not load OffsetView address during init(); "
                "this probably means you have an old version of Binary Ninja. "
                "Deferring load to after analysis complete."
            )
            self.parent_view.add_analysis_completion_event(do_reloc)
            self.parent_view.update_analysis()
        else:
            do_reloc(None)

        return True

    @classmethod
    def is_valid_for_data(cls, data):
        try:
            data.query_metadata(ADDR_METADATA_KEY)
        except KeyError:
            return False
        else:
            return True

OffsetView.register()


def load_at_offset(data):
    raw_data = data.file.raw

    addr_f = interaction.AddressField("Base Address")
    flags_str_f = interaction.ChoiceField(
        "Flags",
        FLAG_OPTIONS,
    )

    res = interaction.get_form_input(
        [addr_f, flags_str_f],
        "Load Parameters"
    )

    if not res:
        return

    flags = 0
    for flag in FLAG_OPTIONS[flags_str_f.result]:
        flags = flags | FLAG_MAP[flag]

    raw_data.store_metadata(ADDR_METADATA_KEY, int(addr_f.result))
    raw_data.store_metadata(FLAGS_METADATA_KEY, flags)

PluginCommand.register(
    "Load at",
    "View this file with a given base address",
    load_at_offset
)
