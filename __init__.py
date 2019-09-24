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
        def analysis_complete(evt):
            # We need to do this in a callback since the parent view's
            # metadata isn't always accessible during init().
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

        self.parent_view.add_analysis_completion_event(analysis_complete)
        self.parent_view.update_analysis()

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
