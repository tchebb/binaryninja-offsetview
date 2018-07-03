import time

from binaryninja import PluginCommand, interaction
from binaryninja.binaryview import BinaryView, AnalysisCompletionEvent
from binaryninja.enums import SegmentFlag

ADDR_METADATA_KEY = 'loadataddr'


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

            length = len(self.parent_view)
            self.add_auto_segment(
                addr, length,
                0, length,
                (SegmentFlag.SegmentReadable |
                 SegmentFlag.SegmentWritable |
                 SegmentFlag.SegmentExecutable)
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

    addr = interaction.get_address_input("Base Address", "Base Address")
    if addr is not None:
        raw_data.store_metadata(ADDR_METADATA_KEY, int(addr))

PluginCommand.register(
    "Load at",
    "View this file with a given base address",
    load_at_offset
)
