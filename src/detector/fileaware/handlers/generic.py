from ..types import FileContext, SuspiciousFileRegion, FileAwareDecision

class GenericHandler:
    def supports(self, ext, magic): return True
    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        return FileAwareDecision(keep_file=True, reason="generic: conservative keep")
