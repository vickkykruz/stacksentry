"""
StackSentry — Storage package.
 
Public API:
    from storage import ScanHistory, DriftEngine, DriftReport
 
The storage layer is local-first by design:
- All data lives in ~/.stacksentry/history.db
- Nothing leaves the machine without explicit user action
- Zero configuration required
"""
 
from storage.history import ScanHistory
from storage.drift import DriftEngine, DriftReport
 
__all__ = ["ScanHistory", "DriftEngine", "DriftReport"]