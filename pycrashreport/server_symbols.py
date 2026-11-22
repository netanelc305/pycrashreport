from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: The server's names of a thread's frame lists, by the report's
FRAME_KEYS = {"kernelFrames": "kernel_frames", "userFrames": "user_frames"}


@dataclass(frozen=True)
class ServerFrame:
    """What the server found for one frame: the path of its image and the function it is in."""

    image: Optional[str] = None
    symbol: Optional[str] = None
    offset: Optional[int] = None

    @classmethod
    def from_dict(cls, frame: Mapping[str, Any]) -> "ServerFrame":
        return cls(frame.get("image"), frame.get("symbol"), frame.get("offset"))


@dataclass
class ServerSymbols:
    """A report as a symbolicator server symbolicated it.

    The server drops the frames at address 0 (offset 0 into an absolute image) and keeps every other
    frame in the report's order, so its frames line up with the report's once those are dropped too.
    """

    #: Frames of each thread, by pid, tid and the report's name of the frame list
    threads: Dict[Tuple[int, int, str], List[ServerFrame]] = field(default_factory=dict)
    #: UUIDs of the report's images the server holds no symbols for
    missing_images: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, report: Mapping[str, Any]) -> "ServerSymbols":
        """Create from the server's JSON of a symbolicated report."""
        threads = {}
        for process in report.get("processes", []):
            for thread in process["threads"]:
                for key, server_key in FRAME_KEYS.items():
                    frames = [
                        ServerFrame.from_dict(frame) for frame in thread[server_key]
                    ]
                    threads[(process["pid"], thread["id"], key)] = frames
        return cls(threads, report.get("missing_images", []))

    def thread_frames(
        self, pid: int, tid: int, key: str, count: int
    ) -> List[ServerFrame]:
        """The server's frames of a thread, unnamed ones when it does not hold the same frames."""
        frames = self.threads.get((pid, tid, key), [])
        if len(frames) != count:
            return [ServerFrame()] * count
        return frames
