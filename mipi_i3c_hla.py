from typing import List, Optional

from saleae.analyzers import AnalyzerFrame, ChoicesSetting, HighLevelAnalyzer


CCC_NAMES = {
    0x00: "ENEC (Broadcast)",
    0x01: "DISEC (Broadcast)",
    0x02: "ENTAS0 (Broadcast)",
    0x03: "ENTAS1 (Broadcast)",
    0x04: "ENTAS2 (Broadcast)",
    0x05: "ENTAS3 (Broadcast)",
    0x06: "RSTDAA (Broadcast)",
    0x07: "ENTDAA (Broadcast)",
    0x08: "DEFSLVS (Broadcast)",
    0x09: "SETMWL (Broadcast)",
    0x0A: "SETMRL (Broadcast)",
    0x0B: "GETMWL (Broadcast)",
    0x0C: "GETMRL (Broadcast)",
    0x0D: "GETPID (Broadcast)",
    0x0E: "GETBCR (Broadcast)",
    0x0F: "GETDCR (Broadcast)",
    0x10: "GETSTATUS (Broadcast)",
    0x11: "GETACCMST (Broadcast)",
    0x12: "SETBRGTGT (Broadcast)",
    0x13: "GETMXDS (Broadcast)",
    0x14: "GETCAPS (Broadcast)",
    0x80: "ENEC (Direct)",
    0x81: "DISEC (Direct)",
    0x86: "SETDASA (Direct)",
    0x87: "SETNEWDA (Direct)",
    0x89: "SETMWL (Direct)",
    0x8A: "SETMRL (Direct)",
    0x8B: "GETMWL (Direct)",
    0x8C: "GETMRL (Direct)",
    0x8D: "GETPID (Direct)",
    0x8E: "GETBCR (Direct)",
    0x8F: "GETDCR (Direct)",
    0x90: "GETSTATUS (Direct)",
    0x91: "GETACCMST (Direct)",
    0x93: "GETMXDS (Direct)",
    0x94: "GETCAPS (Direct)",
}


class MipiI3cHla(HighLevelAnalyzer):
    """
    Saleae HLA for MIPI I3C SDR-like traffic.

    This decoder expects input from the built-in I2C analyzer and converts frame
    streams into transaction-level I3C summaries, with special handling for
    CCC transfers using the broadcast address 0x7E.
    """

    show_ack = ChoicesSetting(choices=("show", "hide"))

    result_types = {
        "private": {
            "format": "I3C {{data.dir}} {{data.addr}} {{data.payload}}{{data.ack_info}}"
        },
        "ccc": {
            "format": "{{data.kind}} CCC {{data.code}} {{data.name}} {{data.payload}}{{data.ack_info}}"
        },
        "warning": {"format": "{{data.message}}"},
    }

    def __init__(self):
        self._reset_transaction()

    def _reset_transaction(self) -> None:
        self.active_address: Optional[int] = None
        self.is_read = False
        self.address_ack = True
        self.data_bytes: List[int] = []
        self.data_acks: List[bool] = []
        self.start_time = None
        self.ccc_code: Optional[int] = None
        self.expecting_ccc_code = False

    @staticmethod
    def _format_byte_list(data: List[int]) -> str:
        if not data:
            return "[0B]"
        return "[{}B] {}".format(len(data), " ".join("{:02X}".format(b) for b in data))

    def _ack_suffix(self) -> str:
        if self.show_ack != "show":
            return ""

        nack_points = []
        if not self.address_ack:
            nack_points.append("ADDR_NACK")

        for idx, ack in enumerate(self.data_acks):
            if not ack:
                nack_points.append("D{}_NACK".format(idx))

        if not nack_points:
            return " ACK:all"

        return " ACK:" + ",".join(nack_points)

    def _emit_transaction(self, end_time):
        if self.active_address is None or self.start_time is None:
            return None

        ack_info = self._ack_suffix()

        if self.active_address == 0x7E:
            code_value = "--"
            name = "UNKNOWN"
            kind = "Broadcast"

            if self.ccc_code is not None:
                code_value = "0x{:02X}".format(self.ccc_code)
                name = CCC_NAMES.get(self.ccc_code, "UNKNOWN_CCC")
                kind = "Direct" if (self.ccc_code & 0x80) else "Broadcast"

            payload = self._format_byte_list(self.data_bytes)
            frame = AnalyzerFrame(
                "ccc",
                self.start_time,
                end_time,
                {
                    "kind": kind,
                    "code": code_value,
                    "name": name,
                    "payload": payload,
                    "ack_info": ack_info,
                },
            )
            self._reset_transaction()
            return frame

        direction = "R" if self.is_read else "W"
        payload = self._format_byte_list(self.data_bytes)
        frame = AnalyzerFrame(
            "private",
            self.start_time,
            end_time,
            {
                "dir": direction,
                "addr": "0x{:02X}".format(self.active_address),
                "payload": payload,
                "ack_info": ack_info,
            },
        )
        self._reset_transaction()
        return frame

    def _extract_byte(self, frame: AnalyzerFrame) -> Optional[int]:
        raw = frame.data.get("data")
        if raw is None:
            return None

        if isinstance(raw, bytes):
            if not raw:
                return None
            return int(raw[0])

        if isinstance(raw, int):
            return raw & 0xFF

        return None

    def decode(self, frame: AnalyzerFrame):
        if frame.type == "start":
            if self.start_time is None:
                self.start_time = frame.start_time
            return None

        if frame.type == "address":
            # Repeated START without STOP: close previous transfer first.
            pending = self._emit_transaction(frame.start_time)
            if pending is not None:
                self.start_time = frame.start_time
                self.active_address = int(frame.data.get("address", 0))
                self.is_read = bool(frame.data.get("read", False))
                self.address_ack = bool(frame.data.get("ack", True))
                self.expecting_ccc_code = self.active_address == 0x7E and not self.is_read
                self.ccc_code = None
                return pending

            if self.start_time is None:
                self.start_time = frame.start_time

            self.active_address = int(frame.data.get("address", 0))
            self.is_read = bool(frame.data.get("read", False))
            self.address_ack = bool(frame.data.get("ack", True))
            self.data_bytes = []
            self.data_acks = []
            self.ccc_code = None
            self.expecting_ccc_code = self.active_address == 0x7E and not self.is_read
            return None

        if frame.type == "data":
            value = self._extract_byte(frame)
            if value is None:
                return AnalyzerFrame(
                    "warning",
                    frame.start_time,
                    frame.end_time,
                    {"message": "Unrecognized data frame format from lower analyzer."},
                )

            ack = bool(frame.data.get("ack", True))

            if self.active_address == 0x7E and self.expecting_ccc_code:
                self.ccc_code = value
                self.expecting_ccc_code = False
            else:
                self.data_bytes.append(value)
                self.data_acks.append(ack)

            return None

        if frame.type == "stop":
            return self._emit_transaction(frame.end_time)

        return None
