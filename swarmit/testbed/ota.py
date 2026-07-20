"""Block-OTA transfer state machine.

This replaced a per-chunk stop-and-wait that broadcast one chunk, waited for
every bot to ack it, then moved on - a round trip per chunk, with the link idle
in between. Instead:

1. Broadcast a whole block of chunks (``block_size`` of them) with no per-chunk
   ack.
2. Broadcast one report request; each bot replies with a bitmap of the chunks it
   received and SHA-verified for that block.
3. Re-broadcast only the union of still-missing chunks, back off, repeat.
4. Advance to the next block once every tracked bot reports the whole block.
5. After the last block, verify each bot's whole-image SHA256 (FINALIZE).

The class is deliberately transport- and clock-injected so it can be unit
tested with a fake transport and zero real time: ``send_payload``, ``clock`` and
``sleep`` are all parameters. ``on_report`` / ``on_finalize_resp`` are fed from
the controller's RX thread (or a test), guarded by a lock.

Nothing here knows what radio it is running on. How fast chunks may be
injected and how long a report window needs to be are properties of the link,
so they arrive as a :class:`BlockOTASettings` derived by the adapter.

Reference: BLE Mesh DFU BLOB Transfer (Push mode) for the block/bitmap shape,
RFC 9177 (CoAP Q-Block) for burst pacing and exponential backoff. Design and
rationale live in ``plans/swarmit-fast-ota/plan.html``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

from dotbot_utils.protocol import Payload

from swarmit.testbed.protocol import (
    BROADCAST_ADDRESS,
    PayloadOTABlockReportReq,
    PayloadOTAChunk,
    PayloadOTAFinalize,
)

# W = 32 is the largest block the uint32 report bitmap holds without a wire
# change; a larger block means fewer report rounds (less per-block overhead).
BLOCK_SIZE_DEFAULT = 32
# How long to collect block reports after a round's sends. Derived from the
# link geometry by the adapter; this default only applies when a settings
# object is built by hand (tests).
REPORT_TIMEOUT_DEFAULT = 0.25
# Delay between chunk sends, which is what paces the transfer: chunks are
# injected at the rate the downlink can carry them, so the gateway's shared TX
# queue stays shallow instead of being blasted a block at a time. Also derived
# from the link geometry.
INTER_CHUNK_DELAY_DEFAULT = 0.02
# A bot that misses this many consecutive report rounds becomes a straggler.
# Sized against ~90% uplink PDR: P(4 lost reports) = 0.01% per bot-block.
SILENT_STRAGGLER_ROUNDS_DEFAULT = 4
# A bot whose own missing set stops shrinking for this many rounds is stuck.
STALL_STRAGGLER_ROUNDS_DEFAULT = 3
# Bounded unicast recovery rounds for a straggler before FINALIZE.
STRAGGLER_MAX_ROUNDS_DEFAULT = 4
# Whole-image verification attempts.
FINALIZE_MAX_ROUNDS_DEFAULT = 4
# Hard per-block safety net so a logic bug can never spin forever.
MAX_ROUNDS_PER_BLOCK_DEFAULT = 32


def popcount(value: int) -> int:
    """Number of set bits."""
    return bin(value).count("1")


@dataclass
class BlockOTASettings:
    """Tunables for the block-OTA state machine.

    ``block_size``, ``inter_chunk_delay`` and ``report_timeout`` normally come
    from ``adapter.derive_block_settings``, which sizes them against the link
    the gateway reports. The straggler and round limits below are protocol
    policy and are the same on any link; per the workspace rules they need
    >=200-node validation before being called tuned.
    """

    block_size: int = BLOCK_SIZE_DEFAULT
    report_timeout: float = REPORT_TIMEOUT_DEFAULT
    inter_chunk_delay: float = INTER_CHUNK_DELAY_DEFAULT
    silent_straggler_rounds: int = SILENT_STRAGGLER_ROUNDS_DEFAULT
    stall_straggler_rounds: int = STALL_STRAGGLER_ROUNDS_DEFAULT
    straggler_max_rounds: int = STRAGGLER_MAX_ROUNDS_DEFAULT
    finalize_max_rounds: int = FINALIZE_MAX_ROUNDS_DEFAULT
    max_rounds_per_block: int = MAX_ROUNDS_PER_BLOCK_DEFAULT


class ChunkLike(Protocol):
    """Minimal shape the transfer needs from a chunk (controller.DataChunk)."""

    index: int
    size: int
    sha: bytes
    data: bytes


@dataclass
class DeviceResult:
    """Per-device outcome of a block-OTA transfer."""

    confirmed_chunks: int = 0
    total_chunks: int = 0
    straggler: bool = False
    finalized: bool = False

    @property
    def success(self) -> bool:
        # The whole-image finalize SHA256 is authoritative: if the device says
        # it matches, every byte is correctly in flash - regardless of what the
        # delivery bitmap tracked. Under heavy loss/retransmit the bitmap can
        # under-count (a report is lost, or the device's per-block mask is
        # overwritten as it advances) while the image is in fact complete;
        # gating success on confirmed==total then fails a perfectly good flash.
        return self.finalized


class BlockTransfer:
    """Drive one block-OTA image transfer to a set of devices.

    Parameters
    ----------
    chunks:
        ordered chunks of the image (objects with ``index/size/sha/data``).
    devices:
        device address strings (hex, as the controller formats them).
    send_payload:
        ``send_payload(destination:int, payload)`` - the transport.
    image_sha:
        32-byte SHA256 of the whole image, sent in FINALIZE.
    settings:
        :class:`BlockOTASettings`.
    broadcast:
        send chunks/report-reqs to the broadcast address (the common case) vs
        per-device unicast.
    sleep:
        injected delay, so tests run without real time.
    on_progress:
        optional ``on_progress(addr, chunk_index)`` fired as chunks are
        confirmed; the controller uses it to drive its progress bar.
    """

    def __init__(
        self,
        chunks: list[ChunkLike],
        devices: Iterable[str],
        send_payload: Callable[[int, Payload], None],
        image_sha: bytes,
        settings: BlockOTASettings | None = None,
        broadcast: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        on_progress: Callable[[str, int], None] | None = None,
        logger=None,
        drop_chunks: Iterable[int] | None = None,
    ):
        self.chunks = list(chunks)
        self.devices = list(devices)
        self._send_payload = send_payload
        self.image_sha = bytes(image_sha)
        self.settings = settings or BlockOTASettings()
        self.broadcast = broadcast
        self._sleep = sleep
        # Test hook: chunk indices to never transmit, simulating permanent loss
        # (proves the finalize SHA catches a genuinely incomplete image).
        self._drop_chunks = set(drop_chunks or ())
        self._on_progress = on_progress
        self._logger = logger

        self._w = self.settings.block_size
        self.num_blocks = (len(self.chunks) + self._w - 1) // self._w

        self._lock = threading.Lock()
        # Reports collected during the current round: addr -> (block, mask).
        self._round_reports: dict[str, tuple[int, int]] = {}
        # Finalize responses: addr -> ok(bool).
        self._finalize_inbox: dict[str, bool] = {}

        # Persistent per-(device, block) confirmed bitmap.
        self._confirmed: dict[tuple[str, int], int] = {}
        # Total chunk frames put on the wire (incl. retransmits). Compared with
        # the delivered count it exposes wasted downlink (churn).
        self._chunk_sends = 0
        # Straggler set (reversible: a bot rejoins when it reports again).
        self._straggler: set[str] = set()
        # Blocks each device never fully confirmed (for the unicast pass).
        self._incomplete: dict[str, set[int]] = {addr: set() for addr in self.devices}

        # Transient per-block counters, reset in _reset_block_state.
        self._silent: dict[str, int] = {}
        self._stall: dict[str, int] = {}
        self._last_missing: dict[str, int | None] = {}
        # Devices that have sent at least one report for the current block.
        self._reported: set[str] = set()
        self._round = 0

    # ------------------------------------------------------------------ #
    # Pure helpers (no I/O) - the unit-test surface.
    # ------------------------------------------------------------------ #
    def block_chunk_indices(self, block: int) -> range:
        """Absolute chunk indices belonging to ``block``."""
        start = block * self._w
        end = min(start + self._w, len(self.chunks))
        return range(start, end)

    def full_block_mask(self, block: int) -> int:
        """Bitmask with one bit per chunk present in ``block``."""
        return (1 << len(self.block_chunk_indices(block))) - 1

    def confirmed_mask(self, addr: str, block: int) -> int:
        return self._confirmed.get((addr, block), 0)

    def device_clean(self, addr: str, block: int) -> bool:
        """True if ``addr`` has confirmed every chunk of ``block``."""
        return self.confirmed_mask(addr, block) == self.full_block_mask(block)

    def repair_mask(self, block: int) -> int:
        """Chunks to re-broadcast this round.

        Union of what each *reporting*, non-clean, non-straggler device is still
        missing. A silent bot contributes nothing - it gets another report
        request, not a data retransmit - so one lost report costs a round, never
        a whole re-sent block.
        """
        full = self.full_block_mask(block)
        missing = 0
        for addr in self.devices:
            if addr not in self._reported:
                continue
            if self.device_clean(addr, block) or addr in self._straggler:
                continue
            missing |= full & ~self.confirmed_mask(addr, block)
        return missing

    def block_settled(self, block: int) -> bool:
        """True once every device is either clean or a straggler for block."""
        return all(
            self.device_clean(addr, block) or addr in self._straggler
            for addr in self.devices
        )

    def indices_from_mask(self, block: int, mask: int) -> list[int]:
        """Absolute chunk indices selected by ``mask`` within ``block``."""
        start = block * self._w
        return [start + bit for bit in range(self._w) if mask & (1 << bit)]

    # ------------------------------------------------------------------ #
    # RX-thread entry points (thread-safe).
    # ------------------------------------------------------------------ #
    def on_report(self, addr: str, block_index: int, received_mask: int) -> None:
        """Feed a BLOCK_REPORT_RESP into the current round (RX thread)."""
        with self._lock:
            self._round_reports[addr] = (block_index, received_mask)

    def on_finalize_resp(self, addr: str, ok: bool) -> None:
        """Feed an OTA_FINALIZE_RESP (RX thread)."""
        with self._lock:
            self._finalize_inbox[addr] = bool(ok)

    # ------------------------------------------------------------------ #
    # Driver.
    # ------------------------------------------------------------------ #
    def run(self) -> dict[str, DeviceResult]:
        """Transfer the whole image and return per-device results."""
        for block in range(self.num_blocks):
            self._transfer_block(block)
        self._recover_stragglers()
        self._finalize()
        # The caller logs the summary (it has the elapsed time to go with it).
        return self._result()

    @property
    def chunk_sends(self) -> int:
        return self._chunk_sends

    def _log(self, event: str, **fields) -> None:
        if self._logger is not None:
            self._logger.info(event, **fields)

    def _delivered_total(self) -> int:
        """Total chunks confirmed across all (device, block) so far."""
        return sum(popcount(mask) for mask in self._confirmed.values())

    def missing_chunks(self, addr: str) -> list[int]:
        """Absolute chunk indices this device has not confirmed."""
        missing = []
        for block in range(self.num_blocks):
            full = self.full_block_mask(block)
            got = self.confirmed_mask(addr, block)
            gap = full & ~got
            if not gap:
                continue
            start = block * self._w
            for bit in range(self._w):
                if gap & (1 << bit):
                    missing.append(start + bit)
        return missing

    def _dest(self, addr: str | None) -> int:
        if addr is None:
            return BROADCAST_ADDRESS
        return int(addr, 16)

    def _send_chunks(self, indices: Iterable[int], addr: str | None) -> None:
        dest = self._dest(addr)
        for idx in sorted(indices):
            if idx in self._drop_chunks:
                continue
            chunk = self.chunks[idx]
            self._send_payload(
                dest,
                PayloadOTAChunk(
                    index=chunk.index,
                    count=chunk.size,
                    sha=chunk.sha,
                    chunk=chunk.data,
                ),
            )
            self._chunk_sends += 1
            if self.settings.inter_chunk_delay:
                self._sleep(self.settings.inter_chunk_delay)

    def _send_report_req(self, block: int, addr: str | None) -> None:
        self._send_payload(
            self._dest(addr),
            PayloadOTABlockReportReq(block_index=block, block_size=self._w),
        )

    def _reset_block_state(self) -> None:
        self._round = 0
        self._reported = set()
        for addr in self.devices:
            self._silent[addr] = 0
            self._stall[addr] = 0
            self._last_missing[addr] = None

    def _apply_confirmed(self, addr: str, block: int, got: int) -> None:
        """Merge newly reported bits, firing on_progress for fresh chunks."""
        key = (addr, block)
        prev = self._confirmed.get(key, 0)
        merged = prev | got
        if merged == prev:
            return
        self._confirmed[key] = merged
        if self._on_progress is not None:
            fresh = merged & ~prev
            start = block * self._w
            for bit in range(self._w):
                if fresh & (1 << bit):
                    self._on_progress(addr, start + bit)

    def _transfer_block(self, block: int) -> None:
        self._reset_block_state()
        needed = set(self.block_chunk_indices(block))
        while True:
            with self._lock:
                self._round_reports = {}
            targets = [None] if self.broadcast else list(self.devices)
            sent_this_round = 0
            for target in targets:
                if needed:
                    self._send_chunks(needed, target)
                    sent_this_round += len(needed)
                self._send_report_req(block, target)
            self._sleep(self.settings.report_timeout)
            self._evaluate_round(block)
            settled = self.block_settled(block)
            self._log(
                "block round",
                block=block,
                round=self._round,
                sent=sent_this_round,
                delivered=self._delivered_total(),
                settled=settled,
            )
            if settled:
                break
            needed = set(
                self.indices_from_mask(block, self.repair_mask(block))
            )
            self._round += 1
            if self._round >= self.settings.max_rounds_per_block:
                break
        # Record blocks this device never completed for the unicast pass.
        for addr in self.devices:
            if not self.device_clean(addr, block):
                self._incomplete[addr].add(block)
        self._log(
            "block done",
            block=block,
            rounds=self._round + 1,
            sends=self._chunk_sends,
            delivered=self._delivered_total(),
        )

    def _evaluate_round(self, block: int) -> None:
        with self._lock:
            reports = dict(self._round_reports)
        full = self.full_block_mask(block)
        for addr in self.devices:
            if self.device_clean(addr, block):
                continue
            rep = reports.get(addr)
            if rep is None:
                self._silent[addr] += 1
                if self._silent[addr] >= self.settings.silent_straggler_rounds:
                    self._straggler.add(addr)
                continue
            # The device reported this round: reset silence, allow rejoin.
            self._silent[addr] = 0
            self._reported.add(addr)
            self._straggler.discard(addr)
            reported_block, mask = rep
            if reported_block == block:
                got = mask & full
            elif reported_block < block:
                got = 0  # device has not started this block yet
            else:
                got = full  # already past this block
            self._apply_confirmed(addr, block, got)
            missing = full & ~self.confirmed_mask(addr, block)
            if missing == 0:
                self._stall[addr] = 0
                continue
            missing_count = popcount(missing)
            last = self._last_missing[addr]
            if last is not None and missing_count >= last:
                self._stall[addr] += 1
            else:
                self._stall[addr] = 0
            self._last_missing[addr] = missing_count
            if self._stall[addr] >= self.settings.stall_straggler_rounds:
                self._straggler.add(addr)

    def _recover_stragglers(self) -> None:
        """Bounded per-bot unicast repair for blocks left incomplete."""
        for addr in self.devices:
            for _ in range(self.settings.straggler_max_rounds):
                blocks = sorted(
                    b
                    for b in self._incomplete.get(addr, set())
                    if not self.device_clean(addr, b)
                )
                if not blocks:
                    break
                for block in blocks:
                    missing = self.full_block_mask(block) & ~self.confirmed_mask(
                        addr, block
                    )
                    with self._lock:
                        self._round_reports = {}
                    self._send_chunks(
                        self.indices_from_mask(block, missing), addr
                    )
                    self._send_report_req(block, addr)
                    self._sleep(self.settings.report_timeout)
                    self._evaluate_unicast(addr, block)
            # Refresh incomplete set after the pass.
            self._incomplete[addr] = {
                b
                for b in self._incomplete.get(addr, set())
                if not self.device_clean(addr, b)
            }

    def _evaluate_unicast(self, addr: str, block: int) -> None:
        with self._lock:
            rep = self._round_reports.get(addr)
        if rep is None:
            return
        reported_block, mask = rep
        if reported_block == block:
            self._straggler.discard(addr)
            self._apply_confirmed(addr, block, mask & self.full_block_mask(block))

    def _finalize(self) -> None:
        """Ask each device to verify the whole image against its SHA256."""
        for _ in range(self.settings.finalize_max_rounds):
            pending = [
                addr
                for addr in self.devices
                if not self._finalize_inbox.get(addr, False)
            ]
            if not pending:
                break
            payload = PayloadOTAFinalize(sha=self.image_sha)
            if self.broadcast and len(pending) == len(self.devices):
                # Everyone still needs it: one frame instead of N.
                self._send_payload(self._dest(None), payload)
            else:
                # Targeted transfer, or a retry for a subset. Asking the whole
                # network would make untargeted bots hash their own (unrelated)
                # flash and answer about it.
                for addr in pending:
                    self._send_payload(self._dest(addr), payload)
            self._sleep(self.settings.report_timeout)

    def _result(self) -> dict[str, DeviceResult]:
        total = len(self.chunks)
        results: dict[str, DeviceResult] = {}
        for addr in self.devices:
            confirmed = sum(
                popcount(self.confirmed_mask(addr, block))
                for block in range(self.num_blocks)
            )
            results[addr] = DeviceResult(
                confirmed_chunks=confirmed,
                total_chunks=total,
                straggler=addr in self._straggler
                or bool(self._incomplete.get(addr)),
                finalized=self._finalize_inbox.get(addr, False),
            )
        return results
