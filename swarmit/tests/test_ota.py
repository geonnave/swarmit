"""Unit tests for the block-OTA state machine (swarmit.testbed.ota).

These drive the protocol logic against a fake transport with a scripted loss
model and zero real time. Per the workspace no-mock rule they validate protocol
*logic* only and do NOT stand in for on-hardware Mari validation.
"""

import dataclasses
import hashlib

import pytest

from swarmit.testbed.ota import (
    BROADCAST_ADDRESS,
    BlockOTASettings,
    BlockTransfer,
)
from swarmit.testbed.protocol import (
    PayloadOTABlockReportReq,
    PayloadOTAChunk,
    PayloadOTAFinalize,
)

pytestmark = pytest.mark.transport_mock

CHUNK_SIZE = 128


@dataclasses.dataclass
class SimpleChunk:
    index: int
    size: int
    sha: bytes
    data: bytes


def make_chunks(image: bytes, chunk_size: int = CHUNK_SIZE) -> list[SimpleChunk]:
    chunks = []
    for i in range(0, len(image), chunk_size):
        data = image[i : i + chunk_size]
        sha = hashlib.sha256(data).digest()[:8]
        chunks.append(
            SimpleChunk(
                index=i // chunk_size, size=len(data), sha=sha, data=data
            )
        )
    return chunks


def make_image(n_bytes: int) -> bytes:
    # Deterministic, non-repeating enough that per-chunk shas differ.
    return bytes((i * 31 + 7) & 0xFF for i in range(n_bytes))


class FakeDevice:
    """Mirrors the firmware's per-block mask bookkeeping."""

    def __init__(self, addr: str, block_size: int):
        self.addr = addr
        self.w = block_size
        self.received: set[int] = set()
        self.block_index = 0
        self.mask = 0

    def deliver_chunk(self, index: int) -> None:
        blk = index // self.w
        if blk != self.block_index:
            self.block_index = blk
            self.mask = 0
        self.mask |= 1 << (index % self.w)
        self.received.add(index)

    def report(self) -> tuple[int, int]:
        return (self.block_index, self.mask)


class FakeTransport:
    """Delivers chunks/reports/finalize to fake devices with scripted loss.

    ``chunk_loss(addr, index) -> bool`` and ``report_loss(addr, block) -> bool``
    may be stateful (e.g. drop-once). ``report_loss`` also suppresses the
    finalize response so a dead/silent bot never finalizes.
    """

    def __init__(
        self,
        devices,
        block_size,
        total_chunks,
        chunk_loss=None,
        report_loss=None,
    ):
        self.devices = {a: FakeDevice(a, block_size) for a in devices}
        self.total_chunks = total_chunks
        self.chunk_loss = chunk_loss or (lambda addr, index: False)
        self.report_loss = report_loss or (lambda addr, block: False)
        self.bt: BlockTransfer | None = None
        self.chunk_sends = 0

    def _targets(self, dest):
        if dest == BROADCAST_ADDRESS:
            return list(self.devices.items())
        return [
            (a, d) for a, d in self.devices.items() if int(a, 16) == dest
        ]

    def send_payload(self, dest, payload):
        if isinstance(payload, PayloadOTAChunk):
            self.chunk_sends += 1
            for addr, dev in self._targets(dest):
                if not self.chunk_loss(addr, payload.index):
                    dev.deliver_chunk(payload.index)
        elif isinstance(payload, PayloadOTABlockReportReq):
            for addr, dev in self._targets(dest):
                if not self.report_loss(addr, payload.block_index):
                    block, mask = dev.report()
                    self.bt.on_report(addr, block, mask)
        elif isinstance(payload, PayloadOTAFinalize):
            for addr, dev in self._targets(dest):
                if self.report_loss(addr, -1):
                    continue
                self.bt.on_finalize_resp(
                    addr, len(dev.received) == self.total_chunks
                )


def build(devices, image, settings=None, chunk_loss=None, report_loss=None):
    chunks = make_chunks(image)
    settings = settings or BlockOTASettings(
        block_size=4, inter_chunk_delay=0.0
    )
    transport = FakeTransport(
        devices,
        settings.block_size,
        len(chunks),
        chunk_loss=chunk_loss,
        report_loss=report_loss,
    )
    progress = []
    bt = BlockTransfer(
        chunks=chunks,
        devices=devices,
        send_payload=transport.send_payload,
        image_sha=hashlib.sha256(image).digest(),
        settings=settings,
        sleep=lambda *_: None,
        on_progress=lambda a, i: progress.append((a, i)),
    )
    transport.bt = bt
    return bt, transport, progress, chunks


# --------------------------------------------------------------------------- #
# Pure-helper tests.
# --------------------------------------------------------------------------- #
def test_block_layout_and_masks():
    image = make_image(10 * CHUNK_SIZE + 5)  # 11 chunks, W=4 -> 3 blocks
    bt, *_ = build(["AABB"], image)
    assert bt.num_blocks == 3
    assert list(bt.block_chunk_indices(0)) == [0, 1, 2, 3]
    assert list(bt.block_chunk_indices(2)) == [8, 9, 10]  # partial last block
    assert bt.full_block_mask(0) == 0b1111
    assert bt.full_block_mask(2) == 0b111  # only 3 chunks
    assert bt.indices_from_mask(1, 0b1010) == [5, 7]


def test_report_wait_waits_for_residual_backlog():
    # No pacing: wait covers the full drain of what was sent.
    unpaced = BlockOTASettings(
        block_size=4,
        report_timeout=0.3,
        per_chunk_delivery=0.25,
        inter_chunk_delay=0.0,
        wait_cap=12.0,
    )
    bt, *_ = build(["AABB"], make_image(CHUNK_SIZE), settings=unpaced)
    assert bt.report_wait(0) == pytest.approx(0.3)  # nothing sent
    assert bt.report_wait(4) == pytest.approx(0.3 + 4 * 0.25)  # full drain
    assert bt.report_wait(1000) == pytest.approx(12.0)  # capped

    # Fully paced (delay >= drain): the send already drained it, so we wait
    # only the report window regardless of how many chunks were sent.
    paced = BlockOTASettings(
        block_size=4,
        report_timeout=0.3,
        per_chunk_delivery=0.25,
        inter_chunk_delay=0.25,
    )
    bt2, *_ = build(["AABB"], make_image(CHUNK_SIZE), settings=paced)
    assert bt2.report_wait(32) == pytest.approx(0.3)


def test_repair_mask_unions_reporting_devices():
    image = make_image(4 * CHUNK_SIZE)  # one full block, W=4
    bt, *_ = build(["AAAA", "BBBB"], image)
    bt._reported = {"AAAA", "BBBB"}
    bt._apply_confirmed("AAAA", 0, 0b0011)  # A has chunks 0,1
    bt._apply_confirmed("BBBB", 0, 0b0101)  # B has chunks 0,2
    # Union of missing: A misses 2,3 ; B misses 1,3 -> {1,2,3}
    assert bt.repair_mask(0) == 0b1110


def test_silent_device_contributes_no_repair():
    image = make_image(4 * CHUNK_SIZE)
    bt, *_ = build(["AAAA", "BBBB"], image)
    # Only AAAA reported (missing chunk 3); BBBB is silent this block.
    bt._reported = {"AAAA"}
    bt._apply_confirmed("AAAA", 0, 0b0111)
    # Repair only covers what AAAA reported missing; silence != full block.
    assert bt.repair_mask(0) == 0b1000


def test_earlier_reported_block_means_needs_full_block():
    image = make_image(8 * CHUNK_SIZE)  # 2 blocks of 4
    bt, transport, _, _ = build(["AAAA"], image)
    bt._reset_block_state(1)
    # Device reports it is still on block 0 while we evaluate block 1.
    bt._round_reports = {"AAAA": (0, 0b1111)}
    bt._evaluate_round(1)
    # Reported but on an older block -> needs the whole current block.
    assert bt.repair_mask(1) == bt.full_block_mask(1)


# --------------------------------------------------------------------------- #
# End-to-end convergence tests.
# --------------------------------------------------------------------------- #
def test_clean_path_single_bot_multi_block():
    image = make_image(10 * CHUNK_SIZE + 20)  # 11 chunks
    bt, transport, progress, chunks = build(["AABBCCDD"], image)
    results = bt.run()
    r = results["AABBCCDD"]
    assert r.success
    assert r.confirmed_chunks == len(chunks)
    assert not r.straggler
    # No loss: exactly one send per chunk.
    assert transport.chunk_sends == len(chunks)
    # Progress fired once per chunk.
    assert len(progress) == len(chunks)


def test_clean_path_multi_bot_broadcast():
    image = make_image(9 * CHUNK_SIZE)
    devices = ["1111", "2222", "3333"]
    bt, transport, _, chunks = build(devices, image)
    results = bt.run()
    assert all(results[d].success for d in devices)
    # Broadcast: one send per chunk covers all bots.
    assert transport.chunk_sends == len(chunks)


def test_recovers_from_chunk_loss_no_straggler():
    image = make_image(8 * CHUNK_SIZE)  # 2 blocks
    # Drop chunk 2 and chunk 5 exactly once each for the single bot.
    drop = {("AAAA", 2), ("AAAA", 5)}

    def chunk_loss(addr, index):
        if (addr, index) in drop:
            drop.discard((addr, index))
            return True
        return False

    bt, transport, _, chunks = build(["AAAA"], image, chunk_loss=chunk_loss)
    results = bt.run()
    assert results["AAAA"].success
    assert not results["AAAA"].straggler
    # Two chunks were retransmitted once.
    assert transport.chunk_sends == len(chunks) + 2


def test_lost_report_costs_a_round_not_a_block():
    image = make_image(4 * CHUNK_SIZE)  # single block
    # Drop the bot's first report only; data all arrives.
    state = {"dropped": False}

    def report_loss(addr, block):
        if block == 0 and not state["dropped"]:
            state["dropped"] = True
            return True
        return False

    bt, transport, _, chunks = build(["AAAA"], image, report_loss=report_loss)
    results = bt.run()
    assert results["AAAA"].success
    # The block never had to be re-sent, only the report re-requested: still
    # exactly one send per chunk.
    assert transport.chunk_sends == len(chunks)


def test_silent_bot_becomes_straggler_and_swarm_advances():
    image = make_image(4 * CHUNK_SIZE)
    good, dead = "600D", "DEAD"
    devices = [good, dead]

    # DEAD receives nothing and never reports; 600D is healthy.
    def chunk_loss(addr, index):
        return addr == dead

    def report_loss(addr, block):
        return addr == dead

    settings = BlockOTASettings(
        block_size=4,
        inter_chunk_delay=0.0,
        silent_straggler_rounds=3,
        straggler_max_rounds=2,
    )
    bt, transport, _, chunks = build(
        devices,
        image,
        settings=settings,
        chunk_loss=chunk_loss,
        report_loss=report_loss,
    )
    results = bt.run()
    # Healthy bot completes; dead bot is a straggler and fails finalize, but
    # the run terminates (swarm advanced past the silent bot).
    assert results[good].success
    assert results[dead].straggler
    assert not results[dead].success
    assert not results[dead].finalized


def test_stall_bot_becomes_straggler():
    image = make_image(4 * CHUNK_SIZE)

    # The bot always misses chunk 3: every retransmit of it is lost, so its
    # missing set never shrinks -> stall straggler after stall_straggler_rounds.
    def chunk_loss(addr, index):
        return index == 3

    settings = BlockOTASettings(
        block_size=4,
        inter_chunk_delay=0.0,
        stall_straggler_rounds=3,
        straggler_max_rounds=1,
        silent_straggler_rounds=99,
    )
    bt, transport, _, _ = build(
        ["AAAA"], image, settings=settings, chunk_loss=chunk_loss
    )
    results = bt.run()
    assert results["AAAA"].straggler
    assert results["AAAA"].confirmed_chunks == 3  # got 0,1,2 not 3


def test_unicast_straggler_recovery_succeeds():
    image = make_image(4 * CHUNK_SIZE)

    # Chunk 3 is lost during the broadcast phase but delivered during the
    # unicast recovery pass (loss keyed to broadcast sends only).
    phase = {"unicast": False}

    def chunk_loss(addr, index):
        return index == 3 and not phase["unicast"]

    settings = BlockOTASettings(
        block_size=4,
        inter_chunk_delay=0.0,
        stall_straggler_rounds=2,
        silent_straggler_rounds=99,
        straggler_max_rounds=3,
    )
    bt, transport, _, chunks = build(
        ["AAAA"], image, settings=settings, chunk_loss=chunk_loss
    )

    # Flip to "unicast delivers" right when the recovery pass starts by wrapping
    # the transport: the first unicast chunk send clears the loss.
    orig_send = transport.send_payload

    def wrapped(dest, payload):
        if dest != BROADCAST_ADDRESS and isinstance(payload, PayloadOTAChunk):
            phase["unicast"] = True
        orig_send(dest, payload)

    bt._send_payload = wrapped
    results = bt.run()
    assert results["AAAA"].success
    assert not results["AAAA"].straggler
