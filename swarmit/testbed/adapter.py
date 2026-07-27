"""Module containing classes for interfacing with the DotBot gateway.

This is the one module that knows how the radio works. Everything above it
sends payloads to addresses; the Mari specifics - schedules, slotframes,
downlink cells - stop here. That includes the OTA pacing model: how fast
chunks may be injected is a property of the link, so it is derived here from
the geometry the gateway reports rather than hardcoded upstream.
"""

import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace

from dotbot_utils.protocol import (
    Packet,
    Payload,
    ProtocolPayloadParserException,
)
from marilib.communication_adapter import MQTTAdapter as MarilibMQTTAdapter
from marilib.communication_adapter import SerialAdapter as MarilibSerialAdapter
from marilib.mari_protocol import Frame as MariFrame
from marilib.mari_protocol import NextProto
from marilib.marilib_cloud import MarilibCloud
from marilib.marilib_edge import MarilibEdge
from marilib.model import SCHEDULES, EdgeEvent, MariNode
from rich import print

from swarmit.testbed.ota import BLOCK_SIZE_DEFAULT, BlockOTASettings

# Share of the gateway's downlink slots OTA is allowed to drive. The rest is
# left for beacons, joins and commands, and as headroom against the gateway's
# shared TX queue.
OTA_DOWNLINK_UTILIZATION = 0.75
# Ceiling on how fast a bot can take chunks: SHA-verify on the net core, then a
# flash write on the app core. Measured on hardware at ~84/s, which is above
# the downlink capacity of every schedule - so the radio binds, not the device.
DEVICE_CHUNK_RATE_HZ = 84.0
# Used when the gateway has not reported its schedule yet. The mid-size
# schedule is the conservative choice: pacing derived from it under-drives a
# bigger schedule rather than overrunning a smaller one.
FALLBACK_SCHEDULE_ID = 4  # "medium"


@dataclass(frozen=True)
class LinkGeometry:
    """Capacity of the Mari link the gateway is currently running.

    Built from the schedule the gateway announces. A gateway sends one
    downlink frame per D-cell per slotframe, and every joined node owns one
    uplink cell per slotframe (so a whole fleet can report within one).
    """

    schedule_name: str
    slotframe_s: float
    downlink_pps: float
    uplink_cells: int
    reported: bool = True

    @classmethod
    def from_schedule_id(cls, schedule_id: int) -> "LinkGeometry | None":
        """Build from a Mari schedule id, or None if it is unknown."""
        schedule = SCHEDULES.get(schedule_id)
        if not schedule or not schedule["sf_duration"]:
            return None
        slotframe_s = schedule["sf_duration"] / 1000.0
        return cls(
            schedule_name=schedule["name"],
            slotframe_s=slotframe_s,
            downlink_pps=schedule["d_down"] / slotframe_s,
            uplink_cells=schedule["max_nodes"],
        )

    @classmethod
    def fallback(cls) -> "LinkGeometry":
        """Geometry to pace with when the gateway has not reported one."""
        return replace(
            cls.from_schedule_id(FALLBACK_SCHEDULE_ID), reported=False
        )


def derive_block_settings(
    geometry: "LinkGeometry | None",
    n_bots: int = 1,
    utilization: float = OTA_DOWNLINK_UTILIZATION,
    device_chunk_rate: float = DEVICE_CHUNK_RATE_HZ,
) -> BlockOTASettings:
    """Derive OTA block-transfer pacing from the link and the fleet size.

    Chunks are broadcast, so one frame reaches every bot and the send rate is
    independent of fleet size: it is the downlink capacity we are allowed to
    use, capped by what a bot can absorb. Fleet size only widens the report
    window, since the bots answer in their own uplink cells.
    """
    if geometry is None:
        geometry = LinkGeometry.fallback()
    inject_pps = max(
        1.0, min(geometry.downlink_pps * utilization, device_chunk_rate)
    )
    # Every bot reports within one slotframe; give the collection window two,
    # plus a slotframe for each extra fleet-full of uplink cells.
    report_slotframes = 2.0 + max(0, n_bots - 1) / max(
        1, geometry.uplink_cells
    )
    return BlockOTASettings(
        block_size=BLOCK_SIZE_DEFAULT,
        inter_chunk_delay=1.0 / inject_pps,
        report_timeout=geometry.slotframe_s * report_slotframes,
    )


class GatewayAdapterBase(ABC):
    """Base class for interface adapters."""

    @abstractmethod
    def init(self, on_frame_received: callable):
        """Initialize the interface."""

    @abstractmethod
    def close(self):
        """Close the interface."""

    @abstractmethod
    def send_payload(self, destination: int, payload: Payload):
        """Send payload to the interface."""

    def link_geometry(self) -> LinkGeometry | None:
        """Capacity of the link, or None if the gateway has not reported it."""
        return None


class MarilibEdgeAdapter(GatewayAdapterBase):
    """Class used to interface with Marilib."""

    def on_event(self, event: EdgeEvent, event_data: MariNode | MariFrame):
        if event == EdgeEvent.NODE_JOINED:
            if self.verbose:
                print("[green]Node joined:[/]", event_data)
        elif event == EdgeEvent.NODE_LEFT:
            if self.verbose:
                print("[orange]Node left:[/]", event_data)
        elif event == EdgeEvent.NODE_DATA:
            if event_data.header.next_proto != NextProto.SWARMIT_TESTBED:
                if self.verbose:
                    print(
                        "[red]swarmit: dropping NODE_DATA frame with "
                        f"unexpected next_proto {event_data.header.next_proto!r}[/]"
                    )
                return
            try:
                packet = Packet.from_bytes(event_data.payload)
            except (ValueError, ProtocolPayloadParserException) as exc:
                if self.verbose:
                    print(f"[red]Error parsing packet: {exc}[/]")
                return
            if not hasattr(self, "on_frame_received"):
                return
            self.on_frame_received(event_data.header, packet)

    def __init__(
        self,
        port: str,
        baudrate: int,
        verbose: bool = False,
        busy_wait_timeout: float = 3,
    ):
        self.verbose = verbose
        self.busy_wait_timeout = busy_wait_timeout
        try:
            self.mari = MarilibEdge(
                self.on_event,
                MarilibSerialAdapter(port, baudrate),
                metrics_probe_period=0,
            )
        except Exception as exc:
            print(f"[red]Error initializing MarilibEdge: {exc}[/]")
            sys.exit(1)

    def _busy_wait(self):
        """Wait for the condition to be met."""
        while self.busy_wait_timeout > 0:
            self.mari.update()
            self.busy_wait_timeout -= 0.1
            time.sleep(0.1)

    def init(self, on_frame_received: callable):
        self.on_frame_received = on_frame_received
        if self.verbose:
            self._busy_wait()
            print("[yellow]Mari nodes available:[/]")
            print(self.mari.nodes)

    def close(self):
        self.mari.serial_interface.close()

    def link_geometry(self) -> LinkGeometry | None:
        return LinkGeometry.from_schedule_id(
            self.mari.gateway.info.schedule_id
        )

    def send_payload(self, destination: int, payload: Payload):
        self.mari.send_frame(
            dst=destination,
            payload=Packet.from_payload(payload).to_bytes(),
            next_proto=NextProto.SWARMIT_TESTBED,
        )


class MarilibCloudAdapter(GatewayAdapterBase):
    """Class used to interface with Marilib."""

    def on_event(self, event: EdgeEvent, event_data: MariNode | MariFrame):
        if event == EdgeEvent.NODE_JOINED:
            if self.verbose:
                print("[green]Node joined:[/]", event_data)
        elif event == EdgeEvent.NODE_LEFT:
            if self.verbose:
                print("[orange]Node left:[/]", event_data)
        elif event == EdgeEvent.NODE_DATA:
            if event_data.header.next_proto != NextProto.SWARMIT_TESTBED:
                if self.verbose:
                    print(
                        "[red]swarmit: dropping NODE_DATA frame with "
                        f"unexpected next_proto {event_data.header.next_proto!r}[/]"
                    )
                return
            try:
                packet = Packet.from_bytes(event_data.payload)
            except (ValueError, ProtocolPayloadParserException) as exc:
                if self.verbose:
                    print(f"[red]Error parsing packet: {exc}[/]")
                return
            if not hasattr(self, "on_frame_received"):
                return
            self.on_frame_received(event_data.header, packet)

    def __init__(
        self,
        host: str,
        port: int,
        use_tls: bool,
        network_id: int,
        verbose: bool = False,
        busy_wait_timeout: float = 3,
        username: str | None = None,
        password: str | None = None,
    ):
        self.verbose = verbose
        self.busy_wait_timeout = busy_wait_timeout
        # Broker credentials (from DOTBOT_MQTT_USER / DOTBOT_MQTT_PASS) take
        # effect once the marilib companion adds username/password to
        # MQTTAdapter; until then anonymous connect (unchanged behaviour).
        mqtt_kwargs = {}
        if username is not None:
            mqtt_kwargs["username"] = username
        if password is not None:
            mqtt_kwargs["password"] = password
        try:
            self.mari = MarilibCloud(
                self.on_event,
                MarilibMQTTAdapter(
                    host, port, use_tls=use_tls, is_edge=False, **mqtt_kwargs
                ),
                network_id,
            )
        except Exception as exc:
            print(f"[red]Error initializing MarilibCloud: {exc}[/]")
            sys.exit(1)

    def _busy_wait(self):
        """Wait for the condition to be met."""
        while self.busy_wait_timeout > 0:
            self.mari.update()
            self.busy_wait_timeout -= 0.1
            time.sleep(0.1)

    def init(self, on_frame_received: callable):
        self.on_frame_received = on_frame_received
        if self.verbose:
            self._busy_wait()
            print("[yellow]Mari nodes available:[/]")
            print(self.mari.nodes)

    def close(self):
        pass

    def link_geometry(self) -> LinkGeometry | None:
        # Several gateways may be on the same network. They run the same
        # schedule, so the first one that has reported answers for all.
        for gateway in self.mari.gateways.values():
            geometry = LinkGeometry.from_schedule_id(gateway.info.schedule_id)
            if geometry is not None:
                return geometry
        return None

    def send_payload(self, destination: int, payload: Payload):
        self.mari.send_frame(
            dst=destination,
            payload=Packet.from_payload(payload).to_bytes(),
            next_proto=NextProto.SWARMIT_TESTBED,
        )
