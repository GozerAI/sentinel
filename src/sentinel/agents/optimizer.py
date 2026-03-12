"""
Optimizer Agent - Traffic engineering and QoS management.

This agent analyzes network traffic patterns and optimizes:
- Bandwidth allocation
- QoS policies
- Traffic shaping
- Load balancing
"""

import asyncio
import logging
import struct
import socket
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from sentinel.core.utils import utc_now
from sentinel.agents.base import BaseAgent
from sentinel.core.models.event import (
    Event,
    EventCategory,
    EventSeverity,
    AgentAction,
    AgentDecision,
)
from sentinel.core.models.network import TrafficFlow, QoSPolicy

logger = logging.getLogger(__name__)


class NetFlowProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for NetFlow packets."""

    def __init__(self, optimizer: "OptimizerAgent"):
        self.optimizer = optimizer
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle incoming NetFlow packet."""
        try:
            asyncio.create_task(self.optimizer._process_netflow_packet(data, addr))
        except Exception as e:
            logger.debug(f"Error processing NetFlow packet from {addr}: {e}")


class OptimizerAgent(BaseAgent):
    """
    Traffic optimization and QoS management agent.

    Monitors network traffic patterns and automatically applies
    QoS policies to ensure optimal bandwidth allocation for
    different application types.

    Configuration:
        optimizer:
            enabled: true
            analysis_interval_seconds: 60
            netflow_enabled: true
            netflow_port: 2055
            bandwidth_threshold_percent: 80
            auto_execute_threshold: 0.90

    Events Published:
        - network.bandwidth.high: High utilization detected
        - network.qos.applied: QoS policy applied
        - network.congestion.critical: Critical congestion

    Events Subscribed:
        - network.flow.detected: New traffic flow
        - network.congestion.detected: Congestion events
    """

    agent_name = "optimizer"
    agent_description = "Traffic engineering and QoS management"

    def __init__(self, engine, config: dict):
        super().__init__(engine, config)

        # Configuration
        self.analysis_interval = config.get("analysis_interval_seconds", 60)
        self.netflow_enabled = config.get("netflow_enabled", True)
        self.netflow_port = config.get("netflow_port", 2055)
        self.bandwidth_threshold = config.get("bandwidth_threshold_percent", 80)

        # State
        self._flows: dict[str, TrafficFlow] = {}
        self._link_utilization: dict[str, float] = {}
        self._qos_policies: dict[str, dict] = {}
        self._congestion_events: list[dict] = []

        # Timing
        self._last_analysis: Optional[datetime] = None

        # Application signatures for classification
        self._app_signatures = {
            # Streaming
            (443, "netflix.com"): "streaming",
            (443, "youtube.com"): "streaming",
            (443, "twitch.tv"): "streaming",
            # Gaming
            (3074, None): "gaming",  # Xbox Live
            (3478, None): "gaming",  # PlayStation
            (27015, None): "gaming",  # Steam
            # VoIP
            (5060, None): "voip",
            (5061, None): "voip",
            (10000, None): "voip",  # Webex
            # Backup/Sync
            (443, "backblaze.com"): "backup",
            (443, "dropbox.com"): "sync",
            (443, "drive.google.com"): "sync",
            # Work
            (443, "zoom.us"): "conferencing",
            (443, "teams.microsoft.com"): "conferencing",
        }

        # QoS priority mapping (lower = higher priority)
        self._priority_map = {
            "voip": 1,  # Highest - real-time
            "gaming": 2,  # High - latency sensitive
            "conferencing": 2,
            "streaming": 3,  # Medium - bandwidth heavy
            "sync": 4,  # Lower - bulk transfer
            "backup": 5,  # Lowest - background
            "default": 3,
        }

        # DSCP markings
        self._dscp_map = {
            1: 46,  # EF - Expedited Forwarding
            2: 34,  # AF41 - Assured Forwarding
            3: 0,  # Best effort
            4: 10,  # AF11
            5: 8,  # CS1 - Scavenger
        }

        # NetFlow listener state
        self._netflow_transport = None
        self._netflow_protocol = None
        self._netflow_packets_received = 0
        self._netflow_flows_processed = 0

        # NetFlow v9/IPFIX template caches (keyed by source_id/observation_domain + template_id)
        self._netflow_v9_templates: dict[tuple[int, int], dict] = {}
        self._ipfix_templates: dict[tuple[int, int], dict] = {}

        # Standard NetFlow v9 field type definitions
        self._netflow_v9_field_types = {
            1: ("IN_BYTES", 4),
            2: ("IN_PKTS", 4),
            3: ("FLOWS", 4),
            4: ("PROTOCOL", 1),
            5: ("SRC_TOS", 1),
            6: ("TCP_FLAGS", 1),
            7: ("L4_SRC_PORT", 2),
            8: ("IPV4_SRC_ADDR", 4),
            9: ("SRC_MASK", 1),
            10: ("INPUT_SNMP", 2),
            11: ("L4_DST_PORT", 2),
            12: ("IPV4_DST_ADDR", 4),
            13: ("DST_MASK", 1),
            14: ("OUTPUT_SNMP", 2),
            15: ("IPV4_NEXT_HOP", 4),
            16: ("SRC_AS", 2),
            17: ("DST_AS", 2),
            21: ("LAST_SWITCHED", 4),
            22: ("FIRST_SWITCHED", 4),
            23: ("OUT_BYTES", 4),
            24: ("OUT_PKTS", 4),
            27: ("IPV6_SRC_ADDR", 16),
            28: ("IPV6_DST_ADDR", 16),
            29: ("IPV6_SRC_MASK", 1),
            30: ("IPV6_DST_MASK", 1),
            32: ("ICMP_TYPE", 2),
            40: ("TOTAL_BYTES_EXP", 4),
            41: ("TOTAL_PKTS_EXP", 4),
            56: ("MAC_SRC_ADDR", 6),
            57: ("MAC_DST_ADDR", 6),
            61: ("DIRECTION", 1),
            136: ("FLOW_END_REASON", 1),
        }

        # Standard IPFIX Information Element definitions (subset)
        self._ipfix_field_types = {
            1: ("octetDeltaCount", 8),
            2: ("packetDeltaCount", 8),
            4: ("protocolIdentifier", 1),
            5: ("ipClassOfService", 1),
            6: ("tcpControlBits", 2),
            7: ("sourceTransportPort", 2),
            8: ("sourceIPv4Address", 4),
            11: ("destinationTransportPort", 2),
            12: ("destinationIPv4Address", 4),
            27: ("sourceIPv6Address", 16),
            28: ("destinationIPv6Address", 16),
            56: ("sourceMacAddress", 6),
            80: ("destinationMacAddress", 6),
            136: ("flowEndReason", 1),
            150: ("flowStartSeconds", 4),
            151: ("flowEndSeconds", 4),
            152: ("flowStartMilliseconds", 8),
            153: ("flowEndMilliseconds", 8),
        }

    async def _subscribe_events(self) -> None:
        """Subscribe to traffic-related events."""
        self.engine.event_bus.subscribe(self._handle_flow_event, event_type="network.flow.detected")
        self.engine.event_bus.subscribe(
            self._handle_congestion_event, event_type="network.congestion.detected"
        )

    async def _main_loop(self) -> None:
        """Main traffic analysis loop."""
        # Load existing QoS policies
        stored_policies = await self.engine.state.get("optimizer:qos_policies")
        if stored_policies:
            self._qos_policies = {p["id"]: p for p in stored_policies}

        # Start NetFlow listener if enabled
        if self.netflow_enabled:
            await self._start_netflow_listener()

        try:
            while self._running:
                try:
                    now = utc_now()

                    # Run analysis periodically
                    if (
                        self._last_analysis is None
                        or (now - self._last_analysis).total_seconds() > self.analysis_interval
                    ):
                        await self._analyze_traffic()
                        self._last_analysis = now

                    await asyncio.sleep(10)

                except Exception as e:
                    logger.error(f"Optimizer loop error: {e}")
                    await asyncio.sleep(30)
        finally:
            # Stop NetFlow listener on shutdown
            await self._stop_netflow_listener()

    async def _start_netflow_listener(self) -> None:
        """Start the NetFlow UDP listener."""
        try:
            loop = asyncio.get_event_loop()

            # Create UDP endpoint
            self._netflow_transport, self._netflow_protocol = await loop.create_datagram_endpoint(
                lambda: NetFlowProtocol(self),
                local_addr=("0.0.0.0", self.netflow_port),
                family=socket.AF_INET,
            )

            logger.info(f"NetFlow listener started on UDP port {self.netflow_port}")

        except PermissionError:
            logger.warning(
                f"Permission denied for NetFlow port {self.netflow_port} - try running as admin or use port > 1024"
            )
        except OSError as e:
            if "address already in use" in str(e).lower():
                logger.warning(f"NetFlow port {self.netflow_port} already in use")
            else:
                logger.error(f"Failed to start NetFlow listener: {e}")
        except Exception as e:
            logger.error(f"Failed to start NetFlow listener: {e}")

    async def _stop_netflow_listener(self) -> None:
        """Stop the NetFlow UDP listener."""
        if self._netflow_transport:
            self._netflow_transport.close()
            self._netflow_transport = None
            self._netflow_protocol = None
            logger.info("NetFlow listener stopped")

    async def _process_netflow_packet(self, data: bytes, addr: tuple) -> None:
        """Process a NetFlow packet and extract flow records."""
        if len(data) < 4:
            return

        self._netflow_packets_received += 1

        try:
            # Check NetFlow version (first 2 bytes)
            version = struct.unpack("!H", data[0:2])[0]

            if version == 5:
                await self._parse_netflow_v5(data, addr)
            elif version == 9:
                await self._parse_netflow_v9(data, addr)
            elif version == 10:  # IPFIX
                await self._parse_ipfix(data, addr)
            else:
                logger.debug(f"Unsupported NetFlow version {version} from {addr}")

        except Exception as e:
            logger.debug(f"Error parsing NetFlow packet: {e}")

    async def _parse_netflow_v5(self, data: bytes, addr: tuple) -> None:
        """Parse NetFlow v5 packet."""
        if len(data) < 24:  # Minimum header size
            return

        # NetFlow v5 header: version(2), count(2), sys_uptime(4), unix_secs(4), unix_nsecs(4), flow_seq(4), engine_type(1), engine_id(1), sampling(2)
        header = struct.unpack("!HHIIIIBBH", data[0:24])
        (
            version,
            count,
            sys_uptime,
            unix_secs,
            unix_nsecs,
            flow_seq,
            engine_type,
            engine_id,
            sampling,
        ) = header

        # Each flow record is 48 bytes
        record_size = 48
        offset = 24

        for i in range(count):
            if offset + record_size > len(data):
                break

            record = data[offset : offset + record_size]
            offset += record_size

            # Parse flow record
            # src_ip(4), dst_ip(4), next_hop(4), input_if(2), output_if(2), packets(4), bytes(4), start_time(4), end_time(4),
            # src_port(2), dst_port(2), pad1(1), tcp_flags(1), proto(1), tos(1), src_as(2), dst_as(2), src_mask(1), dst_mask(1), pad2(2)
            fields = struct.unpack("!IIIHHIIIIHH xBBBHHBBH", record)

            src_ip = socket.inet_ntoa(struct.pack("!I", fields[0]))
            dst_ip = socket.inet_ntoa(struct.pack("!I", fields[1]))
            src_port = fields[9]
            dst_port = fields[10]
            protocol = fields[12]
            packets = fields[5]
            bytes_transferred = fields[6]

            # Create flow event
            flow_data = {
                "id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": "tcp" if protocol == 6 else "udp" if protocol == 17 else str(protocol),
                "packets": packets,
                "bytes_sent": bytes_transferred,
                "exporter": addr[0],
            }

            self._netflow_flows_processed += 1

            # Emit as flow event
            await self.engine.event_bus.publish(
                Event(
                    category=EventCategory.NETWORK,
                    event_type="network.flow.detected",
                    severity=EventSeverity.DEBUG,
                    source=f"sentinel.agents.{self.agent_name}.netflow",
                    title=f"NetFlow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    data=flow_data,
                )
            )

    async def _parse_netflow_v9(self, data: bytes, addr: tuple) -> None:
        """Parse NetFlow v9 packet (template-based)."""
        if len(data) < 20:
            return

        # NetFlow v9 header: version(2), count(2), sys_uptime(4), unix_secs(4), seq_num(4), source_id(4)
        header = struct.unpack("!HHIIII", data[0:20])
        version, count, sys_uptime, unix_secs, seq_num, source_id = header

        logger.debug(f"NetFlow v9 packet from {addr}: {count} flowsets, source_id={source_id}")

        # Parse flowsets
        offset = 20
        flowsets_parsed = 0

        while offset < len(data) and flowsets_parsed < count:
            if offset + 4 > len(data):
                break

            # Flowset header: flowset_id(2), length(2)
            flowset_id, flowset_length = struct.unpack("!HH", data[offset : offset + 4])

            if flowset_length < 4:
                logger.debug(f"Invalid flowset length {flowset_length}")
                break

            flowset_data = data[offset + 4 : offset + flowset_length]

            if flowset_id == 0:
                # Template flowset
                await self._parse_v9_template_flowset(flowset_data, source_id)
            elif flowset_id == 1:
                # Options template flowset (skip for now)
                logger.debug(f"NetFlow v9 options template from {addr}")
            elif flowset_id >= 256:
                # Data flowset - use template to parse
                await self._parse_v9_data_flowset(flowset_data, flowset_id, source_id, addr)

            offset += flowset_length
            flowsets_parsed += 1

    async def _parse_v9_template_flowset(self, data: bytes, source_id: int) -> None:
        """Parse NetFlow v9 template flowset and cache templates."""
        offset = 0

        while offset + 4 <= len(data):
            # Template header: template_id(2), field_count(2)
            template_id, field_count = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4

            if field_count == 0 or offset + (field_count * 4) > len(data):
                break

            # Parse field definitions
            fields = []
            template_length = 0

            for _ in range(field_count):
                if offset + 4 > len(data):
                    break
                field_type, field_length = struct.unpack("!HH", data[offset : offset + 4])
                offset += 4

                field_info = self._netflow_v9_field_types.get(
                    field_type, (f"FIELD_{field_type}", field_length)
                )
                fields.append(
                    {
                        "type": field_type,
                        "name": field_info[0],
                        "length": field_length,
                    }
                )
                template_length += field_length

            # Cache the template
            template_key = (source_id, template_id)
            self._netflow_v9_templates[template_key] = {
                "template_id": template_id,
                "field_count": field_count,
                "fields": fields,
                "record_length": template_length,
            }

            logger.debug(
                f"Cached NetFlow v9 template {template_id}: {field_count} fields, {template_length} bytes"
            )

    async def _parse_v9_data_flowset(
        self, data: bytes, template_id: int, source_id: int, addr: tuple
    ) -> None:
        """Parse NetFlow v9 data flowset using cached template."""
        template_key = (source_id, template_id)
        template = self._netflow_v9_templates.get(template_key)

        if not template:
            logger.debug(f"No template for flowset {template_id} from source {source_id}")
            return

        record_length = template["record_length"]
        if record_length == 0:
            return

        offset = 0
        while offset + record_length <= len(data):
            record_data = data[offset : offset + record_length]
            flow_record = await self._decode_v9_record(record_data, template)

            if flow_record:
                # Extract key fields for flow event
                src_ip = flow_record.get("IPV4_SRC_ADDR") or flow_record.get("IPV6_SRC_ADDR", "")
                dst_ip = flow_record.get("IPV4_DST_ADDR") or flow_record.get("IPV6_DST_ADDR", "")
                src_port = flow_record.get("L4_SRC_PORT", 0)
                dst_port = flow_record.get("L4_DST_PORT", 0)
                protocol = flow_record.get("PROTOCOL", 0)
                bytes_in = flow_record.get("IN_BYTES", 0)
                packets = flow_record.get("IN_PKTS", 0)

                if src_ip and dst_ip:
                    flow_data = {
                        "id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
                        "source_ip": src_ip,
                        "source_port": src_port,
                        "destination_ip": dst_ip,
                        "destination_port": dst_port,
                        "protocol": (
                            "tcp" if protocol == 6 else "udp" if protocol == 17 else str(protocol)
                        ),
                        "packets": packets,
                        "bytes_sent": bytes_in,
                        "exporter": addr[0],
                        "netflow_version": 9,
                    }

                    self._netflow_flows_processed += 1

                    await self.engine.event_bus.publish(
                        Event(
                            category=EventCategory.NETWORK,
                            event_type="network.flow.detected",
                            severity=EventSeverity.DEBUG,
                            source=f"sentinel.agents.{self.agent_name}.netflow_v9",
                            title=f"NetFlow v9: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                            data=flow_data,
                        )
                    )

            offset += record_length

    async def _decode_v9_record(self, data: bytes, template: dict) -> dict:
        """Decode a NetFlow v9 data record using template."""
        record = {}
        offset = 0

        for field in template["fields"]:
            field_name = field["name"]
            field_length = field["length"]
            field_type = field["type"]

            if offset + field_length > len(data):
                break

            field_data = data[offset : offset + field_length]
            offset += field_length

            # Decode based on field type
            if field_type in (8, 12, 15):  # IPv4 addresses
                if field_length == 4:
                    record[field_name] = socket.inet_ntoa(field_data)
            elif field_type in (27, 28):  # IPv6 addresses
                if field_length == 16:
                    record[field_name] = socket.inet_ntop(socket.AF_INET6, field_data)
            elif field_type in (56, 57):  # MAC addresses
                if field_length == 6:
                    record[field_name] = ":".join(f"{b:02x}" for b in field_data)
            else:
                # Numeric fields
                if field_length == 1:
                    record[field_name] = struct.unpack("!B", field_data)[0]
                elif field_length == 2:
                    record[field_name] = struct.unpack("!H", field_data)[0]
                elif field_length == 4:
                    record[field_name] = struct.unpack("!I", field_data)[0]
                elif field_length == 8:
                    record[field_name] = struct.unpack("!Q", field_data)[0]

        return record

    async def _parse_ipfix(self, data: bytes, addr: tuple) -> None:
        """Parse IPFIX (NetFlow v10) packet."""
        if len(data) < 16:
            return

        # IPFIX header: version(2), length(2), export_time(4), seq_num(4), observation_domain(4)
        header = struct.unpack("!HHIII", data[0:16])
        version, length, export_time, seq_num, observation_domain = header

        logger.debug(f"IPFIX packet from {addr}: length {length}, domain={observation_domain}")

        # Parse sets (IPFIX calls them "sets" not "flowsets")
        offset = 16

        while offset + 4 <= len(data):
            # Set header: set_id(2), length(2)
            set_id, set_length = struct.unpack("!HH", data[offset : offset + 4])

            if set_length < 4 or offset + set_length > len(data):
                break

            set_data = data[offset + 4 : offset + set_length]

            if set_id == 2:
                # Template set
                await self._parse_ipfix_template_set(set_data, observation_domain)
            elif set_id == 3:
                # Options template set (skip for now)
                logger.debug(f"IPFIX options template from {addr}")
            elif set_id >= 256:
                # Data set - use template to parse
                await self._parse_ipfix_data_set(set_data, set_id, observation_domain, addr)

            offset += set_length

    async def _parse_ipfix_template_set(self, data: bytes, observation_domain: int) -> None:
        """Parse IPFIX template set and cache templates."""
        offset = 0

        while offset + 4 <= len(data):
            # Template record header: template_id(2), field_count(2)
            template_id, field_count = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4

            if field_count == 0:
                break

            # Parse field specifiers
            fields = []
            template_length = 0

            for _ in range(field_count):
                if offset + 4 > len(data):
                    break

                # Field specifier: information_element_id(2), field_length(2)
                # High bit of IE ID indicates enterprise bit
                ie_id, field_length = struct.unpack("!HH", data[offset : offset + 4])
                offset += 4

                enterprise_bit = (ie_id >> 15) & 1
                ie_id = ie_id & 0x7FFF

                enterprise_number = None
                if enterprise_bit:
                    if offset + 4 > len(data):
                        break
                    enterprise_number = struct.unpack("!I", data[offset : offset + 4])[0]
                    offset += 4

                # Handle variable length fields (length = 65535)
                actual_length = field_length if field_length != 65535 else 0

                field_info = self._ipfix_field_types.get(ie_id, (f"IE_{ie_id}", actual_length))
                fields.append(
                    {
                        "ie_id": ie_id,
                        "name": field_info[0],
                        "length": field_length,
                        "enterprise": enterprise_number,
                        "variable_length": field_length == 65535,
                    }
                )

                if field_length != 65535:
                    template_length += field_length

            # Cache the template
            template_key = (observation_domain, template_id)
            self._ipfix_templates[template_key] = {
                "template_id": template_id,
                "field_count": field_count,
                "fields": fields,
                "record_length": template_length,
                "has_variable_length": any(f["variable_length"] for f in fields),
            }

            logger.debug(f"Cached IPFIX template {template_id}: {field_count} fields")

    async def _parse_ipfix_data_set(
        self, data: bytes, template_id: int, observation_domain: int, addr: tuple
    ) -> None:
        """Parse IPFIX data set using cached template."""
        template_key = (observation_domain, template_id)
        template = self._ipfix_templates.get(template_key)

        if not template:
            logger.debug(
                f"No IPFIX template for set {template_id} from domain {observation_domain}"
            )
            return

        if template["has_variable_length"]:
            # Variable length records require more complex parsing
            await self._parse_ipfix_variable_records(data, template, addr)
        else:
            # Fixed length records
            record_length = template["record_length"]
            if record_length == 0:
                return

            offset = 0
            while offset + record_length <= len(data):
                record_data = data[offset : offset + record_length]
                flow_record = await self._decode_ipfix_record(record_data, template)

                if flow_record:
                    await self._emit_ipfix_flow_event(flow_record, addr)

                offset += record_length

    async def _parse_ipfix_variable_records(self, data: bytes, template: dict, addr: tuple) -> None:
        """Parse IPFIX records with variable-length fields."""
        offset = 0

        while offset < len(data):
            record = {}
            record_valid = True

            for field in template["fields"]:
                if offset >= len(data):
                    record_valid = False
                    break

                field_name = field["name"]
                ie_id = field["ie_id"]

                if field["variable_length"]:
                    # Variable length encoding
                    if offset >= len(data):
                        record_valid = False
                        break

                    length_byte = data[offset]
                    offset += 1

                    if length_byte < 255:
                        field_length = length_byte
                    else:
                        # Extended length
                        if offset + 2 > len(data):
                            record_valid = False
                            break
                        field_length = struct.unpack("!H", data[offset : offset + 2])[0]
                        offset += 2
                else:
                    field_length = field["length"]

                if offset + field_length > len(data):
                    record_valid = False
                    break

                field_data = data[offset : offset + field_length]
                offset += field_length

                # Decode the field
                record[field_name] = self._decode_ipfix_field(ie_id, field_data, field_length)

            if record_valid and record:
                await self._emit_ipfix_flow_event(record, addr)

    async def _decode_ipfix_record(self, data: bytes, template: dict) -> dict:
        """Decode an IPFIX data record using template."""
        record = {}
        offset = 0

        for field in template["fields"]:
            field_name = field["name"]
            field_length = field["length"]
            ie_id = field["ie_id"]

            if offset + field_length > len(data):
                break

            field_data = data[offset : offset + field_length]
            offset += field_length

            record[field_name] = self._decode_ipfix_field(ie_id, field_data, field_length)

        return record

    def _decode_ipfix_field(self, ie_id: int, data: bytes, length: int):
        """Decode a single IPFIX field based on its Information Element ID."""
        # IPv4 addresses
        if ie_id in (8, 12):  # sourceIPv4Address, destinationIPv4Address
            if length == 4:
                return socket.inet_ntoa(data)

        # IPv6 addresses
        elif ie_id in (27, 28):  # sourceIPv6Address, destinationIPv6Address
            if length == 16:
                return socket.inet_ntop(socket.AF_INET6, data)

        # MAC addresses
        elif ie_id in (56, 80):  # sourceMacAddress, destinationMacAddress
            if length == 6:
                return ":".join(f"{b:02x}" for b in data)

        # Numeric fields
        if length == 1:
            return struct.unpack("!B", data)[0]
        elif length == 2:
            return struct.unpack("!H", data)[0]
        elif length == 4:
            return struct.unpack("!I", data)[0]
        elif length == 8:
            return struct.unpack("!Q", data)[0]

        # Default: return as hex string for unknown types
        return data.hex()

    async def _emit_ipfix_flow_event(self, record: dict, addr: tuple) -> None:
        """Emit a flow event from parsed IPFIX record."""
        # Extract key fields - IPFIX uses different field names
        src_ip = record.get("sourceIPv4Address") or record.get("sourceIPv6Address", "")
        dst_ip = record.get("destinationIPv4Address") or record.get("destinationIPv6Address", "")
        src_port = record.get("sourceTransportPort", 0)
        dst_port = record.get("destinationTransportPort", 0)
        protocol = record.get("protocolIdentifier", 0)
        bytes_count = record.get("octetDeltaCount", 0)
        packets = record.get("packetDeltaCount", 0)

        if src_ip and dst_ip:
            flow_data = {
                "id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": "tcp" if protocol == 6 else "udp" if protocol == 17 else str(protocol),
                "packets": packets,
                "bytes_sent": bytes_count,
                "exporter": addr[0],
                "netflow_version": 10,  # IPFIX
            }

            self._netflow_flows_processed += 1

            await self.engine.event_bus.publish(
                Event(
                    category=EventCategory.NETWORK,
                    event_type="network.flow.detected",
                    severity=EventSeverity.DEBUG,
                    source=f"sentinel.agents.{self.agent_name}.ipfix",
                    title=f"IPFIX: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    data=flow_data,
                )
            )

    async def _handle_flow_event(self, event: Event) -> None:
        """Handle new flow detection."""
        flow_data = event.data

        # Create flow record
        flow_id = flow_data.get(
            "id", f"{flow_data.get('source_ip')}:{flow_data.get('source_port')}"
        )

        flow = {
            "id": flow_id,
            "source_ip": flow_data.get("source_ip"),
            "source_port": flow_data.get("source_port"),
            "destination_ip": flow_data.get("destination_ip"),
            "destination_port": flow_data.get("destination_port"),
            "protocol": flow_data.get("protocol", "tcp"),
            "bytes_sent": flow_data.get("bytes_sent", 0),
            "bytes_received": flow_data.get("bytes_received", 0),
            "start_time": flow_data.get("start_time", utc_now().isoformat()),
            "last_seen": utc_now(),
            "application": self._classify_application(flow_data),
        }

        self._flows[flow_id] = flow

        # Check if flow needs QoS
        await self._evaluate_flow_qos(flow)

    async def _handle_congestion_event(self, event: Event) -> None:
        """Handle congestion detection."""
        congestion_data = event.data

        self._congestion_events.append(
            {
                "timestamp": utc_now(),
                "link_id": congestion_data.get("link_id"),
                "utilization": congestion_data.get("utilization"),
                "queue_depth": congestion_data.get("queue_depth"),
            }
        )

        # Trigger immediate analysis for severe congestion
        utilization = congestion_data.get("utilization", 0)
        if utilization > 95:
            await self._handle_critical_congestion(congestion_data)

    def _classify_application(self, flow_data: dict) -> str:
        """Classify application from flow data."""
        dst_port = flow_data.get("destination_port")
        dst_host = flow_data.get("destination_host", "")

        # Check signatures
        for (port, host), app in self._app_signatures.items():
            if dst_port == port:
                if host is None or (dst_host and host in dst_host):
                    return app

        # Heuristics based on port
        if dst_port in (80, 443, 8080):
            return "web"
        elif dst_port in (22, 3389, 5900):
            return "remote_access"
        elif dst_port in (445, 139, 2049):
            return "file_transfer"
        elif dst_port in (25, 587, 993, 143):
            return "email"

        return "default"

    async def _evaluate_flow_qos(self, flow: dict) -> None:
        """Evaluate if flow needs QoS policy."""
        app = flow.get("application", "default")
        priority = self._priority_map.get(app, 3)

        # High priority apps get automatic QoS
        if priority <= 2:
            # Check if policy already exists
            existing = self._find_matching_policy(flow)
            if not existing:
                await self._propose_qos_policy(flow, priority)

    def _find_matching_policy(self, flow: dict) -> Optional[dict]:
        """Find existing QoS policy matching flow."""
        dst_port = flow.get("destination_port")

        for policy in self._qos_policies.values():
            if policy.get("destination_port") == dst_port:
                return policy
        return None

    async def _propose_qos_policy(self, flow: dict, priority: int) -> None:
        """Propose a new QoS policy for a flow."""
        policy_id = f"auto_{flow.get('application')}_{flow.get('destination_port')}"

        policy = {
            "id": policy_id,
            "name": policy_id,
            "description": f"Auto-generated QoS for {flow.get('application')}",
            "priority_queue": priority,
            "bandwidth_limit_mbps": None,  # No limit for high priority
            "bandwidth_guarantee_mbps": 10 if priority <= 2 else None,
            "dscp_marking": self._dscp_map.get(priority, 0),
            "destination_port": flow.get("destination_port"),
            "protocol": flow.get("protocol"),
            "auto_generated": True,
            "created_at": utc_now().isoformat(),
        }

        # Calculate confidence
        confidence = 0.85
        if flow.get("application") in ("voip", "gaming", "conferencing"):
            confidence = 0.92  # Higher for known apps

        decision = AgentDecision(
            agent_name=self.agent_name,
            decision_type="apply_qos",
            input_state={"flow": flow},
            analysis=f"High-priority {flow.get('application')} traffic detected",
            options_considered=[
                {"action": "apply_qos", "priority": priority},
                {"action": "monitor_only"},
            ],
            selected_option={"action": "apply_qos", "priority": priority},
            confidence=confidence,
        )
        self._decisions.append(decision)

        await self.execute_action(
            action_type="apply_qos_policy",
            target_type="qos_policy",
            target_id=policy_id,
            parameters={
                "policy": policy,
                "flow_id": flow.get("id"),
                "application": flow.get("application"),
            },
            reasoning=f"High-priority {flow.get('application')} traffic detected, applying QoS priority {priority}",
            confidence=confidence,
            reversible=True,
        )

    async def _analyze_traffic(self) -> None:
        """Periodic traffic analysis."""
        logger.debug("Running traffic analysis")

        # Clean old flows (older than 5 minutes)
        cutoff = utc_now() - timedelta(minutes=5)
        self._flows = {
            k: v
            for k, v in self._flows.items()
            if isinstance(v.get("last_seen"), datetime) and v["last_seen"] > cutoff
        }

        # Calculate bandwidth utilization per link
        await self._calculate_link_utilization()

        # Check for optimization opportunities
        await self._check_optimization_opportunities()

        # Persist state
        await self.engine.state.set("optimizer:flow_count", len(self._flows))

    async def _calculate_link_utilization(self) -> None:
        """Calculate bandwidth utilization for each link."""
        link_traffic: dict[str, int] = defaultdict(int)

        for flow in self._flows.values():
            src_net = flow.get("source_ip", "0.0.0.0").rsplit(".", 1)[0]
            dst_net = flow.get("destination_ip", "0.0.0.0").rsplit(".", 1)[0]
            link_key = f"{src_net}_to_{dst_net}"

            traffic = flow.get("bytes_sent", 0) + flow.get("bytes_received", 0)
            link_traffic[link_key] += traffic

        # Calculate utilization (assuming 1Gbps links)
        link_capacity_bytes = 125_000_000  # 1Gbps in bytes/sec

        for link_id, traffic in link_traffic.items():
            rate = traffic / max(self.analysis_interval, 1)
            utilization = (rate / link_capacity_bytes) * 100
            self._link_utilization[link_id] = min(utilization, 100)

            if utilization > self.bandwidth_threshold:
                await self._handle_high_utilization(link_id, utilization)

    async def _handle_high_utilization(self, link_id: str, utilization: float) -> None:
        """Handle high bandwidth utilization on a link."""
        logger.warning(f"High utilization on {link_id}: {utilization:.1f}%")

        # Find low-priority flows on this link
        low_priority_flows = []
        for flow in self._flows.values():
            src_net = flow.get("source_ip", "0.0.0.0").rsplit(".", 1)[0]
            dst_net = flow.get("destination_ip", "0.0.0.0").rsplit(".", 1)[0]
            flow_link = f"{src_net}_to_{dst_net}"

            if flow_link == link_id:
                priority = self._priority_map.get(flow.get("application", "default"), 3)
                if priority >= 4:  # Low priority
                    low_priority_flows.append(flow)

        if low_priority_flows:
            await self._propose_rate_limit(link_id, low_priority_flows)

        # Emit event
        await self.engine.event_bus.publish(
            Event(
                category=EventCategory.NETWORK,
                event_type="network.bandwidth.high",
                severity=EventSeverity.WARNING,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"High bandwidth utilization on {link_id}",
                description=f"Link utilization at {utilization:.1f}%, threshold is {self.bandwidth_threshold}%",
                data={
                    "link_id": link_id,
                    "utilization": utilization,
                    "low_priority_flows": len(low_priority_flows),
                },
            )
        )

    async def _propose_rate_limit(self, link_id: str, flows: list[dict]) -> None:
        """Propose rate limiting for flows."""
        # Group by application
        by_app: dict[str, list[dict]] = defaultdict(list)
        for flow in flows:
            app = flow.get("application", "default")
            by_app[app].append(flow)

        for app, app_flows in by_app.items():
            total_bytes = sum(
                f.get("bytes_sent", 0) + f.get("bytes_received", 0) for f in app_flows
            )

            # Calculate rate limit (50% of current usage, minimum 10 Mbps)
            current_rate_mbps = (total_bytes / max(self.analysis_interval, 1)) * 8 / 1_000_000
            limit_mbps = max(10, current_rate_mbps * 0.5)

            policy_id = f"ratelimit_{app}_{link_id.replace('.', '_')}"

            decision = AgentDecision(
                agent_name=self.agent_name,
                decision_type="rate_limit",
                input_state={"link_id": link_id, "app": app, "flows": len(app_flows)},
                analysis=f"Congestion on {link_id}, proposing rate limit for {app}",
                options_considered=[
                    {"action": "rate_limit", "limit_mbps": limit_mbps},
                    {"action": "monitor_only"},
                ],
                selected_option={"action": "rate_limit", "limit_mbps": limit_mbps},
                confidence=0.78,
            )
            self._decisions.append(decision)

            await self.execute_action(
                action_type="apply_rate_limit",
                target_type="qos_policy",
                target_id=policy_id,
                parameters={
                    "policy": {
                        "id": policy_id,
                        "name": policy_id,
                        "description": f"Rate limit for {app} during congestion",
                        "priority_queue": 5,
                        "bandwidth_limit_mbps": limit_mbps,
                        "auto_generated": True,
                    },
                    "link_id": link_id,
                    "application": app,
                    "flow_count": len(app_flows),
                },
                reasoning=f"Congestion on {link_id}, limiting {app} traffic to {limit_mbps:.1f} Mbps",
                confidence=0.78,
                reversible=True,
            )

    async def _handle_critical_congestion(self, congestion_data: dict) -> None:
        """Handle critical congestion events."""
        link_id = congestion_data.get("link_id")
        utilization = congestion_data.get("utilization", 0)

        logger.error(f"Critical congestion on {link_id}: {utilization}%")

        await self.engine.event_bus.publish(
            Event(
                category=EventCategory.NETWORK,
                event_type="network.congestion.critical",
                severity=EventSeverity.CRITICAL,
                source=f"sentinel.agents.{self.agent_name}",
                title=f"Critical congestion on {link_id}",
                description=f"Link at {utilization}% capacity, intervention required",
                data=congestion_data,
            )
        )

    async def _check_optimization_opportunities(self) -> None:
        """Check for traffic optimization opportunities."""
        # Remove stale auto-generated QoS policies
        stale_policies = []

        for policy_id, policy in self._qos_policies.items():
            if not policy.get("auto_generated"):
                continue

            dst_port = policy.get("destination_port")
            has_matching_flow = any(
                f.get("destination_port") == dst_port for f in self._flows.values()
            )

            if not has_matching_flow:
                stale_policies.append(policy_id)

        for policy_id in stale_policies:
            logger.info(f"Removing stale QoS policy: {policy_id}")
            del self._qos_policies[policy_id]

        # Persist if changes made
        if stale_policies:
            await self.engine.state.set("optimizer:qos_policies", list(self._qos_policies.values()))

    async def analyze(self, event: Event) -> Optional[AgentDecision]:
        """Analyze events for optimization decisions."""
        # Most handling done in event handlers
        return None

    async def _do_execute(self, action: AgentAction) -> dict:
        """Execute optimizer actions."""
        if action.action_type == "apply_qos_policy":
            policy = action.parameters.get("policy", {})
            policy_id = policy.get("id")

            # Store policy locally
            self._qos_policies[policy_id] = policy

            # Apply to router if available
            router = self.engine.get_integration("router")
            router_rule_id = None
            if router:
                try:
                    router_rule_id = await router.add_traffic_shaper(policy)
                    if router_rule_id:
                        # Store the router rule ID for rollback
                        policy["router_rule_id"] = router_rule_id
                        logger.info(
                            f"Applied QoS policy to router: {policy_id} -> {router_rule_id}"
                        )
                    else:
                        logger.warning(f"Router returned empty rule ID for policy {policy_id}")
                except Exception as e:
                    logger.error(f"Failed to apply QoS to router: {e}")
                    # Continue anyway - policy is stored locally

            # Persist
            await self.engine.state.set("optimizer:qos_policies", list(self._qos_policies.values()))

            return {"applied": True, "policy_id": policy_id, "router_rule_id": router_rule_id}

        elif action.action_type == "apply_rate_limit":
            policy = action.parameters.get("policy", {})
            policy_id = policy.get("id")

            self._qos_policies[policy_id] = policy

            # Apply rate limit to router
            router = self.engine.get_integration("router")
            router_rule_id = None
            if router:
                try:
                    router_rule_id = await router.add_traffic_shaper(policy)
                    if router_rule_id:
                        policy["router_rule_id"] = router_rule_id
                        logger.info(
                            f"Applied rate limit to router: {policy_id} -> {router_rule_id}"
                        )
                except Exception as e:
                    logger.error(f"Failed to apply rate limit to router: {e}")

            await self.engine.state.set("optimizer:qos_policies", list(self._qos_policies.values()))

            return {"applied": True, "policy_id": policy_id, "router_rule_id": router_rule_id}

        elif action.action_type == "remove_policy":
            policy_id = action.parameters.get("policy_id")

            if policy_id in self._qos_policies:
                policy = self._qos_policies[policy_id]

                # Remove from router if we have a router rule ID
                router_rule_id = policy.get("router_rule_id")
                if router_rule_id:
                    router = self.engine.get_integration("router")
                    if router:
                        try:
                            await router.delete_traffic_shaper(router_rule_id)
                            logger.info(f"Removed QoS policy from router: {router_rule_id}")
                        except Exception as e:
                            logger.error(f"Failed to remove QoS from router: {e}")

                del self._qos_policies[policy_id]

                await self.engine.state.set(
                    "optimizer:qos_policies", list(self._qos_policies.values())
                )
                return {"removed": True, "policy_id": policy_id}

            return {"removed": False, "error": "Policy not found"}

        raise ValueError(f"Unknown action type: {action.action_type}")

    async def _capture_rollback_data(self, action: AgentAction) -> Optional[dict]:
        """Capture state for rollback."""
        if action.action_type in ("apply_qos_policy", "apply_rate_limit"):
            policy = action.parameters.get("policy", {})
            return {
                "action": "remove_policy",
                "policy_id": policy.get("id"),
                "router_rule_id": policy.get("router_rule_id"),
            }
        return None

    async def _do_rollback(self, action: AgentAction) -> None:
        """Rollback optimizer actions."""
        rollback = action.rollback_data or {}

        if rollback.get("action") == "remove_policy":
            policy_id = rollback.get("policy_id")
            router_rule_id = rollback.get("router_rule_id")

            # Remove from router first
            if router_rule_id:
                router = self.engine.get_integration("router")
                if router:
                    try:
                        await router.delete_traffic_shaper(router_rule_id)
                        logger.info(f"Rolled back QoS from router: {router_rule_id}")
                    except Exception as e:
                        logger.error(f"Failed to rollback QoS from router: {e}")

            # Remove from local state
            if policy_id in self._qos_policies:
                del self._qos_policies[policy_id]

                await self.engine.state.set(
                    "optimizer:qos_policies", list(self._qos_policies.values())
                )

    async def _get_relevant_state(self) -> dict:
        """Get state relevant to optimizer decisions."""
        return {
            "active_flows": len(self._flows),
            "qos_policies": len(self._qos_policies),
            "link_utilization": self._link_utilization,
        }

    @property
    def stats(self) -> dict:
        """Get optimizer statistics."""
        base = super().stats

        return {
            **base,
            "active_flows": len(self._flows),
            "qos_policies": len(self._qos_policies),
            "congestion_events": len(self._congestion_events),
            "link_utilization": dict(self._link_utilization),
            "netflow_enabled": self.netflow_enabled,
            "netflow_listening": self._netflow_transport is not None,
            "netflow_packets_received": self._netflow_packets_received,
            "netflow_flows_processed": self._netflow_flows_processed,
        }
