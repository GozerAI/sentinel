# Sentinel Stub Implementation Plan

## Executive Summary

After reviewing the codebase, the integrations (OPNsense, UniFi, Proxmox, TrueNAS) are **well-implemented**. The problem was that agents had stubbed code that didn't call these integrations properly.

## Completed Implementations

### Phase 1: Wire Existing Integrations (COMPLETED)

#### 1.1 Optimizer Agent - QoS Application (COMPLETED)
**File:** `src/sentinel/agents/optimizer.py`
**Changes:**
- Added traffic shaping integration in `_do_execute()` for `apply_qos_policy` and `apply_rate_limit`
- Calls `router.add_traffic_shaper(policy)` to apply QoS rules to OPNsense
- Stores router rule ID for rollback capability
- Updated `_do_rollback()` to call `router.delete_traffic_shaper()`
- Added `router_rule_id` to rollback data capture

#### 1.2 Planner Agent - Firewall Rules (COMPLETED)
**File:** `src/sentinel/agents/planner.py`
**Changes:**
- Fixed `add_firewall_rule` action to call `router.add_firewall_rule()` and track rule ID
- Fixed `remove_firewall_rule` action to call `router.delete_firewall_rule()`
- Updated `_capture_rollback_data()` to include `router_rule_id`
- Updated `_do_rollback()` to properly delete router rules

#### 1.3 Guardian Agent - IP Block Rollback (COMPLETED)
**File:** `src/sentinel/agents/guardian.py`
**Changes:**
- Fixed `block_ip` to store IP->rule_id mapping in state (`guardian:blocked_ip_rules`)
- Fixed `unblock_ip` to call `router.delete_firewall_rule()`
- Updated `_capture_rollback_data()` to include `router_rule_id`
- Updated `_do_rollback()` to properly remove rules from router

### Phase 2: Add Missing Listeners (COMPLETED)

#### 2.1 Optimizer - NetFlow Listener (COMPLETED)
**File:** `src/sentinel/agents/optimizer.py`
**Changes:**
- Added `NetFlowProtocol` class as asyncio UDP protocol handler
- Added `_start_netflow_listener()` to create UDP endpoint on configured port
- Added `_stop_netflow_listener()` for clean shutdown
- Implemented `_parse_netflow_v5()` with full packet parsing
- Added stub implementations for NetFlow v9 and IPFIX
- Emits `network.flow.detected` events for each parsed flow
- Added netflow stats to agent stats (packets_received, flows_processed)

#### 2.2 Discovery - LLDP Topology (COMPLETED)
**File:** `src/sentinel/agents/discovery.py`
**Changes:**
- Implemented `_build_topology_from_lldp()` to parse LLDP neighbor data
- Creates `TopologyNode` for each discovered neighbor
- Creates `NetworkLink` for each connection (local_port -> remote_port)
- Added `_add_router_interfaces_to_topology()` for router integration
- Added `_lldp_capabilities_to_node_type()` for LLDP capability parsing
- Added `_device_type_to_node_type()` for device type conversion

**File:** `src/sentinel/core/models/network.py`
**Changes:**
- Updated `TopologyNode` with flexible string IDs, name, ip_address, mac_address, vendor, metadata
- Updated `NetworkLink` with string IDs, source/target_node_id for LLDP support
- Updated `NetworkTopology` with dict-based nodes and links storage
- Added `get_node_neighbors()`, `get_nodes_by_type()`, `get_node_by_mac()` methods

### Integration Layer Additions

#### OPNsense Router - Traffic Shaping (COMPLETED)
**File:** `src/sentinel/integrations/routers/opnsense.py`
**Changes:**
- Added `add_traffic_shaper()` - creates pipe, queue, and rule for QoS
- Added `delete_traffic_shaper()` - removes traffic shaping pipe
- Added `get_traffic_shapers()` - lists all traffic shaping policies

#### Router Integration Base - QoS Interface (COMPLETED)
**File:** `src/sentinel/integrations/base.py`
**Changes:**
- Added `add_traffic_shaper()` with default warning implementation
- Added `delete_traffic_shaper()` with default warning implementation
- Added `get_traffic_shapers()` with default empty list return

## Remaining Work (Priority 3 - Nice-to-Have)

### 3.1 Strategy - LLM Failure Analysis
**File:** `src/sentinel/agents/strategy.py`
**Current:** Has placeholder for pattern analysis
**Fix:** Implement LLM query for failure root cause analysis

### 3.2 Strategy - Auto-Confirmation Logic
**File:** `src/sentinel/agents/strategy.py`
**Current:** `_evaluate_confirmation_request()` does nothing
**Fix:** Add risk-based auto-approval logic for low-risk actions

### 3.3 Healer - Predictive Analysis
**File:** `src/sentinel/agents/healer.py`
**Current:** Stores warnings but no ML prediction
**Fix:** Add time-series analysis for failure prediction

## Files Modified Summary

| File | Changes Made | Status |
|------|-------------|--------|
| `agents/optimizer.py` | QoS application, NetFlow listener | COMPLETED |
| `agents/planner.py` | Firewall rule application/rollback | COMPLETED |
| `agents/guardian.py` | IP block/unblock rollback | COMPLETED |
| `agents/discovery.py` | LLDP topology building | COMPLETED |
| `core/models/network.py` | Flexible topology models | COMPLETED |
| `integrations/base.py` | QoS interface methods | COMPLETED |
| `integrations/routers/opnsense.py` | Traffic shaping support | COMPLETED |

## Quick Wins Available Now

1. **Enable scanning in config** - Network discovery works, just disabled by default for safety
2. **Connect integrations** - OPNsense/UniFi just need credentials in config
3. **Configure NetFlow** - Enable netflow export on your router to port 2055

## Configuration Examples

### Enable Network Scanning
```yaml
agents:
  discovery:
    enable_scanning: true
    networks:
      - "192.168.1.0/24"
```

### Enable NetFlow Collection
```yaml
agents:
  optimizer:
    netflow_enabled: true
    netflow_port: 2055
```

### OPNsense Integration
```yaml
router:
  type: opnsense
  host: "192.168.1.1"
  port: 443
  api_key: "${ROUTER_API_KEY}"
  api_secret: "${ROUTER_API_SECRET}"
```
