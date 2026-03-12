"""
Sentinel Specialists - Real implementations with LLM integration.

These specialists perform actual infrastructure operations with:
- LLM-powered intelligent decision making
- Integration with real infrastructure APIs
- Proper error handling and validation
"""

from sentinel.agents.hierarchy.specialists.security import (
    IntrusionDetectionSpecialist,
    FirewallSpecialist,
    ThreatClassificationSpecialist,
)

from sentinel.agents.hierarchy.specialists.discovery import (
    ARPScanSpecialist,
    SNMPScanSpecialist,
    VendorIdentificationSpecialist,
    DeviceFingerprintSpecialist,
)

from sentinel.agents.hierarchy.specialists.reliability import (
    HealthCheckSpecialist,
    LogAnalysisSpecialist,
    ServiceRecoverySpecialist,
)

from sentinel.agents.hierarchy.specialists.network import (
    TrafficAnalysisSpecialist,
    QoSPolicySpecialist,
    BandwidthMonitorSpecialist,
    PathOptimizationSpecialist,
)

from sentinel.agents.hierarchy.specialists.compliance import (
    PolicyAuditSpecialist,
    RegulatoryComplianceSpecialist,
    AuditLogSpecialist,
    ComplianceReportSpecialist,
    ConfigurationDriftSpecialist,
)

from sentinel.agents.hierarchy.specialists.disaster_recovery import (
    BackupManagementSpecialist,
    RecoveryTestingSpecialist,
    FailoverOrchestrationSpecialist,
    ReplicationMonitoringSpecialist,
    DRPlanManagementSpecialist,
)

from sentinel.agents.hierarchy.specialists.cost_management import (
    BudgetTrackingSpecialist,
    CostOptimizationSpecialist,
    CostAnomalySpecialist,
    ResourceAllocationSpecialist,
    CostReportingSpecialist,
)

__all__ = [
    # Security specialists
    "IntrusionDetectionSpecialist",
    "FirewallSpecialist",
    "ThreatClassificationSpecialist",
    # Discovery specialists
    "ARPScanSpecialist",
    "SNMPScanSpecialist",
    "VendorIdentificationSpecialist",
    "DeviceFingerprintSpecialist",
    # Reliability specialists
    "HealthCheckSpecialist",
    "LogAnalysisSpecialist",
    "ServiceRecoverySpecialist",
    # Network optimization specialists
    "TrafficAnalysisSpecialist",
    "QoSPolicySpecialist",
    "BandwidthMonitorSpecialist",
    "PathOptimizationSpecialist",
    # Compliance specialists
    "PolicyAuditSpecialist",
    "RegulatoryComplianceSpecialist",
    "AuditLogSpecialist",
    "ComplianceReportSpecialist",
    "ConfigurationDriftSpecialist",
    # Disaster recovery specialists
    "BackupManagementSpecialist",
    "RecoveryTestingSpecialist",
    "FailoverOrchestrationSpecialist",
    "ReplicationMonitoringSpecialist",
    "DRPlanManagementSpecialist",
    # Cost management specialists
    "BudgetTrackingSpecialist",
    "CostOptimizationSpecialist",
    "CostAnomalySpecialist",
    "ResourceAllocationSpecialist",
    "CostReportingSpecialist",
]
