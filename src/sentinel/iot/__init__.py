"""
IoT device management for Sentinel.

Provides automatic classification, segmentation, and security
management for IoT devices on the network:
- Device fingerprinting and classification
- Automatic VLAN assignment based on device type
- Security policy enforcement
- Behavioral anomaly detection
"""
from sentinel.iot.classifier import (
    IoTClassifier,
    DeviceClass,
    DeviceProfile,
    ClassificationResult,
)
from sentinel.iot.segmenter import IoTSegmenter

__all__ = [
    "IoTClassifier",
    "IoTSegmenter",
    "DeviceClass",
    "DeviceProfile",
    "ClassificationResult",
]
