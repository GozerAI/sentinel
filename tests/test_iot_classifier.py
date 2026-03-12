"""
Tests for IoT device classifier and segmenter.

Tests cover device fingerprinting, classification accuracy,
VLAN policy matching, and segmentation actions.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.iot.classifier import (
    IoTClassifier,
    DeviceClass,
    DeviceProfile,
    ClassificationResult,
    SecurityRisk,
)
from sentinel.iot.segmenter import (
    IoTSegmenter,
    VLANPolicy,
    SegmentationAction,
)


@pytest.fixture
def classifier():
    """Create an IoT classifier instance."""
    return IoTClassifier()


@pytest.fixture
def segmenter(classifier):
    """Create an IoT segmenter instance."""
    return IoTSegmenter(classifier)


class TestDeviceClassification:
    """Tests for device classification."""

    @pytest.mark.asyncio
    async def test_classify_raspberry_pi_by_mac(self, classifier):
        """Test Raspberry Pi classification by MAC OUI."""
        result = await classifier.classify(
            mac_address="B8:27:EB:12:34:56", ip_address="192.168.1.100"
        )

        assert result.device_class == DeviceClass.RASPBERRY_PI
        assert result.manufacturer == "Raspberry Pi Foundation"
        assert result.confidence > 0.3

    @pytest.mark.asyncio
    async def test_classify_ring_doorbell(self, classifier):
        """Test Ring doorbell classification."""
        result = await classifier.classify(
            mac_address="34:76:C5:AA:BB:CC", ip_address="192.168.1.101", hostname="ring-doorbell"
        )

        assert result.device_class == DeviceClass.DOORBELL
        assert "Ring" in result.manufacturer

    @pytest.mark.asyncio
    async def test_classify_philips_hue(self, classifier):
        """Test Philips Hue bridge classification."""
        result = await classifier.classify(
            mac_address="00:17:88:11:22:33", ip_address="192.168.1.102", open_ports=[80, 443]
        )

        assert result.device_class == DeviceClass.ZIGBEE_HUB
        assert "Philips" in result.manufacturer or "Signify" in result.manufacturer

    @pytest.mark.asyncio
    async def test_classify_amazon_echo(self, classifier):
        """Test Amazon Echo classification."""
        result = await classifier.classify(
            mac_address="44:65:0D:AA:BB:CC", ip_address="192.168.1.103", hostname="amazon-echo"
        )

        assert result.device_class == DeviceClass.SMART_SPEAKER
        assert result.manufacturer == "Amazon"

    @pytest.mark.asyncio
    async def test_classify_unknown_device(self, classifier):
        """Test classification of unknown device."""
        result = await classifier.classify(
            mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.199"
        )

        assert result.device_class == DeviceClass.UNKNOWN
        assert result.confidence < 0.5

    @pytest.mark.asyncio
    async def test_classify_by_hostname_pattern(self, classifier):
        """Test classification using hostname patterns."""
        result = await classifier.classify(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.104",
            hostname="nest-thermostat-living",
        )

        # Should match Nest pattern even with unknown MAC
        assert result.confidence > 0

    @pytest.mark.asyncio
    async def test_classify_by_ports(self, classifier):
        """Test classification using open ports."""
        result = await classifier.classify(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.105",
            open_ports=[554, 80, 443],  # RTSP + web
        )

        # Ports alone might suggest camera
        assert result.confidence > 0


class TestManufacturerLookup:
    """Tests for MAC OUI manufacturer lookup."""

    def test_lookup_known_vendor(self, classifier):
        """Test looking up known vendor."""
        vendor = classifier.get_manufacturer("B8:27:EB:12:34:56")
        assert vendor == "Raspberry Pi Foundation"

    def test_lookup_unknown_vendor(self, classifier):
        """Test looking up unknown vendor."""
        vendor = classifier.get_manufacturer("AA:BB:CC:DD:EE:FF")
        assert vendor == "Unknown"

    def test_lookup_normalized_mac(self, classifier):
        """Test MAC address normalization."""
        # Different formats should work
        assert classifier.get_manufacturer("b8:27:eb:12:34:56") == "Raspberry Pi Foundation"
        assert classifier.get_manufacturer("B8-27-EB-12-34-56") == "Raspberry Pi Foundation"


class TestSecurityRiskAssessment:
    """Tests for security risk assessment."""

    @pytest.mark.asyncio
    async def test_high_risk_device_classification(self, classifier):
        """Test high-risk device gets appropriate risk level."""
        # Hikvision camera - known security issues
        result = await classifier.classify(
            mac_address="1C:C3:16:AA:BB:CC", ip_address="192.168.1.110"
        )

        assert result.security_risk == SecurityRisk.HIGH

    @pytest.mark.asyncio
    async def test_low_risk_device_classification(self, classifier):
        """Test low-risk device gets appropriate risk level."""
        # Apple TV - generally secure
        result = await classifier.classify(
            mac_address="28:6A:B8:AA:BB:CC", ip_address="192.168.1.111"
        )

        assert result.security_risk in [SecurityRisk.LOW, SecurityRisk.MINIMAL]

    @pytest.mark.asyncio
    async def test_dangerous_ports_add_risk_factors(self, classifier):
        """Test that dangerous open ports add risk factors."""
        result = await classifier.classify(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.112",
            open_ports=[23, 21],  # Telnet and FTP
        )

        assert len(result.risk_factors) > 0
        assert any("Telnet" in f for f in result.risk_factors)


class TestClassificationCaching:
    """Tests for classification result caching."""

    @pytest.mark.asyncio
    async def test_cache_stores_result(self, classifier):
        """Test that classification result is cached."""
        await classifier.classify(mac_address="B8:27:EB:12:34:56", ip_address="192.168.1.100")

        cached = classifier.get_cached_classification("B8:27:EB:12:34:56")
        assert cached is not None
        assert cached.device_class == DeviceClass.RASPBERRY_PI

    @pytest.mark.asyncio
    async def test_get_all_classifications(self, classifier):
        """Test getting all cached classifications."""
        await classifier.classify(mac_address="B8:27:EB:11:11:11", ip_address="192.168.1.1")
        await classifier.classify(mac_address="B8:27:EB:22:22:22", ip_address="192.168.1.2")

        all_results = classifier.get_all_classifications()
        assert len(all_results) >= 2

    @pytest.mark.asyncio
    async def test_get_devices_by_class(self, classifier):
        """Test filtering devices by class."""
        await classifier.classify(mac_address="B8:27:EB:11:11:11", ip_address="192.168.1.1")
        await classifier.classify(mac_address="B8:27:EB:22:22:22", ip_address="192.168.1.2")

        pis = classifier.get_devices_by_class(DeviceClass.RASPBERRY_PI)
        assert len(pis) >= 2

    @pytest.mark.asyncio
    async def test_get_high_risk_devices(self, classifier):
        """Test getting high-risk devices."""
        # Add a high-risk device (Hikvision)
        await classifier.classify(mac_address="1C:C3:16:AA:BB:CC", ip_address="192.168.1.110")

        high_risk = classifier.get_high_risk_devices()
        assert len(high_risk) >= 1


class TestDeviceProfile:
    """Tests for device profile model."""

    def test_profile_creation(self):
        """Test creating a device profile."""
        profile = DeviceProfile(
            name="Test Device",
            manufacturer="Test Corp",
            device_class=DeviceClass.IOT_GENERIC,
            oui_prefixes=["AA:BB:CC"],
            recommended_vlan=50,
        )

        assert profile.name == "Test Device"
        assert profile.device_class == DeviceClass.IOT_GENERIC
        assert "AA:BB:CC" in profile.oui_prefixes

    def test_profile_with_risk_factors(self):
        """Test profile with risk factors."""
        profile = DeviceProfile(
            name="Risky Device",
            manufacturer="Risky Corp",
            device_class=DeviceClass.SECURITY_CAMERA,
            security_risk=SecurityRisk.HIGH,
            risk_factors=["Known vulnerabilities", "Outdated firmware"],
        )

        assert len(profile.risk_factors) == 2


class TestClassificationResult:
    """Tests for classification result model."""

    def test_result_serialization(self):
        """Test classification result to_dict."""
        result = ClassificationResult(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100",
            device_class=DeviceClass.SMART_TV,
            confidence=0.85,
            manufacturer="Samsung",
        )

        data = result.to_dict()

        assert data["mac_address"] == "AA:BB:CC:DD:EE:FF"
        assert data["device_class"] == "smart_tv"
        assert data["confidence"] == 0.85


class TestVLANPolicy:
    """Tests for VLAN policy model."""

    def test_policy_matches_device(self):
        """Test policy device matching."""
        policy = VLANPolicy(
            vlan_id=50, name="IoT", device_classes=[DeviceClass.SMART_TV, DeviceClass.SMART_SPEAKER]
        )

        result = ClassificationResult(device_class=DeviceClass.SMART_TV)
        assert policy.matches_device(result) is True

        result2 = ClassificationResult(device_class=DeviceClass.DESKTOP)
        assert policy.matches_device(result2) is False


class TestIoTSegmenter:
    """Tests for IoT device segmentation."""

    def test_default_policies_created(self, segmenter):
        """Test that default VLAN policies are created."""
        policies = segmenter.get_policies()
        assert len(policies) > 0

        # Check for common VLANs
        vlan_ids = [p.vlan_id for p in policies]
        assert 1 in vlan_ids  # Management
        assert 50 in vlan_ids  # IoT
        assert 100 in vlan_ids  # Infrastructure

    def test_determine_vlan_for_iot(self, segmenter, classifier):
        """Test VLAN determination for IoT device."""
        result = ClassificationResult(
            mac_address="AA:BB:CC:DD:EE:FF", device_class=DeviceClass.SMART_SPEAKER
        )

        vlan = segmenter.determine_vlan(result)
        assert vlan == 50  # IoT VLAN

    def test_determine_vlan_for_infrastructure(self, segmenter, classifier):
        """Test VLAN determination for infrastructure device."""
        result = ClassificationResult(
            mac_address="B8:27:EB:12:34:56", device_class=DeviceClass.RASPBERRY_PI
        )

        vlan = segmenter.determine_vlan(result)
        assert vlan == 100  # Infrastructure VLAN

    def test_determine_vlan_for_security_camera(self, segmenter, classifier):
        """Test VLAN determination for security camera."""
        result = ClassificationResult(
            mac_address="1C:C3:16:AA:BB:CC", device_class=DeviceClass.SECURITY_CAMERA
        )

        vlan = segmenter.determine_vlan(result)
        assert vlan == 55  # Security VLAN

    @pytest.mark.asyncio
    async def test_segment_device(self, segmenter, classifier):
        """Test device segmentation."""
        result = ClassificationResult(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100",
            device_class=DeviceClass.SMART_TV,
        )

        action = await segmenter.segment_device(result)

        assert action.success is True
        assert action.to_vlan == 50
        assert action.device_mac == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.asyncio
    async def test_segment_device_dry_run(self, segmenter, classifier):
        """Test dry run segmentation."""
        result = ClassificationResult(
            mac_address="AA:BB:CC:DD:EE:FF",
            ip_address="192.168.1.100",
            device_class=DeviceClass.SMART_TV,
        )

        action = await segmenter.segment_device(result, dry_run=True)

        assert "[DRY RUN]" in action.reason

    def test_get_device_vlan(self, segmenter):
        """Test getting device VLAN assignment."""
        segmenter._assignments["AA:BB:CC:DD:EE:FF"] = 50

        vlan = segmenter.get_device_vlan("aa:bb:cc:dd:ee:ff")
        assert vlan == 50

    def test_get_devices_in_vlan(self, segmenter):
        """Test getting devices in a VLAN."""
        segmenter._assignments["AA:BB:CC:DD:EE:FF"] = 50
        segmenter._assignments["11:22:33:44:55:66"] = 50
        segmenter._assignments["77:88:99:AA:BB:CC"] = 100

        devices = segmenter.get_devices_in_vlan(50)
        assert len(devices) == 2

    def test_add_custom_policy(self, segmenter):
        """Test adding custom VLAN policy."""
        policy = VLANPolicy(vlan_id=200, name="Custom", device_classes=[DeviceClass.PRINTER])

        segmenter.add_policy(policy)

        result = segmenter.get_policy(200)
        assert result is not None
        assert result.name == "Custom"

    @pytest.mark.asyncio
    async def test_audit_segmentation(self, segmenter, classifier):
        """Test segmentation audit."""
        # Add some classifications and assignments
        await classifier.classify(mac_address="AA:BB:CC:DD:EE:FF", ip_address="192.168.1.100")

        audit = await segmenter.audit_segmentation()

        assert "vlans" in audit
        assert "unassigned" in audit
        assert "violations" in audit
        assert "high_risk" in audit

    def test_get_statistics(self, segmenter):
        """Test getting segmentation statistics."""
        segmenter._assignments["AA:BB:CC:DD:EE:FF"] = 50
        segmenter._assignments["11:22:33:44:55:66"] = 100

        stats = segmenter.get_statistics()

        assert stats["total_devices"] == 2
        assert 50 in stats["vlan_distribution"]
        assert 100 in stats["vlan_distribution"]
