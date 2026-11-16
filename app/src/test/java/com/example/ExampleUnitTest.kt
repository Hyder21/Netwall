package com.example

import com.example.data.db.TrustedNetworkEntity
import com.example.security.MetadataScannerEngine
import com.example.security.NetworkDefenseEngine
import com.example.vpn.PacketParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExampleUnitTest {

    @Test
    fun networkDefense_detectsArpSpoofingSniffing() {
        val lines = listOf(
            "IP address       HW type     Flags       HW address            Mask     Device",
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        wlan0",
            "192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:01     *        wlan0"
        )
        val entries = NetworkDefenseEngine.parseArpTableLines(lines)
        assertEquals(2, entries.size)
        val anomalies = NetworkDefenseEngine.detectArpSpoofingAnomalies(entries)
        assertTrue(anomalies.any { it.category == "SNIFFING_ALERT" && it.severity == "CRITICAL" })
    }

    @Test
    fun networkDefense_detectsWirelessEvilTwinSpoofing() {
        val baseline = TrustedNetworkEntity(
            networkKey = "HomeWiFi",
            lastBssid = "11:22:33:44:55:66",
            lastGatewayIp = "192.168.1.1",
            lastGatewayMac = "11:22:33:44:55:66",
            lastSecurityType = "WPA2-PSK"
        )
        val alerts = NetworkDefenseEngine.detectWirelessSpoofingAnomalies(
            transport = "Wi-Fi",
            ssid = "HomeWiFi",
            bssid = "99:88:77:66:55:44",
            security = "Open (Unencrypted)",
            gatewayIp = "192.168.1.1",
            gatewayMac = "11:22:33:44:55:66",
            hasCaptivePortal = false,
            dnsServers = listOf("1.1.1.1"),
            privateDnsActive = true,
            baseline = baseline
        )
        assertTrue(alerts.any { it.category == "WIRELESS_SPOOFING" && it.title.contains("BSSID Changed") })
        assertTrue(alerts.any { it.category == "WIRELESS_SPOOFING" && it.title.contains("Downgrade") })
    }

    @Test
    fun metadataScanner_detectsMalformedEmojiAndBidiSpoof() {
        val bidiResult = MetadataScannerEngine.scanEmojiAndText("photo_\u202Egpj.apk")
        assertEquals("CRITICAL", bidiResult.threatLevel)
        assertFalse(bidiResult.sanitizedText.contains('\u202E'))

        val brokenSurrogate = MetadataScannerEngine.scanEmojiAndText("Hello \uD83D World")
        assertEquals("CRITICAL", brokenSurrogate.threatLevel)
        assertFalse(brokenSurrogate.sanitizedText.contains('\uD83D'))
    }

    @Test
    fun metadataScanner_flagsMaliciousQrPayload() {
        val qrResult = MetadataScannerEngine.inspectQrPayload(
            rawPayload = "https://xn--pypal-4ve.com/login",
            blockedDomains = setOf("doubleclick.net")
        )
        assertEquals("WARNING", qrResult.threatLevel)
        assertTrue(qrResult.findings.any { it.title.contains("Punycode") })

        val jsQr = MetadataScannerEngine.inspectQrPayload(
            rawPayload = "javascript:alert(1)",
            blockedDomains = emptySet()
        )
        assertEquals("CRITICAL", jsQr.threatLevel)
    }

    @Test
    fun packetParser_parsesIpv4UdpPacket() {
        val packet = ByteArray(28)
        packet[0] = 0x45.toByte()
        packet[2] = 0x00
        packet[3] = 28
        packet[9] = 17 // UDP
        packet[12] = 10; packet[13] = 8; packet[14] = 0; packet[15] = 2
        packet[16] = 10; packet[17] = 8; packet[18] = 0; packet[19] = 1
        packet[20] = (12345 ushr 8).toByte(); packet[21] = (12345 and 0xFF).toByte()
        packet[22] = 0; packet[23] = 53

        val parsed = PacketParser.parseIpv4(packet, packet.size)
        assertNotNull(parsed)
        assertEquals("10.8.0.2", parsed?.srcIp)
        assertEquals("10.8.0.1", parsed?.dstIp)
        assertEquals(53, parsed?.dstPort)
    }
}
