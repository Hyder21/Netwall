package com.example.vpn

import java.nio.ByteBuffer

data class ParsedIpv4Packet(
    val headerLength: Int,
    val totalLength: Int,
    val protocol: Int, // 6=TCP, 17=UDP, 1=ICMP
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val tcpFlags: Int,
    val payloadOffset: Int,
    val payloadLength: Int
)

object PacketParser {

    fun parseIpv4(buffer: ByteArray, length: Int): ParsedIpv4Packet? {
        if (length < 20) return null
        val version = (buffer[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (buffer[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null

        val totalLength = ((buffer[2].toInt() and 0xFF) shl 8) or (buffer[3].toInt() and 0xFF)
        val protocol = buffer[9].toInt() and 0xFF

        val srcIp = "${buffer[12].toInt() and 0xFF}.${buffer[13].toInt() and 0xFF}.${buffer[14].toInt() and 0xFF}.${buffer[15].toInt() and 0xFF}"
        val dstIp = "${buffer[16].toInt() and 0xFF}.${buffer[17].toInt() and 0xFF}.${buffer[18].toInt() and 0xFF}.${buffer[19].toInt() and 0xFF}"

        var srcPort = 0
        var dstPort = 0
        var tcpFlags = 0
        var payloadOffset = ihl

        if (protocol == 6 && length >= ihl + 20) {
            srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)
            dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
            val dataOffset = ((buffer[ihl + 12].toInt() ushr 4) and 0x0F) * 4
            tcpFlags = buffer[ihl + 13].toInt() and 0x3F
            payloadOffset = ihl + maxOf(20, dataOffset)
        } else if (protocol == 17 && length >= ihl + 8) {
            srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)
            dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
            payloadOffset = ihl + 8
        }

        val payloadLength = (length - payloadOffset).coerceAtLeast(0)
        return ParsedIpv4Packet(
            headerLength = ihl,
            totalLength = totalLength,
            protocol = protocol,
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = srcPort,
            dstPort = dstPort,
            tcpFlags = tcpFlags,
            payloadOffset = payloadOffset,
            payloadLength = payloadLength
        )
    }

    /**
     * Extracts QNAME domain from a DNS query payload.
     */
    fun extractDnsQueryDomain(buffer: ByteArray, dnsOffset: Int, dnsLength: Int): String? {
        if (dnsLength < 13 || dnsOffset + dnsLength > buffer.size) return null
        var idx = dnsOffset + 12
        val end = dnsOffset + dnsLength
        val domain = StringBuilder()
        while (idx < end) {
            val labelLen = buffer[idx].toInt() and 0xFF
            if (labelLen == 0) break
            if ((labelLen and 0xC0) != 0) break // compressed pointer not expected in question
            idx++
            if (idx + labelLen > end) return null
            if (domain.isNotEmpty()) domain.append('.')
            for (k in 0 until labelLen) {
                domain.append(buffer[idx + k].toInt().toChar())
            }
            idx += labelLen
        }
        return domain.toString().lowercase().takeIf { it.isNotBlank() }
    }

    /**
     * Wraps a UDP response payload into a valid IPv4+UDP packet with computed checksums.
     */
    fun buildIpv4UdpResponsePacket(
        requestPacket: ByteArray,
        req: ParsedIpv4Packet,
        udpPayload: ByteArray,
        udpPayloadLen: Int
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + udpPayloadLen
        val out = ByteArray(totalLen)

        // IPv4 Header
        out[0] = 0x45.toByte()
        out[1] = 0x00
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = requestPacket[4]
        out[5] = requestPacket[5]
        out[6] = 0x40
        out[7] = 0x00
        out[8] = 64 // TTL
        out[9] = 17 // UDP
        // Swap src and dst IPs
        System.arraycopy(requestPacket, 16, out, 12, 4)
        System.arraycopy(requestPacket, 12, out, 16, 4)

        val ipChecksum = computeChecksum(out, 0, ipHeaderLen)
        out[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        out[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header (swap ports)
        out[20] = ((req.dstPort ushr 8) and 0xFF).toByte()
        out[21] = (req.dstPort and 0xFF).toByte()
        out[22] = ((req.srcPort ushr 8) and 0xFF).toByte()
        out[23] = (req.srcPort and 0xFF).toByte()
        val udpLen = udpHeaderLen + udpPayloadLen
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0
        out[27] = 0

        System.arraycopy(udpPayload, 0, out, 28, udpPayloadLen)

        // UDP checksum (with IPv4 pseudo-header)
        val pseudo = ByteBuffer.allocate(12 + udpLen)
        pseudo.put(out, 12, 4)
        pseudo.put(out, 16, 4)
        pseudo.put(0.toByte())
        pseudo.put(17.toByte())
        pseudo.putShort(udpLen.toShort())
        pseudo.put(out, 20, udpLen)
        val udpChecksum = computeChecksum(pseudo.array(), 0, pseudo.position())
        out[26] = ((udpChecksum ushr 8) and 0xFF).toByte()
        out[27] = (udpChecksum and 0xFF).toByte()

        return out
    }

    /**
     * Builds an NXDOMAIN DNS sinkhole response for a blocked domain.
     */
    fun buildDnsNxDomainPayload(queryPayload: ByteArray, queryOffset: Int, queryLen: Int): ByteArray {
        val copy = ByteArray(queryLen)
        System.arraycopy(queryPayload, queryOffset, copy, 0, queryLen)
        if (copy.size >= 4) {
            copy[2] = ((copy[2].toInt() and 0x01) or 0x81).toByte() // QR=1, RD preserved
            copy[3] = 0x83.toByte() // RA=1, RCODE=3 (NXDOMAIN)
            copy[6] = 0; copy[7] = 0 // Answer count = 0
            copy[8] = 0; copy[9] = 0 // Authority = 0
            copy[10] = 0; copy[11] = 0 // Additional = 0
        }
        return copy
    }

    private fun computeChecksum(buf: ByteArray, offset: Int, len: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (buf[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }
}
