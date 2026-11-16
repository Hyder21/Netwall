package com.example.security

import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.exifinterface.media.ExifInterface
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.io.ByteArrayOutputStream
import java.io.InputStream

data class MetadataFinding(
    val title: String,
    val severity: String, // CRITICAL, HIGH, MEDIUM, INFO
    val description: String
)

data class ImageScanResult(
    val fileName: String,
    val dimensions: String,
    val fileSizeBytes: Int,
    val threatLevel: String, // CRITICAL, WARNING, CLEAN
    val findings: List<MetadataFinding>,
    val exifFields: Map<String, String>,
    val embeddedQrText: String? = null
)

data class QrScanResult(
    val rawPayload: String,
    val payloadType: String,
    val threatLevel: String,
    val findings: List<MetadataFinding>,
    val sanitizedPayload: String
)

data class EmojiScanResult(
    val originalLength: Int,
    val codePointCount: Int,
    val threatLevel: String,
    val findings: List<MetadataFinding>,
    val sanitizedText: String
)

object MetadataScannerEngine {

    private val suspiciousExifPatterns = listOf(
        Regex("<script|</script>|javascript:|vbscript:", RegexOption.IGNORE_CASE) to "Embedded Script Tag",
        Regex("powershell|cmd\\.exe|/bin/sh|/bin/bash|eval\\(|exec\\(", RegexOption.IGNORE_CASE) to "Command Execution String",
        Regex("http://\\d+\\.\\d+\\.\\d+\\.\\d+", RegexOption.IGNORE_CASE) to "Raw IP C2 URL",
        Regex("[\u202A-\u202E\u2066-\u2069]") to "Bidi Spoofing Control Character",
        Regex("[\u200B\u200C\u200D\uFEFF]{3,}") to "Hidden Zero-Width Steganography"
    )

    private val dangerousUrlSchemes = listOf("javascript:", "data:", "vbscript:", "file:", "intent://")

    private val cyrillicHomoglyphs = setOf(
        '\u0430', '\u0435', '\u043E', '\u0440', '\u0441', '\u0443', '\u0445',
        '\u0410', '\u0415', '\u041E', '\u0420', '\u0421', '\u0423', '\u0425'
    )

    fun scanImageUri(context: Context, uri: Uri): ImageScanResult {
        val resolver = context.contentResolver
        val fileName = resolveFileName(context, uri)
        val rawBytes = resolver.openInputStream(uri)?.use { readCappedBytes(it, 8 * 1024 * 1024) }
            ?: ByteArray(0)

        val findings = mutableListOf<MetadataFinding>()
        val exifMap = linkedMapOf<String, String>()

        // 1. Decode image dimensions cleanly
        val boundsOpts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(rawBytes, 0, rawBytes.size, boundsOpts)
        val width = boundsOpts.outWidth.coerceAtLeast(0)
        val height = boundsOpts.outHeight.coerceAtLeast(0)
        val dimensions = if (width > 0 && height > 0) "${width}x${height} px" else "Unknown"

        // 2. Inspect EXIF metadata via ExifInterface
        try {
            rawBytes.inputStream().use { stream ->
                val exif = ExifInterface(stream)
                val tagList = listOf(
                    ExifInterface.TAG_MAKE to "Camera Make",
                    ExifInterface.TAG_MODEL to "Camera Model",
                    ExifInterface.TAG_SOFTWARE to "Software / Encoder",
                    ExifInterface.TAG_DATETIME to "Capture Timestamp",
                    ExifInterface.TAG_ARTIST to "Artist / Author",
                    ExifInterface.TAG_COPYRIGHT to "Copyright",
                    ExifInterface.TAG_USER_COMMENT to "User Comment",
                    ExifInterface.TAG_IMAGE_DESCRIPTION to "Image Description",
                    ExifInterface.TAG_XMP to "Embedded XMP XML"
                )
                for ((tag, label) in tagList) {
                    val value = exif.getAttribute(tag)?.trim()
                    if (!value.isNullOrEmpty()) {
                        val preview = if (value.length > 140) value.take(140) + "..." else value
                        exifMap[label] = preview

                        // Check for injection or malformed Unicode inside EXIF tags
                        for ((pattern, issue) in suspiciousExifPatterns) {
                            if (pattern.containsMatchIn(value)) {
                                findings.add(
                                    MetadataFinding(
                                        title = "$issue in $label",
                                        severity = "CRITICAL",
                                        description = "Suspicious payload detected inside EXIF '$label' field."
                                    )
                                )
                            }
                        }

                        if (value.length > 512) {
                            findings.add(
                                MetadataFinding(
                                    title = "Oversized Metadata Field ($label)",
                                    severity = "HIGH",
                                    description = "$label contains ${value.length} chars, which can conceal steganographic or exploit payloads."
                                )
                            )
                        }
                    }
                }

                // GPS privacy leak check
                val latLong = exif.latLong
                if (latLong != null) {
                    val coords = String.format("%.5f, %.5f", latLong[0], latLong[1])
                    exifMap["GPS Coordinates"] = coords
                    findings.add(
                        MetadataFinding(
                            title = "GPS Location Leak Embedded",
                            severity = "HIGH",
                            description = "Exact coordinates ($coords) are stored in EXIF metadata and can expose device location."
                        )
                    )
                }
            }
        } catch (e: Exception) {
            findings.add(
                MetadataFinding(
                    title = "Malformed EXIF Header",
                    severity = "MEDIUM",
                    description = "EXIF parser flagged structural irregularity: ${e.message ?: "corrupt header"}."
                )
            )
        }

        // 3. Inspect raw binary polyglot & trailing bytes after JPEG EOI / PNG IEND
        inspectBinaryStegoAndPolyglot(rawBytes, findings)

        // 4. Also check if the picture contains a QR code!
        var embeddedQr: String? = null
        val bitmap = decodeSampledBitmap(rawBytes, 1200)
        if (bitmap != null) {
            embeddedQr = decodeQrFromBitmap(bitmap)
            if (embeddedQr != null) {
                val qrCheck = inspectQrPayload(embeddedQr, emptySet())
                if (qrCheck.threatLevel != "CLEAN") {
                    findings.add(
                        MetadataFinding(
                            title = "Embedded Malicious/Suspicious QR Code",
                            severity = if (qrCheck.threatLevel == "CRITICAL") "CRITICAL" else "HIGH",
                            description = "Picture contains a QR payload flagged as ${qrCheck.threatLevel}: ${embeddedQr.take(80)}"
                        )
                    )
                } else {
                    findings.add(
                        MetadataFinding(
                            title = "QR Code Detected in Image",
                            severity = "INFO",
                            description = "Decoded QR payload: ${embeddedQr.take(80)}"
                        )
                    )
                }
            }
            bitmap.recycle()
        }

        val threatLevel = when {
            findings.any { it.severity == "CRITICAL" } -> "CRITICAL"
            findings.any { it.severity == "HIGH" || it.severity == "MEDIUM" } -> "WARNING"
            else -> "CLEAN"
        }

        if (findings.isEmpty()) {
            findings.add(
                MetadataFinding(
                    title = "No Threats or Hidden Payloads",
                    severity = "INFO",
                    description = "Image headers, EXIF fields, and EOF markers passed integrity checks."
                )
            )
        }

        return ImageScanResult(
            fileName = fileName,
            dimensions = dimensions,
            fileSizeBytes = rawBytes.size,
            threatLevel = threatLevel,
            findings = findings,
            exifFields = exifMap,
            embeddedQrText = embeddedQr
        )
    }

    /**
     * Re-encodes image pixel data into a clean JPEG without EXIF, XMP, GPS, or trailing polyglot bytes.
     */
    fun stripMetadataAndSaveCleanCopy(context: Context, uri: Uri, originalName: String): String? {
        return try {
            val bitmap = context.contentResolver.openInputStream(uri)?.use {
                BitmapFactory.decodeStream(it)
            } ?: return null

            val cleanName = "NETWALL_Clean_${System.currentTimeMillis()}_${originalName.substringBeforeLast('.')}.jpg"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val values = ContentValues().apply {
                    put(MediaStore.Images.Media.DISPLAY_NAME, cleanName)
                    put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
                    put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/NETWALL")
                }
                val outUri = context.contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
                outUri?.let { dest ->
                    context.contentResolver.openOutputStream(dest)?.use { out ->
                        bitmap.compress(Bitmap.CompressFormat.JPEG, 95, out)
                    }
                }
                bitmap.recycle()
                "Pictures/NETWALL/$cleanName"
            } else {
                val outFile = java.io.File(context.cacheDir, cleanName)
                outFile.outputStream().use { out ->
                    bitmap.compress(Bitmap.CompressFormat.JPEG, 95, out)
                }
                bitmap.recycle()
                outFile.absolutePath
            }
        } catch (_: Exception) {
            null
        }
    }

    fun scanQrFromImageUri(context: Context, uri: Uri, blockedDomains: Set<String>): QrScanResult? {
        val rawBytes = context.contentResolver.openInputStream(uri)?.use { readCappedBytes(it, 8 * 1024 * 1024) }
            ?: return null
        val bitmap = decodeSampledBitmap(rawBytes, 1400) ?: return null
        val decoded = decodeQrFromBitmap(bitmap)
        bitmap.recycle()
        return decoded?.let { inspectQrPayload(it, blockedDomains) }
    }

    fun inspectQrPayload(rawPayload: String, blockedDomains: Set<String>): QrScanResult {
        val findings = mutableListOf<MetadataFinding>()
        val trimmed = rawPayload.trim()
        val lower = trimmed.lowercase()

        val payloadType = when {
            lower.startsWith("http://") || lower.startsWith("https://") -> "URL Link"
            lower.startsWith("wifi:") -> "Wi-Fi Config"
            lower.startsWith("intent://") || lower.startsWith("javascript:") || lower.startsWith("data:") -> "Executable / Script URI"
            lower.startsWith("tel:") || lower.startsWith("sms:") || lower.startsWith("smsto:") -> "Telephony / SMS Action"
            else -> "Raw Text / Data"
        }

        // Check dangerous URI schemes
        for (scheme in dangerousUrlSchemes) {
            if (lower.startsWith(scheme)) {
                findings.add(
                    MetadataFinding(
                        title = "Dangerous URI Scheme ($scheme)",
                        severity = "CRITICAL",
                        description = "QR code attempts to invoke an executable, script, or Android intent URI."
                    )
                )
            }
        }

        // Unencrypted HTTP
        if (lower.startsWith("http://")) {
            findings.add(
                MetadataFinding(
                    title = "Unencrypted HTTP Destination",
                    severity = "MEDIUM",
                    description = "Traffic is vulnerable to MITM interception or injection."
                )
            )
        }

        // Extract host if URL
        val host = extractHost(trimmed)
        if (host != null) {
            if (host.startsWith("xn--") || host.contains(".xn--")) {
                findings.add(
                    MetadataFinding(
                        title = "Punycode Homograph Domain (xn--)",
                        severity = "HIGH",
                        description = "Domain '$host' uses IDN punycode often used to spoof trusted brand names."
                    )
                )
            }
            if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)) {
                findings.add(
                    MetadataFinding(
                        title = "Direct Raw IP Address Link",
                        severity = "HIGH",
                        description = "QR points to raw IP '$host' rather than a verified domain."
                    )
                )
            }
            if (trimmed.substringAfter("://").substringBefore("/").contains("@")) {
                findings.add(
                    MetadataFinding(
                        title = "URL '@' Credential Spoofing",
                        severity = "CRITICAL",
                        description = "URL embeds '@' authority confusion to mask the true destination host."
                    )
                )
            }
            if (blockedDomains.any { blocked -> host.equals(blocked, true) || host.endsWith(".$blocked", true) }) {
                findings.add(
                    MetadataFinding(
                        title = "Matched Malicious Domain Blocklist",
                        severity = "CRITICAL",
                        description = "Destination '$host' is listed in NETWALL's malicious/phishing blocklist."
                    )
                )
            }
        }

        // Check hidden Unicode / emoji anomalies inside QR string
        val unicodeCheck = scanEmojiAndText(trimmed)
        if (unicodeCheck.threatLevel != "CLEAN") {
            findings.addAll(unicodeCheck.findings.filter { it.severity != "INFO" })
        }

        // Check embedded shell or script injection payloads in QR text
        val scriptPattern = Regex(
            "<script|javascript:|eval\\(|union\\s+select|cmd\\.exe|powershell|/bin/sh|/bin/bash",
            RegexOption.IGNORE_CASE
        )
        val scriptMatch = scriptPattern.find(trimmed)
        if (scriptMatch != null) {
            findings.add(
                MetadataFinding(
                    title = "Exploit / Script Payload in QR",
                    severity = "CRITICAL",
                    description = "Detected potentially malicious command or script sequence ('${scriptMatch.value}') inside QR payload."
                )
            )
        }

        val threatLevel = when {
            findings.any { it.severity == "CRITICAL" } -> "CRITICAL"
            findings.any { it.severity == "HIGH" || it.severity == "MEDIUM" } -> "WARNING"
            else -> "CLEAN"
        }

        if (findings.isEmpty()) {
            findings.add(
                MetadataFinding(
                    title = "Verified Safe QR Payload",
                    severity = "INFO",
                    description = "No dangerous URI schemes, homoglyphs, hidden Unicode, or blocked domains detected."
                )
            )
        }

        return QrScanResult(
            rawPayload = rawPayload,
            payloadType = payloadType,
            threatLevel = threatLevel,
            findings = findings,
            sanitizedPayload = unicodeCheck.sanitizedText
        )
    }

    fun scanEmojiAndText(input: String): EmojiScanResult {
        val findings = mutableListOf<MetadataFinding>()
        var unpairedSurrogates = 0
        var bidiControls = 0
        var zeroWidthCount = 0
        var controlChars = 0
        var maxZwjCluster = 0
        var currentZwjCluster = 0
        var maxCombiningRun = 0
        var currentCombiningRun = 0
        var homoglyphCount = 0

        var i = 0
        while (i < input.length) {
            val ch = input[i]
            if (Character.isHighSurrogate(ch)) {
                if (i + 1 < input.length && Character.isLowSurrogate(input[i + 1])) {
                    i += 2
                    currentCombiningRun = 0
                    continue
                } else {
                    unpairedSurrogates++
                    i++
                    continue
                }
            } else if (Character.isLowSurrogate(ch)) {
                unpairedSurrogates++
                i++
                continue
            }

            val code = ch.code
            when {
                code in 0x202A..0x202E || code in 0x2066..0x2069 -> bidiControls++
                code == 0x200D -> {
                    currentZwjCluster++
                    if (currentZwjCluster > maxZwjCluster) maxZwjCluster = currentZwjCluster
                }
                code == 0x200B || code == 0x200C || code == 0x2060 || code == 0xFEFF -> zeroWidthCount++
                (code in 0x0000..0x001F && code != 0x000A && code != 0x000D && code != 0x0009) || code == 0x007F -> controlChars++
                Character.getType(ch) == Character.NON_SPACING_MARK.toInt() -> {
                    currentCombiningRun++
                    if (currentCombiningRun > maxCombiningRun) maxCombiningRun = currentCombiningRun
                }
                ch in cyrillicHomoglyphs -> {
                    // Check if mixed with Latin letters
                    if (input.any { it in 'a'..'z' || it in 'A'..'Z' }) {
                        homoglyphCount++
                    }
                }
                else -> {
                    currentCombiningRun = 0
                    if (code !in 0xFE00..0xFE0F) {
                        currentZwjCluster = 0
                    }
                }
            }
            i++
        }

        if (unpairedSurrogates > 0) {
            findings.add(
                MetadataFinding(
                    title = "Malformed Emoji: $unpairedSurrogates Unpaired UTF-16 Surrogate(s)",
                    severity = "CRITICAL",
                    description = "Broken UTF-16 surrogate halves can crash text renderers, databases, or bypass input sanitizers."
                )
            )
        }
        if (bidiControls > 0) {
            findings.add(
                MetadataFinding(
                    title = "Bidi Override Attack ($bidiControls char)",
                    severity = "CRITICAL",
                    description = "Right-to-left override (U+202E / isolate) can disguise malicious .apk/.exe names or spoof URLs."
                )
            )
        }
        if (maxZwjCluster >= 4) {
            findings.add(
                MetadataFinding(
                    title = "Emoji ZWJ Crash Bomb ($maxZwjCluster chained joiners)",
                    severity = "HIGH",
                    description = "Excessive U+200D Zero-Width Joiner chaining triggers layout/rendering DoS."
                )
            )
        }
        if (maxCombiningRun >= 4) {
            findings.add(
                MetadataFinding(
                    title = "Zalgo / Combining Mark Flood ($maxCombiningRun stacked marks)",
                    severity = "HIGH",
                    description = "Stacked diacritical marks cause UI overflow and obscure hidden payloads."
                )
            )
        }
        if (zeroWidthCount > 0) {
            findings.add(
                MetadataFinding(
                    title = "Hidden Zero-Width Steganography ($zeroWidthCount chars)",
                    severity = "MEDIUM",
                    description = "Invisible zero-width characters (U+200B/FEFF) can watermark or smuggle hidden instructions."
                )
            )
        }
        if (homoglyphCount > 0) {
            findings.add(
                MetadataFinding(
                    title = "Mixed-Script Homoglyph Spoofing ($homoglyphCount chars)",
                    severity = "HIGH",
                    description = "Cyrillic lookalike characters mixed with Latin text to mimic legitimate domains or handles."
                )
            )
        }
        if (controlChars > 0) {
            findings.add(
                MetadataFinding(
                    title = "ASCII Control Characters ($controlChars chars)",
                    severity = "MEDIUM",
                    description = "Non-printable control bytes (NUL/ESC/DEL) embedded in text stream."
                )
            )
        }

        val sanitized = sanitizeUnicodeText(input)
        val threatLevel = when {
            findings.any { it.severity == "CRITICAL" } -> "CRITICAL"
            findings.any { it.severity == "HIGH" || it.severity == "MEDIUM" } -> "WARNING"
            else -> "CLEAN"
        }

        if (findings.isEmpty()) {
            findings.add(
                MetadataFinding(
                    title = "Valid Emoji & Clean Unicode",
                    severity = "INFO",
                    description = "All code points, emoji ZWJ sequences, and surrogate pairs are well-formed."
                )
            )
        }

        return EmojiScanResult(
            originalLength = input.length,
            codePointCount = runCatching { input.codePointCount(0, input.length) }.getOrDefault(input.length),
            threatLevel = threatLevel,
            findings = findings,
            sanitizedText = sanitized
        )
    }

    private fun sanitizeUnicodeText(input: String): String {
        val sb = StringBuilder(input.length)
        var i = 0
        var combiningRun = 0
        while (i < input.length) {
            val ch = input[i]
            if (Character.isHighSurrogate(ch)) {
                if (i + 1 < input.length && Character.isLowSurrogate(input[i + 1])) {
                    sb.append(ch).append(input[i + 1])
                    i += 2
                    combiningRun = 0
                    continue
                } else {
                    i++
                    continue // strip unpaired high surrogate
                }
            } else if (Character.isLowSurrogate(ch)) {
                i++
                continue // strip unpaired low surrogate
            }
            val code = ch.code
            val isDangerousInvisible = code in 0x202A..0x202E ||
                code in 0x2066..0x2069 ||
                code == 0x200B || code == 0x200C || code == 0x2060 || code == 0xFEFF ||
                (code in 0x0000..0x001F && code != 0x000A && code != 0x000D && code != 0x0009) ||
                code == 0x007F
            if (isDangerousInvisible) {
                i++
                continue
            }
            if (Character.getType(ch) == Character.NON_SPACING_MARK.toInt()) {
                combiningRun++
                if (combiningRun > 2) {
                    i++
                    continue
                }
            } else {
                combiningRun = 0
            }
            sb.append(ch)
            i++
        }
        return sb.toString()
    }

    private fun inspectBinaryStegoAndPolyglot(bytes: ByteArray, findings: MutableList<MetadataFinding>) {
        if (bytes.size < 16) return
        val isJpeg = (bytes[0].toInt() and 0xFF) == 0xFF && (bytes[1].toInt() and 0xFF) == 0xD8
        val isPng = bytes.size > 8 &&
            (bytes[0].toInt() and 0xFF) == 0x89 &&
            bytes[1].toInt().toChar() == 'P' &&
            bytes[2].toInt().toChar() == 'N' &&
            bytes[3].toInt().toChar() == 'G'

        if (isJpeg) {
            // Find last EOI FF D9
            var eoiIndex = -1
            for (i in bytes.size - 2 downTo 2) {
                if ((bytes[i].toInt() and 0xFF) == 0xFF && (bytes[i + 1].toInt() and 0xFF) == 0xD9) {
                    eoiIndex = i + 2
                    break
                }
            }
            if (eoiIndex != -1 && bytes.size - eoiIndex > 64) {
                val trailing = bytes.size - eoiIndex
                findings.add(
                    MetadataFinding(
                        title = "Polyglot / Trailing Data After JPEG EOI",
                        severity = "CRITICAL",
                        description = "Detected $trailing hidden bytes appended after the JPEG End-Of-Image marker (0xFFD9)."
                    )
                )
            }
        } else if (isPng) {
            val iendPattern = byteArrayOf(0x49, 0x45, 0x4E, 0x44) // "IEND"
            val iendIdx = indexOfBytes(bytes, iendPattern)
            if (iendIdx != -1 && bytes.size - (iendIdx + 8) > 32) {
                val trailing = bytes.size - (iendIdx + 8)
                findings.add(
                    MetadataFinding(
                        title = "Hidden Data Appended After PNG IEND",
                        severity = "CRITICAL",
                        description = "Detected $trailing trailing bytes hidden past the PNG IEND chunk."
                    )
                )
            }
        }

        // Scan printable header region (first 64KB) for embedded scripts or ZIP polyglots
        val headerSample = String(bytes, 0, minOf(bytes.size, 65536), Charsets.ISO_8859_1)
        if (headerSample.contains("<script", ignoreCase = true) ||
            headerSample.contains("<?php", ignoreCase = true)
        ) {
            findings.add(
                MetadataFinding(
                    title = "Embedded Script Inside Image Binary",
                    severity = "CRITICAL",
                    description = "Detected <script> or PHP code inside image file chunks."
                )
            )
        }
    }

    private fun decodeQrFromBitmap(bitmap: Bitmap): String? {
        val width = bitmap.width
        val height = bitmap.height
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
        val source = RGBLuminanceSource(width, height, pixels)
        val hints = mapOf(
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.ALSO_INVERTED to true
        )
        val reader = MultiFormatReader()
        return try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: Exception) {
            null
        } finally {
            reader.reset()
        }
    }

    private fun decodeSampledBitmap(bytes: ByteArray, maxDim: Int): Bitmap? {
        if (bytes.isEmpty()) return null
        val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
        var sample = 1
        while (opts.outWidth / sample > maxDim || opts.outHeight / sample > maxDim) {
            sample *= 2
        }
        val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sample }
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, decodeOpts)
    }

    private fun readCappedBytes(stream: InputStream, maxBytes: Int): ByteArray {
        val buffer = ByteArray(8192)
        val out = ByteArrayOutputStream()
        var total = 0
        while (total < maxBytes) {
            val read = stream.read(buffer)
            if (read <= 0) break
            out.write(buffer, 0, read)
            total += read
        }
        return out.toByteArray()
    }

    private fun resolveFileName(context: Context, uri: Uri): String {
        return context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && cursor.moveToFirst()) cursor.getString(idx) else null
        } ?: uri.lastPathSegment ?: "selected_image"
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    private fun extractHost(url: String): String? {
        val idx = url.indexOf("://")
        if (idx == -1) return null
        val after = url.substring(idx + 3).substringBefore('/').substringBefore('?').substringBefore('#')
        val hostPort = after.substringAfterLast('@')
        return hostPort.substringBefore(':').lowercase().takeIf { it.isNotBlank() }
    }
}
