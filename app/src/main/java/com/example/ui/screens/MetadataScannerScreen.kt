package com.example.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.EmojiEmotions
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.db.ScanReportEntity
import com.example.security.EmojiScanResult
import com.example.security.ImageScanResult
import com.example.security.MetadataFinding
import com.example.security.QrScanResult
import com.example.ui.components.ColourfulStatusPill
import com.example.ui.components.GradientFeatureCard
import com.example.ui.components.SeverityBadge
import com.example.ui.components.formatBytes
import com.example.ui.components.formatTimestamp
import com.example.ui.theme.LocalNetShieldColors

@Composable
fun MetadataScannerScreen(
    imageScanResult: ImageScanResult?,
    qrScanResult: QrScanResult?,
    emojiScanResult: EmojiScanResult?,
    scanReports: List<ScanReportEntity>,
    onScanImageUri: (Uri) -> Unit,
    onStripImageMetadata: () -> Unit,
    onScanQrImageUri: (Uri) -> Unit,
    onInspectQrText: (String) -> Unit,
    onScanEmojiText: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    var activeMode by remember { mutableIntStateOf(0) } // 0=Picture, 1=QR, 2=Emoji/Unicode
    var qrInput by remember { mutableStateOf("") }
    var emojiInput by remember { mutableStateOf("") }
    val clipboardManager = LocalClipboardManager.current

    val imagePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        uri?.let { onScanImageUri(it) }
    }

    val qrImagePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        uri?.let { onScanQrImageUri(it) }
    }

    Column(modifier = modifier.fillMaxSize()) {
        // Mode Selector Pills
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp)
        ) {
            ScannerModeTab(
                label = "Pictures",
                icon = Icons.Default.Image,
                selected = activeMode == 0,
                accent = accents.violet,
                onClick = { activeMode = 0 },
                modifier = Modifier
                    .weight(1f)
                    .testTag("scanner_tab_pictures")
            )
            ScannerModeTab(
                label = "QR Codes",
                icon = Icons.Default.QrCode2,
                selected = activeMode == 1,
                accent = accents.cyan,
                onClick = { activeMode = 1 },
                modifier = Modifier
                    .weight(1f)
                    .testTag("scanner_tab_qr")
            )
            ScannerModeTab(
                label = "Emojis",
                icon = Icons.Default.EmojiEmotions,
                selected = activeMode == 2,
                accent = accents.amber,
                onClick = { activeMode = 2 },
                modifier = Modifier
                    .weight(1f)
                    .testTag("scanner_tab_emoji")
            )
        }

        LazyColumn(
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize()
        ) {
            when (activeMode) {
                0 -> {
                    item {
                        GradientFeatureCard(accent = accents.violet, modifier = Modifier.fillMaxWidth()) {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                ColourfulStatusPill(
                                    label = "ZERO-PERMISSION PHOTO PICKER",
                                    accent = accents.violet,
                                    icon = Icons.Default.PhotoLibrary
                                )
                                Text(
                                    text = "Picture EXIF & Polyglot Scanner",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Text(
                                    text = "Audits EXIF GPS leaks, software tags, XMP scripts, embedded QR payloads, and trailing steganography bytes after JPEG EOI / PNG IEND.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Button(
                                    onClick = {
                                        imagePicker.launch(
                                            PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                        )
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = accents.violet,
                                        contentColor = Color.White
                                    ),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(min = 48.dp)
                                        .testTag("pick_image_scan_button")
                                ) {
                                    Icon(Icons.Default.PhotoLibrary, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Select Picture to Scan Metadata")
                                }
                            }
                        }
                    }

                    if (imageScanResult != null) {
                        item {
                            ImageScanResultCard(
                                result = imageScanResult,
                                onStripMetadata = onStripImageMetadata
                            )
                        }
                    }
                }

                1 -> {
                    item {
                        GradientFeatureCard(accent = accents.cyan, modifier = Modifier.fillMaxWidth()) {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                ColourfulStatusPill(
                                    label = "ZXING QR + PAYLOAD SHIELD",
                                    accent = accents.cyan,
                                    icon = Icons.Default.QrCodeScanner
                                )
                                Text(
                                    text = "QR Code Metadata & Exploit Scanner",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Text(
                                    text = "Decodes QR images or inspects raw QR payloads for javascript:/intent:// schemes, homoglyph domains (xn--), raw IPs, and hidden Unicode.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Button(
                                    onClick = {
                                        qrImagePicker.launch(
                                            PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                        )
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = accents.cyan,
                                        contentColor = Color(0xFF061022)
                                    ),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(min = 48.dp)
                                        .testTag("pick_qr_image_button")
                                ) {
                                    Icon(Icons.Default.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Scan QR From Image")
                                }
                                OutlinedTextField(
                                    value = qrInput,
                                    onValueChange = { qrInput = it },
                                    placeholder = { Text("Or paste QR URL / payload string...") },
                                    singleLine = false,
                                    maxLines = 3,
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .testTag("qr_payload_input")
                                )
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Button(
                                        onClick = { onInspectQrText(qrInput) },
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = accents.emerald,
                                            contentColor = Color(0xFF061022)
                                        ),
                                        modifier = Modifier
                                            .weight(1f)
                                            .heightIn(min = 48.dp)
                                            .testTag("inspect_qr_text_button")
                                    ) {
                                        Text("Inspect QR Payload")
                                    }
                                }
                                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    item {
                                        QuickSampleChip("Test Punycode Phish", accents.amber) {
                                            val sample = "https://xn--pypal-4ve.com/login?verify=1"
                                            qrInput = sample
                                            onInspectQrText(sample)
                                        }
                                    }
                                    item {
                                        QuickSampleChip("Test Script URI", accents.coral) {
                                            val sample = "javascript:eval(document.cookie)"
                                            qrInput = sample
                                            onInspectQrText(sample)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (qrScanResult != null) {
                        item {
                            QrScanResultCard(result = qrScanResult)
                        }
                    }
                }

                2 -> {
                    item {
                        GradientFeatureCard(accent = accents.amber, modifier = Modifier.fillMaxWidth()) {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                ColourfulStatusPill(
                                    label = "UNICODE & EMOJI FORENSICS",
                                    accent = accents.amber,
                                    icon = Icons.Default.EmojiEmotions
                                )
                                Text(
                                    text = "Malformed Emoji & Unicode Scanner",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Text(
                                    text = "Detects unpaired UTF-16 surrogates, ZWJ emoji crash bombs, Bidi RLO filename spoofing (U+202E), Zalgo floods, and invisible zero-width steganography.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                OutlinedTextField(
                                    value = emojiInput,
                                    onValueChange = { emojiInput = it },
                                    placeholder = { Text("Paste suspicious emojis, message, or filename...") },
                                    maxLines = 4,
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .testTag("emoji_scan_input")
                                )
                                Button(
                                    onClick = { onScanEmojiText(emojiInput) },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = accents.amber,
                                        contentColor = Color(0xFF061022)
                                    ),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .heightIn(min = 48.dp)
                                        .testTag("scan_emoji_button")
                                ) {
                                    Text("Scan Emoji & Unicode Metadata")
                                }
                                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    item {
                                        QuickSampleChip("Bidi RLO Spoof", accents.coral) {
                                            val sample = "invoice_\u202Ecod.apk"
                                            emojiInput = sample
                                            onScanEmojiText(sample)
                                        }
                                    }
                                    item {
                                        QuickSampleChip("Broken Surrogate Emoji", accents.magenta) {
                                            val sample = "Alert \uD83D test \uDE00\u200B\u200B\uFEFF"
                                            emojiInput = sample
                                            onScanEmojiText(sample)
                                        }
                                    }
                                    item {
                                        QuickSampleChip("ZWJ Crash Bomb", accents.violet) {
                                            val sample = "🧑\u200D🧑\u200D🧑\u200D🧑\u200D🧑\u200D🧑"
                                            emojiInput = sample
                                            onScanEmojiText(sample)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (emojiScanResult != null) {
                        item {
                            EmojiScanResultCard(
                                result = emojiScanResult,
                                onCopySanitized = {
                                    clipboardManager.setText(AnnotatedString(emojiScanResult.sanitizedText))
                                }
                            )
                        }
                    }
                }
            }

            if (scanReports.isNotEmpty()) {
                item {
                    Text(
                        text = "Recent Scan Reports",
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(top = 6.dp)
                    )
                }
                items(scanReports.take(8), key = { it.id }) { report ->
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.surfaceContainer,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(12.dp)
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "${report.scanType.replace('_', ' ')}: ${report.targetLabel}",
                                    style = MaterialTheme.typography.titleSmall,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${report.summary} • ${formatTimestamp(report.timestamp)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            SeverityBadge(severity = report.threatLevel)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ScannerModeTab(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    selected: Boolean,
    accent: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = if (selected) accent.copy(alpha = 0.2f) else MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, if (selected) accent else MaterialTheme.colorScheme.outlineVariant),
        modifier = modifier.heightIn(min = 48.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 8.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(5.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelLarge,
                color = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1
            )
        }
    }
}

@Composable
private fun QuickSampleChip(
    label: String,
    accent: Color,
    onClick: () -> Unit
) {
    OutlinedButton(
        onClick = onClick,
        border = BorderStroke(1.dp, accent.copy(alpha = 0.55f)),
        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
        modifier = Modifier.heightIn(min = 40.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = accent
        )
    }
}

@Composable
private fun ImageScanResultCard(
    result: ImageScanResult,
    onStripMetadata: () -> Unit
) {
    val accents = LocalNetShieldColors.current
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(14.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = result.fileName,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "${result.dimensions} • ${formatBytes(result.fileSizeBytes.toLong())}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                SeverityBadge(severity = result.threatLevel)
            }

            FindingsList(findings = result.findings)

            if (result.exifFields.isNotEmpty()) {
                Text(
                    text = "Extracted EXIF / Chunk Fields",
                    style = MaterialTheme.typography.labelLarge,
                    color = accents.cyan
                )
                result.exifFields.forEach { (k, v) ->
                    Text(
                        text = "$k: $v",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            OutlinedButton(
                onClick = onStripMetadata,
                border = BorderStroke(1.dp, accents.emerald),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag("strip_exif_button")
            ) {
                Icon(Icons.Default.CleaningServices, contentDescription = null, tint = accents.emerald, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Strip EXIF & Save Sanitized Copy", color = accents.emerald)
            }
        }
    }
}

@Composable
private fun QrScanResultCard(result: QrScanResult) {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(14.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = result.payloadType, style = MaterialTheme.typography.titleSmall)
                SeverityBadge(severity = result.threatLevel)
            }
            Text(
                text = result.rawPayload,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            FindingsList(findings = result.findings)
        }
    }
}

@Composable
private fun EmojiScanResultCard(
    result: EmojiScanResult,
    onCopySanitized: () -> Unit
) {
    val accents = LocalNetShieldColors.current
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(14.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "${result.codePointCount} code points (${result.originalLength} UTF-16 units)",
                    style = MaterialTheme.typography.titleSmall
                )
                SeverityBadge(severity = result.threatLevel)
            }

            FindingsList(findings = result.findings)

            Surface(
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, accents.emerald.copy(alpha = 0.4f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(10.dp)
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "SANITIZED SAFE OUTPUT",
                            style = MaterialTheme.typography.labelSmall,
                            color = accents.emerald,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = result.sanitizedText.ifBlank { "(empty)" },
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                    OutlinedButton(
                        onClick = onCopySanitized,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.heightIn(min = 40.dp)
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = "Copy sanitized text", modifier = Modifier.size(16.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun FindingsList(findings: List<MetadataFinding>) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        findings.forEach { finding ->
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.surface.copy(alpha = 0.7f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = finding.title,
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        SeverityBadge(severity = finding.severity)
                    }
                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        text = finding.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}
