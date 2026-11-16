package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.db.EventCategory
import com.example.data.db.ScanReportEntity
import com.example.data.db.ScanType
import com.example.data.db.SecurityEventEntity
import com.example.ui.components.ColourfulStatusPill
import com.example.ui.components.GradientFeatureCard
import com.example.ui.components.SeverityBadge
import com.example.ui.components.formatTimestamp
import com.example.ui.theme.LocalNetShieldColors
import com.example.vpn.VpnTunnelStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

private enum class ThreatWindow(val label: String, val durationMs: Long, val buckets: Int) {
    LIVE_15M("15m Live", 15 * 60_000L, 6),
    HOUR_1("1 Hour", 60 * 60_000L, 6),
    DAY_24H("24 Hours", 24 * 60 * 60_000L, 6),
    ALL("All Time", Long.MAX_VALUE, 6)
}

private data class ThreatTimeBucket(
    val label: String,
    val blockedConnections: Int,
    val metadataThreats: Int
)

private data class VectorBarDatum(
    val label: String,
    val count: Int,
    val color: Color
)

private data class DonutSlice(
    val label: String,
    val count: Int,
    val color: Color
)

@Composable
fun ThreatDashboardScreen(
    vpnStatus: VpnTunnelStatus,
    securityEvents: List<SecurityEventEntity>,
    scanReports: List<ScanReportEntity>,
    onNavigateToTraffic: () -> Unit,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    var selectedWindow by remember { mutableStateOf(ThreatWindow.HOUR_1) }
    var selectedBucketIndex by remember { mutableIntStateOf(-1) }
    var selectedBarIndex by remember { mutableIntStateOf(-1) }

    val now = System.currentTimeMillis()
    val cutoff = if (selectedWindow == ThreatWindow.ALL) 0L else now - selectedWindow.durationMs

    val windowEvents = remember(securityEvents, cutoff) {
        securityEvents.filter { it.timestamp >= cutoff }
    }
    val windowScans = remember(scanReports, cutoff) {
        scanReports.filter { it.timestamp >= cutoff }
    }

    val networkCategories = remember {
        setOf(
            EventCategory.PORT_SCAN.name,
            EventCategory.SNIFFING_ALERT.name,
            EventCategory.WIRELESS_SPOOFING.name,
            EventCategory.DATA_THEFT_APP.name,
            EventCategory.MALICIOUS_PAGE.name
        )
    }

    val blockedConnectionsCount = remember(windowEvents) {
        windowEvents.count { it.category in networkCategories }
    }
    val maliciousMetadataCount = remember(windowEvents, windowScans) {
        val evCount = windowEvents.count { it.category == EventCategory.METADATA_THREAT.name }
        val reportCount = windowScans.count { it.threatLevel != "CLEAN" }
        maxOf(evCount, reportCount)
    }
    val sniffSpoofCount = remember(windowEvents) {
        windowEvents.count {
            it.category == EventCategory.SNIFFING_ALERT.name ||
                it.category == EventCategory.WIRELESS_SPOOFING.name
        }
    }

    val buckets = remember(windowEvents, windowScans, selectedWindow) {
        buildTimeBuckets(windowEvents, windowScans, selectedWindow, now, networkCategories)
    }

    val vectorBars = remember(windowEvents, windowScans, accents) {
        listOf(
            VectorBarDatum(
                label = "Port Scan",
                count = windowEvents.count { it.category == EventCategory.PORT_SCAN.name },
                color = accents.emerald
            ),
            VectorBarDatum(
                label = "Local Net",
                count = windowEvents.count {
                    it.category == EventCategory.SNIFFING_ALERT.name ||
                        it.category == EventCategory.WIRELESS_SPOOFING.name
                },
                color = accents.coral
            ),
            VectorBarDatum(
                label = "App Theft",
                count = windowEvents.count { it.category == EventCategory.DATA_THEFT_APP.name },
                color = accents.amber
            ),
            VectorBarDatum(
                label = "Mal. Page",
                count = windowEvents.count { it.category == EventCategory.MALICIOUS_PAGE.name },
                color = accents.cyan
            ),
            VectorBarDatum(
                label = "Metadata",
                count = maxOf(
                    windowEvents.count { it.category == EventCategory.METADATA_THREAT.name },
                    windowScans.count { it.threatLevel != "CLEAN" }
                ),
                color = accents.violet
            )
        )
    }

    val severitySlices = remember(windowEvents, accents) {
        listOf(
            DonutSlice("CRITICAL", windowEvents.count { it.severity == "CRITICAL" }, accents.coral),
            DonutSlice("HIGH", windowEvents.count { it.severity == "HIGH" }, accents.amber),
            DonutSlice("MEDIUM", windowEvents.count { it.severity == "MEDIUM" }, accents.violet),
            DonutSlice("INFO", windowEvents.count { it.severity == "INFO" }, accents.cyan)
        ).filter { it.count > 0 }
    }

    val metadataSlices = remember(windowScans, accents) {
        val flagged = windowScans.filter { it.threatLevel != "CLEAN" }
        listOf(
            DonutSlice("Pictures", flagged.count { it.scanType == ScanType.IMAGE_EXIF.name }, accents.violet),
            DonutSlice("QR Codes", flagged.count { it.scanType == ScanType.QR_CODE.name }, accents.cyan),
            DonutSlice("Emojis", flagged.count { it.scanType == ScanType.EMOJI_UNICODE.name }, accents.amber)
        ).filter { it.count > 0 }
    }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        modifier = modifier.fillMaxSize()
    ) {
        // Header + Time Range Selector
        item {
            GradientFeatureCard(accent = accents.coral, modifier = Modifier.fillMaxWidth()) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        ColourfulStatusPill(
                            label = if (vpnStatus.isRunning) "REAL-TIME TELEMETRY" else "TELEMETRY STANDBY",
                            accent = if (vpnStatus.isRunning) accents.emerald else accents.amber,
                            icon = Icons.Default.Analytics
                        )
                        ColourfulStatusPill(
                            label = "${vpnStatus.packetsInspected} PKTS",
                            accent = accents.cyan
                        )
                    }
                    Text(
                        text = "Threat Dashboard",
                        style = MaterialTheme.typography.headlineSmall
                    )
                    Text(
                        text = "Visualizing real-time blocked network connections, local network issues, and malicious QR, image & emoji metadata attempts.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(ThreatWindow.entries) { window ->
                            FilterChip(
                                selected = selectedWindow == window,
                                onClick = {
                                    selectedWindow = window
                                    selectedBucketIndex = -1
                                },
                                label = { Text(window.label) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = accents.cyan.copy(alpha = 0.22f),
                                    selectedLabelColor = accents.cyan
                                ),
                                modifier = Modifier.testTag("threat_window_${window.name.lowercase()}")
                            )
                        }
                    }
                }
            }
        }

        // KPI Row
        item {
            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                ThreatKpiTile(
                    title = "Blocked Net",
                    value = "$blockedConnectionsCount",
                    icon = Icons.Default.GppBad,
                    accent = accents.coral,
                    modifier = Modifier.weight(1f)
                )
                ThreatKpiTile(
                    title = "Metadata",
                    value = "$maliciousMetadataCount",
                    icon = Icons.Default.QrCodeScanner,
                    accent = accents.violet,
                    modifier = Modifier.weight(1f)
                )
                ThreatKpiTile(
                    title = "Local Issues",
                    value = "$sniffSpoofCount",
                    icon = Icons.Default.Security,
                    accent = accents.amber,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Chart 1: Multi-Series Area Chart (Blocked Network vs Malicious Metadata)
        item {
            ThreatTimelineAreaChart(
                buckets = buckets,
                selectedIndex = selectedBucketIndex,
                onSelectIndex = { selectedBucketIndex = it },
                netColor = accents.coral,
                metaColor = accents.violet
            )
        }

        // Chart 2: Attack Vector Breakdown Bar Chart
        item {
            AttackVectorBarChart(
                bars = vectorBars,
                selectedBarIndex = selectedBarIndex,
                onSelectBar = { idx ->
                    selectedBarIndex = if (selectedBarIndex == idx) -1 else idx
                }
            )
        }

        // Chart 3: Dual Donut Breakdown (Severity & Metadata Channel)
        item {
            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                ThreatDonutCard(
                    title = "By Severity",
                    slices = severitySlices,
                    emptyText = "No events",
                    modifier = Modifier.weight(1f)
                )
                ThreatDonutCard(
                    title = "Metadata Risks",
                    slices = metadataSlices,
                    emptyText = "All clean",
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Recent Flagged Detections Header
        item {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Latest Blocked Attempts",
                    style = MaterialTheme.typography.titleMedium
                )
                ColourfulStatusPill(
                    label = "Full Log →",
                    accent = accents.cyan,
                    modifier = Modifier
                        .pointerInput(Unit) {
                            detectTapGestures { onNavigateToTraffic() }
                        }
                        .testTag("threat_dashboard_to_log")
                )
            }
        }

        val highlighted = windowEvents.filter { it.severity != "INFO" }.ifEmpty { windowEvents }
        if (highlighted.isEmpty()) {
            item {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.surfaceContainer,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(16.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.BugReport,
                            contentDescription = null,
                            tint = accents.emerald,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = "No blocked connections or malicious metadata detected in this time window.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            items(highlighted.take(6), key = { it.id }) { ev ->
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
                                text = ev.title,
                                style = MaterialTheme.typography.titleSmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "${ev.source} → ${ev.target} • ${formatTimestamp(ev.timestamp)}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        SeverityBadge(severity = ev.severity)
                    }
                }
            }
        }
    }
}

@Composable
private fun ThreatKpiTile(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accent: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, accent.copy(alpha = 0.4f)),
        modifier = modifier
    ) {
        Column(
            horizontalAlignment = Alignment.Start,
            modifier = Modifier.padding(12.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = accent,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = value,
                style = MaterialTheme.typography.headlineSmall,
                color = accent,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = title,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1
            )
        }
    }
}

@Composable
private fun ThreatTimelineAreaChart(
    buckets: List<ThreatTimeBucket>,
    selectedIndex: Int,
    onSelectIndex: (Int) -> Unit,
    netColor: Color,
    metaColor: Color
) {
    val maxVal = (buckets.maxOfOrNull { maxOf(it.blockedConnections, it.metadataThreats) } ?: 1)
        .coerceAtLeast(1)

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("threat_area_chart")
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Blocked Connections vs. Metadata Threats",
                        style = MaterialTheme.typography.titleSmall
                    )
                    Text(
                        text = "Tap chart points to inspect bucket telemetry",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                LegendDot("Blocked Net", netColor)
                LegendDot("Metadata Threats", metaColor)
            }

            if (selectedIndex in buckets.indices) {
                val b = buckets[selectedIndex]
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surface,
                    border = BorderStroke(1.dp, netColor.copy(alpha = 0.45f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                    ) {
                        Text(b.label, style = MaterialTheme.typography.labelMedium)
                        Text(
                            text = "Net: ${b.blockedConnections}  •  Meta: ${b.metadataThreats}",
                            style = MaterialTheme.typography.labelMedium,
                            color = netColor,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                // Y-axis scale labels
                Column(
                    verticalArrangement = Arrangement.SpaceBetween,
                    horizontalAlignment = Alignment.End,
                    modifier = Modifier
                        .height(140.dp)
                        .padding(end = 6.dp)
                ) {
                    Text("$maxVal", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("${(maxVal / 2f).roundToInt()}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("0", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }

                Canvas(
                    modifier = Modifier
                        .weight(1f)
                        .height(140.dp)
                        .pointerInput(buckets) {
                            detectTapGestures { offset ->
                                if (buckets.size > 1) {
                                    val idx = ((offset.x / size.width) * (buckets.size - 1))
                                        .roundToInt()
                                        .coerceIn(0, buckets.lastIndex)
                                    onSelectIndex(idx)
                                }
                            }
                        }
                ) {
                    val w = size.width
                    val h = size.height
                    val topPad = 8.dp.toPx()
                    val usableH = h - topPad * 2

                    // Dashed Cartesian gridlines
                    val dash = PathEffect.dashPathEffect(floatArrayOf(8f, 8f), 0f)
                    for (i in 0..2) {
                        val y = topPad + usableH * (i / 2f)
                        drawLine(
                            color = Color.Gray.copy(alpha = 0.22f),
                            start = Offset(0f, y),
                            end = Offset(w, y),
                            strokeWidth = 1.dp.toPx(),
                            pathEffect = dash
                        )
                    }

                    if (buckets.size >= 2) {
                        val stepX = w / (buckets.size - 1)

                        fun drawAreaSeries(selector: (ThreatTimeBucket) -> Int, color: Color) {
                            val linePath = Path()
                            val areaPath = Path()
                            val pts = buckets.mapIndexed { idx, bucket ->
                                val x = idx * stepX
                                val y = topPad + usableH * (1f - (selector(bucket).toFloat() / maxVal.toFloat()).coerceIn(0f, 1f))
                                Offset(x, y)
                            }
                            pts.forEachIndexed { idx, p ->
                                if (idx == 0) {
                                    linePath.moveTo(p.x, p.y)
                                    areaPath.moveTo(p.x, h)
                                    areaPath.lineTo(p.x, p.y)
                                } else {
                                    val prev = pts[idx - 1]
                                    val cx = (prev.x + p.x) / 2f
                                    linePath.cubicTo(cx, prev.y, cx, p.y, p.x, p.y)
                                    areaPath.cubicTo(cx, prev.y, cx, p.y, p.x, p.y)
                                }
                            }
                            areaPath.lineTo(pts.last().x, h)
                            areaPath.close()

                            drawPath(
                                path = areaPath,
                                brush = Brush.verticalGradient(
                                    colors = listOf(color.copy(alpha = 0.34f), Color.Transparent)
                                )
                            )
                            drawPath(
                                path = linePath,
                                color = color,
                                style = Stroke(
                                    width = 2.6.dp.toPx(),
                                    cap = StrokeCap.Round,
                                    join = StrokeJoin.Round
                                )
                            )
                            pts.forEachIndexed { idx, p ->
                                val r = if (idx == selectedIndex) 5.5.dp.toPx() else 3.2.dp.toPx()
                                drawCircle(color = color, radius = r, center = p)
                            }
                        }

                        drawAreaSeries({ it.blockedConnections }, netColor)
                        drawAreaSeries({ it.metadataThreats }, metaColor)

                        if (selectedIndex in buckets.indices) {
                            val sx = selectedIndex * stepX
                            drawLine(
                                color = Color.White.copy(alpha = 0.45f),
                                start = Offset(sx, 0f),
                                end = Offset(sx, h),
                                strokeWidth = 1.2.dp.toPx()
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(6.dp))
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 24.dp)
            ) {
                buckets.forEach { b ->
                    Text(
                        text = b.label,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1
                    )
                }
            }
        }
    }
}

@Composable
private fun AttackVectorBarChart(
    bars: List<VectorBarDatum>,
    selectedBarIndex: Int,
    onSelectBar: (Int) -> Unit
) {
    val maxCount = (bars.maxOfOrNull { it.count } ?: 1).coerceAtLeast(1)

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("threat_bar_chart")
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Attack Vector Distribution",
                    style = MaterialTheme.typography.titleSmall
                )
                if (selectedBarIndex in bars.indices) {
                    val b = bars[selectedBarIndex]
                    ColourfulStatusPill(label = "${b.label}: ${b.count}", accent = b.color)
                }
            }
            Spacer(modifier = Modifier.height(12.dp))

            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(118.dp)
                    .pointerInput(bars) {
                        detectTapGestures { offset ->
                            if (bars.isNotEmpty()) {
                                val slotW = size.width / bars.size
                                val idx = (offset.x / slotW).toInt().coerceIn(0, bars.lastIndex)
                                onSelectBar(idx)
                            }
                        }
                    }
            ) {
                val slotW = size.width / bars.size.coerceAtLeast(1)
                val barW = slotW * 0.52f
                val maxBarH = size.height - 12.dp.toPx()

                bars.forEachIndexed { idx, bar ->
                    val ratio = (bar.count.toFloat() / maxCount.toFloat()).coerceIn(0f, 1f)
                    val barH = (ratio * maxBarH).coerceAtLeast(if (bar.count > 0) 10.dp.toPx() else 4.dp.toPx())
                    val left = idx * slotW + (slotW - barW) / 2f
                    val top = size.height - barH

                    drawRoundRect(
                        color = bar.color.copy(alpha = if (selectedBarIndex == -1 || selectedBarIndex == idx) 0.92f else 0.35f),
                        topLeft = Offset(left, top),
                        size = Size(barW, barH),
                        cornerRadius = CornerRadius(8.dp.toPx(), 8.dp.toPx())
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Row(
                horizontalArrangement = Arrangement.SpaceAround,
                modifier = Modifier.fillMaxWidth()
            ) {
                bars.forEach { bar ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "${bar.count}",
                            style = MaterialTheme.typography.labelMedium,
                            color = bar.color,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = bar.label,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ThreatDonutCard(
    title: String,
    slices: List<DonutSlice>,
    emptyText: String,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    val total = slices.sumOf { it.count }

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = modifier
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(12.dp)
        ) {
            Text(text = title, style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(10.dp))

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(92.dp)
            ) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val stroke = Stroke(width = 14.dp.toPx(), cap = StrokeCap.Butt)
                    if (total == 0) {
                        drawArc(
                            color = accents.emerald.copy(alpha = 0.25f),
                            startAngle = 0f,
                            sweepAngle = 360f,
                            useCenter = false,
                            style = stroke
                        )
                    } else {
                        var start = -90f
                        slices.forEach { slice ->
                            val sweep = (slice.count.toFloat() / total.toFloat()) * 360f
                            drawArc(
                                color = slice.color,
                                startAngle = start,
                                sweepAngle = (sweep - 3f).coerceAtLeast(2f),
                                useCenter = false,
                                style = stroke
                            )
                            start += sweep
                        }
                    }
                }
                Text(
                    text = if (total == 0) emptyText else "$total",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(10.dp))
            Column(
                verticalArrangement = Arrangement.spacedBy(3.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (slices.isEmpty()) {
                    Text(
                        text = emptyText,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    slices.forEach { slice ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            LegendDot(slice.label, slice.color)
                            Text(
                                text = "${slice.count}",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LegendDot(label: String, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Surface(
            shape = CircleShape,
            color = color,
            modifier = Modifier.size(8.dp)
        ) {}
        Spacer(modifier = Modifier.width(5.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1
        )
    }
}

private fun buildTimeBuckets(
    events: List<SecurityEventEntity>,
    scans: List<ScanReportEntity>,
    window: ThreatWindow,
    now: Long,
    networkCategories: Set<String>
): List<ThreatTimeBucket> {
    val count = window.buckets
    val earliest = if (window == ThreatWindow.ALL) {
        val minEv = events.minOfOrNull { it.timestamp } ?: (now - 3600_000L)
        val minSc = scans.minOfOrNull { it.timestamp } ?: (now - 3600_000L)
        minOf(minEv, minSc).coerceAtMost(now - 60_000L)
    } else {
        now - window.durationMs
    }
    val span = (now - earliest).coerceAtLeast(60_000L)
    val step = span / count
    val fmt = SimpleDateFormat(if (span > 6 * 3600_000L) "HH:mm" else "HH:mm", Locale.getDefault())

    return (0 until count).map { idx ->
        val start = earliest + idx * step
        val end = if (idx == count - 1) now + 1L else start + step
        val netCount = events.count { it.timestamp in start until end && it.category in networkCategories }
        val metaEvCount = events.count { it.timestamp in start until end && it.category == EventCategory.METADATA_THREAT.name }
        val metaScanCount = scans.count { it.timestamp in start until end && it.threatLevel != "CLEAN" }
        ThreatTimeBucket(
            label = fmt.format(Date(end - 1L)),
            blockedConnections = netCount,
            metadataThreats = maxOf(metaEvCount, metaScanCount)
        )
    }
}
