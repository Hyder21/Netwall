package com.example.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.ui.theme.LocalNetShieldColors
import com.example.ui.viewmodel.TrafficSample
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun NetShieldLogoBadge(
    isActive: Boolean,
    size: Dp = 76.dp,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    val transition = rememberInfiniteTransition(label = "shield_pulse")
    val pulse by transition.animateFloat(
        initialValue = 0.85f,
        targetValue = 1.15f,
        animationSpec = infiniteRepeatable(
            animation = tween(1600, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )
    val sweep by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(4200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "sweep"
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier.size(size)
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val center = Offset(this.size.width / 2f, this.size.height / 2f)
            val baseRadius = this.size.minDimension * 0.44f
            if (isActive) {
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            accents.cyan.copy(alpha = 0.32f),
                            accents.violet.copy(alpha = 0.14f),
                            Color.Transparent
                        ),
                        center = center,
                        radius = baseRadius * pulse * 1.18f
                    ),
                    radius = baseRadius * pulse * 1.18f,
                    center = center
                )
                drawArc(
                    brush = Brush.sweepGradient(
                        colors = listOf(accents.cyan, accents.emerald, accents.violet, accents.cyan),
                        center = center
                    ),
                    startAngle = sweep,
                    sweepAngle = 240f,
                    useCenter = false,
                    style = Stroke(width = 3.5.dp.toPx(), cap = StrokeCap.Round)
                )
            } else {
                drawCircle(
                    color = accents.amber.copy(alpha = 0.4f),
                    radius = baseRadius,
                    center = center,
                    style = Stroke(width = 2.5.dp.toPx())
                )
            }
        }

        Image(
            painter = painterResource(id = R.drawable.netshield_icon_1794580913324),
            contentDescription = stringResource(id = R.string.cd_shield_logo),
            contentScale = ContentScale.Crop,
            modifier = Modifier
                .size(size * 0.74f)
                .clip(CircleShape)
                .border(
                    width = 1.5.dp,
                    color = if (isActive) accents.cyan else accents.amber,
                    shape = CircleShape
                )
        )
    }
}

@Composable
fun ColourfulStatusPill(
    label: String,
    accent: Color,
    icon: ImageVector? = null,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(50),
        color = accent.copy(alpha = 0.16f),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.45f)),
        modifier = modifier
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
        ) {
            if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(modifier = Modifier.width(5.dp))
            }
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = accent,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun SeverityBadge(severity: String, modifier: Modifier = Modifier) {
    val accents = LocalNetShieldColors.current
    val (color, icon) = when (severity.uppercase()) {
        "CRITICAL" -> accents.coral to Icons.Default.Error
        "HIGH", "WARNING" -> accents.amber to Icons.Default.Warning
        "MEDIUM" -> accents.violet to Icons.Default.Shield
        "CLEAN" -> accents.emerald to Icons.Default.CheckCircle
        else -> accents.cyan to Icons.Default.Info
    }
    ColourfulStatusPill(
        label = severity.uppercase(),
        accent = color,
        icon = icon,
        modifier = modifier
    )
}

@Composable
fun LiveTrafficSparkline(
    samples: List<TrafficSample>,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    val maxRate = (samples.maxOfOrNull { maxOf(it.rxBytesPerSec, it.txBytesPerSec) } ?: 1024L)
        .coerceAtLeast(1024L)
    val latestRx = samples.lastOrNull()?.rxBytesPerSec ?: 0L
    val latestTx = samples.lastOrNull()?.txBytesPerSec ?: 0L

    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "LIVE NETWORK THROUGHPUT",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Real-Time TrafficStats Monitor",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ColourfulStatusPill(
                        label = "↓ ${formatRate(latestRx)}",
                        accent = accents.cyan
                    )
                    ColourfulStatusPill(
                        label = "↑ ${formatRate(latestTx)}",
                        accent = accents.magenta
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(84.dp)
            ) {
                val w = size.width
                val h = size.height

                // Grid lines
                for (i in 1..3) {
                    val y = h * (i / 4f)
                    drawLine(
                        color = Color.Gray.copy(alpha = 0.16f),
                        start = Offset(0f, y),
                        end = Offset(w, y),
                        strokeWidth = 1.dp.toPx()
                    )
                }

                if (samples.size >= 2) {
                    val stepX = w / (samples.size - 1).coerceAtLeast(1)

                    fun drawSeries(selector: (TrafficSample) -> Long, lineColor: Color) {
                        val path = Path()
                        val fillPath = Path()
                        samples.forEachIndexed { idx, s ->
                            val x = idx * stepX
                            val ratio = (selector(s).toFloat() / maxRate.toFloat()).coerceIn(0f, 1f)
                            val y = h - (ratio * (h - 8.dp.toPx())) - 4.dp.toPx()
                            if (idx == 0) {
                                path.moveTo(x, y)
                                fillPath.moveTo(x, h)
                                fillPath.lineTo(x, y)
                            } else {
                                path.lineTo(x, y)
                                fillPath.lineTo(x, y)
                            }
                        }
                        fillPath.lineTo((samples.size - 1) * stepX, h)
                        fillPath.close()

                        drawPath(
                            path = fillPath,
                            brush = Brush.verticalGradient(
                                colors = listOf(lineColor.copy(alpha = 0.25f), Color.Transparent)
                            )
                        )
                        drawPath(
                            path = path,
                            color = lineColor,
                            style = Stroke(
                                width = 2.5.dp.toPx(),
                                cap = StrokeCap.Round,
                                join = StrokeJoin.Round
                            )
                        )
                    }

                    drawSeries({ it.rxBytesPerSec }, accents.cyan)
                    drawSeries({ it.txBytesPerSec }, accents.magenta)
                }
            }
        }
    }
}

fun formatRate(bytesPerSec: Long): String {
    return when {
        bytesPerSec >= 1024 * 1024 -> String.format(Locale.US, "%.1f MB/s", bytesPerSec / (1024f * 1024f))
        bytesPerSec >= 1024 -> String.format(Locale.US, "%.1f KB/s", bytesPerSec / 1024f)
        else -> "$bytesPerSec B/s"
    }
}

fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1024L * 1024L * 1024L -> String.format(Locale.US, "%.2f GB", bytes / (1024f * 1024f * 1024f))
        bytes >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes / (1024f * 1024f))
        bytes >= 1024L -> String.format(Locale.US, "%.1f KB", bytes / 1024f)
        else -> "$bytes B"
    }
}

fun formatTimestamp(millis: Long): String {
    return SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(millis))
}

@Composable
fun GradientFeatureCard(
    accent: Color,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    Surface(
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, accent.copy(alpha = 0.35f)),
        modifier = modifier
    ) {
        Box(
            modifier = Modifier
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            accent.copy(alpha = 0.14f),
                            Color.Transparent
                        )
                    )
                )
                .padding(14.dp)
        ) {
            content()
        }
    }
}
