package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Immutable
data class NetShieldAccentColors(
    val cyan: Color,
    val emerald: Color,
    val coral: Color,
    val amber: Color,
    val violet: Color,
    val magenta: Color,
    val indigo: Color,
    val cardGradientStart: Color,
    val cardGradientEnd: Color,
    val isDark: Boolean
)

val LocalNetShieldColors = staticCompositionLocalOf {
    NetShieldAccentColors(
        cyan = ElectricCyan,
        emerald = EmeraldSafe,
        coral = CoralThreat,
        amber = AmberWarn,
        violet = VividViolet,
        magenta = MagentaPulse,
        indigo = IndigoAccent,
        cardGradientStart = ShieldCardDark,
        cardGradientEnd = ShieldCardElevated,
        isDark = true
    )
}

private val NetShieldDarkColorScheme = darkColorScheme(
    primary = ElectricCyan,
    onPrimary = ShieldMidnight,
    primaryContainer = Color(0xFF004B66),
    onPrimaryContainer = Color(0xFFBDF4FF),
    secondary = VividViolet,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFF2D1B6E),
    onSecondaryContainer = Color(0xFFE3D8FF),
    tertiary = EmeraldSafe,
    onTertiary = ShieldMidnight,
    tertiaryContainer = Color(0xFF004D2A),
    onTertiaryContainer = Color(0xFFB8FFD8),
    error = CoralThreat,
    onError = Color.White,
    errorContainer = Color(0xFF5D0A26),
    onErrorContainer = Color(0xFFFFD6E1),
    background = ShieldMidnight,
    onBackground = TextPrimaryDark,
    surface = ShieldDeepNavy,
    onSurface = TextPrimaryDark,
    surfaceVariant = ShieldCardDark,
    onSurfaceVariant = TextSecondaryDark,
    surfaceContainerLowest = Color(0xFF060B18),
    surfaceContainerLow = ShieldDeepNavy,
    surfaceContainer = ShieldCardDark,
    surfaceContainerHigh = ShieldCardElevated,
    surfaceContainerHighest = Color(0xFF243763),
    outline = ShieldOutlineDark,
    outlineVariant = Color(0xFF1F3056)
)

private val NetShieldLightColorScheme = lightColorScheme(
    primary = DeepCyan,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD0F4FF),
    onPrimaryContainer = Color(0xFF002A3A),
    secondary = VividViolet,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFECE4FF),
    onSecondaryContainer = Color(0xFF230068),
    tertiary = EmeraldDeep,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFC8FFE0),
    onTertiaryContainer = Color(0xFF002B14),
    error = CrimsonDeep,
    onError = Color.White,
    errorContainer = Color(0xFFFFDCE5),
    onErrorContainer = Color(0xFF4D0019),
    background = PrismCanvasLight,
    onBackground = TextPrimaryLight,
    surface = PrismSurfaceLight,
    onSurface = TextPrimaryLight,
    surfaceVariant = PrismCardLight,
    onSurfaceVariant = TextSecondaryLight,
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF7F9FE),
    surfaceContainer = PrismCardLight,
    surfaceContainerHigh = Color(0xFFDFE8FA),
    surfaceContainerHighest = Color(0xFFD2DDF5),
    outline = PrismOutlineLight,
    outlineVariant = Color(0xFFDCE5F7)
)

val NetShieldShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(30.dp)
)

@Composable
fun NetShieldTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) NetShieldDarkColorScheme else NetShieldLightColorScheme
    val accentColors = if (darkTheme) {
        NetShieldAccentColors(
            cyan = ElectricCyan,
            emerald = EmeraldSafe,
            coral = CoralThreat,
            amber = AmberWarn,
            violet = VividViolet,
            magenta = MagentaPulse,
            indigo = IndigoAccent,
            cardGradientStart = ShieldCardDark,
            cardGradientEnd = ShieldCardElevated,
            isDark = true
        )
    } else {
        NetShieldAccentColors(
            cyan = DeepCyan,
            emerald = EmeraldDeep,
            coral = CrimsonDeep,
            amber = AmberDeep,
            violet = VividViolet,
            magenta = MagentaPulse,
            indigo = IndigoAccent,
            cardGradientStart = Color(0xFFFFFFFF),
            cardGradientEnd = Color(0xFFEAF1FF),
            isDark = false
        )
    }

    CompositionLocalProvider(LocalNetShieldColors provides accentColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = NetShieldTypography,
            shapes = NetShieldShapes,
            content = content
        )
    }
}
