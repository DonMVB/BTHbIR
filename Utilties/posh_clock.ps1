# ASCII Time Display Script (UTF-8 safe)
# - IMPORTANT: Save this file as UTF-8 with BOM
# - Recommended console: Windows Terminal or Console using a font that supports block glyphs (Consolas, Lucida Console, Cascadia Code)
# - This script forces PowerShell/Console output to UTF-8 and uses an explicit Unicode fallback for the block glyph.

# Ensure console and PowerShell output use UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Define explicit block character fallback
$Block = [char]0x2588

# Define array of bright colors for "Current Time" header
$BrightColors = @(
    "Yellow", "White", "Gray", "Cyan", "Magenta", "Red", "Green", "Blue",
    "DarkYellow", "DarkCyan", "DarkMagenta", "DarkRed", "DarkGreen", "DarkBlue",
    "DarkGray", "Yellow", "Cyan", "Magenta", "White", "Gray",
    "Yellow", "Cyan", "White", "Magenta", "Gray", "Yellow",
    "Cyan", "White", "Magenta", "Gray"
)

# Define ASCII art for digits 0-9 and colon (use placeholder '█' here but we'll normalize at runtime)
$ASCIIDigits = @{

    '0' = @(
        "  ███    ",
        " █   █   ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        " █   █   ",
        "  ███    ",
        "         "
    )

    '1' = @(
        "   █     ",
        "  ██     ",
        " █ █     ",
        "   █     ",
        "   █     ",
        "   █     ",
        "   █     ",
        "   █     ",
        "   █     ",
        "   █     ",
        " █████   ",
        "         "
    )

    '2' = @(
        " █████   ",
        "█     █  ",
        "      █  ",
        "      █  ",
        "     █   ",
        "    █    ",
        "   █     ",
        "  █      ",
        " █       ",
        "█        ",
        "███████  ",
        "         "
    )

    '3' = @(
        " █████   ",
        "█     █  ",
        "      █  ",
        "      █  ",
        " █████   ",
        "      █  ",
        "      █  ",
        "      █  ",
        "      █  ",
        "█     █  ",
        " █████   ",
        "         "
    )

    '4' = @(
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "███████  ",
        "      █  ",
        "      █  ",
        "      █  ",
        "      █  ",
        "      █  ",
        "      █  ",
        "         "
    )

    '5' = @(
        "███████  ",
        "█        ",
        "█        ",
        "█        ",
        "██████   ",
        "      █  ",
        "      █  ",
        "      █  ",
        "      █  ",
        "█     █  ",
        " █████   ",
        "         "
    )

    '6' = @(
        " █████   ",
        "█     █  ",
        "█        ",
        "█        ",
        "██████   ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        " █████   ",
        "         "
    )
    '7' = @(
        "███████  ",
        "      █  ",
        "     █   ",
        "    █    ",
        "   █     ",
        "  █      ",
        " █       ",
        "█        ",
        "█        ",
        "█        ",
        "█        ",
        "         "
    )

    '8' = @(
        " █████   ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        " █████   ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        " █████   ",
        "         "
    )

    '9' = @(
        " █████   ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        "█     █  ",
        " ██████  ",
        "      █  ",
        "      █  ",
        "█     █  ",
        " █████   ",
        "         "
    )

    ':' = @(
        "         ",
        "         ",
        "   ██    ",
        "   ██    ",
        "         ",
        "         ",
        "         ",
        "   ██    ",
        "   ██    ",
        "         ",
        "         ",
        "         "
    )

}

function Get-TimeColor {
    param([int]$Minutes)

    if ($Minutes -eq 0) {
        return "Green"  # On the hour
    }
    elseif ($Minutes -ge 55) {
        return "Yellow"  # Last 5 minutes of hour
    }
    else {
        return "White"  # All other times
    }
}

function Normalize-AsciiLines {
    param(
        [string[]]$Lines,
        [char]$BlockChar
    )
    # Replace any literal '█' in the source lines with our explicit $BlockChar
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $Lines[$i] = $Lines[$i] -replace '█', $BlockChar
    }
    return ,$Lines
}

function Draw-TimeASCII {
    param(
        [string]$TimeString,
        [string]$Color
    )

    # Convert time string to array of characters
    $chars = $TimeString.ToCharArray()

    # Create array to hold each row of the combined ASCII art
    $combinedRows = @("", "", "", "", "", "", "", "", "", "", "", "")

    # Build each row by concatenating characters horizontally
    for ($row = 0; $row -lt 12; $row++) {
        foreach ($char in $chars) {
            # Fetch the source line
            $sourceLine = $ASCIIDigits[$char.ToString()][$row]
            # Normalize any block placeholders to the explicit block glyph
            $sourceLine = $sourceLine -replace '█', $Block
            $combinedRows[$row] += $sourceLine
        }
    }

    # Output with color
    foreach ($row in $combinedRows) {
        switch ($Color) {
            "Green"  { Write-Host $row -ForegroundColor Green; break }
            "Yellow" { Write-Host $row -ForegroundColor Yellow; break }
            default  { Write-Host $row -ForegroundColor White; break }
        }
    }
}

# Main loop

Write-Host "ASCII Time Display - Press Ctrl+C to exit" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan

$lastMinute = -1

while ($true) {
    $currentTime = Get-Date
    $currentMinute = $currentTime.Minute

    # Only update display when minute changes
    if ($currentMinute -ne $lastMinute) {
        Clear-Host

        # Format time as HH:MM
        $timeString = $currentTime.ToString("HH:mm")

        # Determine color based on minutes
        $color = Get-TimeColor -Minutes $currentMinute

        # Display header
        Write-Host ""
        $headerColor = $BrightColors | Get-Random
        Write-Host "Current Time: $timeString" -ForegroundColor $headerColor
        Write-Host ("=" * 50) -ForegroundColor Cyan
        Write-Host ""

        # Draw ASCII time
        Draw-TimeASCII -TimeString $timeString -Color $color

        # Display bottom line
        Write-Host ("=" * 50) -ForegroundColor Cyan

        # Display status
        Write-Host ""

        if ($currentMinute -eq 0) {
            Write-Host "ON THE HOUR!" -ForegroundColor Green
        }
        elseif ($currentMinute -ge 55) {
            Write-Host "LAST 5 MINUTES OF HOUR" -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "Press Ctrl+C to exit" -ForegroundColor Gray
        $lastMinute = $currentMinute

    }

    # Sleep before checking again
    Start-Sleep -Seconds 30
}
