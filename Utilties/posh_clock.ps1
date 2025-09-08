# ASCII Time Display Script
# Displays current time in ASCII art with color coding
 
# Define array of bright colors for "Current Time" header

$BrightColors = @(
    "Yellow", "White", "Gray", "Cyan", "Magenta", "Red", "Green", "Blue",
    "DarkYellow", "DarkCyan", "DarkMagenta", "DarkRed", "DarkGreen", "DarkBlue",
    "DarkGray", "Yellow", "Cyan", "Magenta", "White", "Gray",
    "Yellow", "Cyan", "White", "Magenta", "Gray", "Yellow",
    "Cyan", "White", "Magenta", "Gray"
)
 
# Define ASCII art for digits 0-9 and colon (with 2 extra spaces for separation)
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
            $combinedRows[$row] += $ASCIIDigits[$char.ToString()][$row]
        }
    }
  

    # Output with color
    foreach ($row in $combinedRows) {
        if ($Color -eq "Green") {
            Write-Host $row -ForegroundColor Green
       }
        elseif ($Color -eq "Yellow") {
           Write-Host $row -ForegroundColor Yellow
        }
        else {
            Write-Host $row -ForegroundColor White
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
   
    # Sleep for 1 second before checking again
    Start-Sleep -Seconds 30
}
