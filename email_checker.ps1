param (
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [Parameter(Mandatory = $true)]
    [string]$OutputFile
)

function Show-Banner {
    $banner = @"
=============================================================
  DKIM-DMARC-SPF-MX Checker por Alejandro Leon AKA GX 
  Uso etico y autorizado solamente 
=============================================================
"@
    Write-Host $banner -ForegroundColor Cyan
    $banner | Out-File -Append $OutputFile
}

function Check-SPF {
    $message = "Analizando SPF..."
    Write-Host $message -ForegroundColor Green
    $message | Out-File -Append $OutputFile
    try {
        $records = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction Stop
        $spf = $records | Where-Object { $_.Strings -match "^v=spf1" }
        if ($spf) {
            $spf | ForEach-Object { 
                $message = "SPF encontrado: $($_.Strings)"
                Write-Host $message -ForegroundColor Green
                $message | Out-File -Append $OutputFile
            }
        } else {
            $message = "SPF no encontrado."
            Write-Host $message -ForegroundColor Red
            $message | Out-File -Append $OutputFile
        }
    } catch {
        $message = "Error al buscar SPF: $_"
        Write-Host $message -ForegroundColor Red
        $message | Out-File -Append $OutputFile
    }
    $message = "`n============================================================="
    Write-Host $message -ForegroundColor Cyan
    $message | Out-File -Append $OutputFile
}

function Check-DKIM {
    $message = "Analizando DKIM..."
    Write-Host $message -ForegroundColor Green
    $message | Out-File -Append $OutputFile
    $selectors = @('default', 'selector1', 'selector2', 'mail')
    $found = $false

    foreach ($selector in $selectors) {
        $dkimDomain = "$selector._domainkey.$Domain"
        try {
            $record = Resolve-DnsName -Name $dkimDomain -Type TXT -ErrorAction Stop
            foreach ($entry in $record) {
                $message = "DKIM encontrado con selector '$selector': $($entry.Strings)"
                Write-Host $message -ForegroundColor Green
                $message | Out-File -Append $OutputFile
                $found = $true
            }
            break
        } catch {
            continue
        }
    }

    if (-not $found) {
        $message = "No se encontro DKIM con los selectores comunes."
        Write-Host $message -ForegroundColor Red
        $message | Out-File -Append $OutputFile
    }
    $message = "`n============================================================="
    Write-Host $message -ForegroundColor Cyan
    $message | Out-File -Append $OutputFile
}

function Check-DMARC {
    $message = "Analizando DMARC..."
    Write-Host $message -ForegroundColor Green
    $message | Out-File -Append $OutputFile
    $dmarcDomain = "_dmarc.$Domain"
    try {
        $record = Resolve-DnsName -Name $dmarcDomain -Type TXT -ErrorAction Stop
        foreach ($entry in $record) {
            $message = "DMARC encontrado: $($entry.Strings)"
            Write-Host $message -ForegroundColor Green
            $message | Out-File -Append $OutputFile
        }
    } catch {
        $message = "DMARC no encontrado o error: $_"
        Write-Host $message -ForegroundColor Red
        $message | Out-File -Append $OutputFile
    }
    $message = "`n============================================================="
    Write-Host $message -ForegroundColor Cyan
    $message | Out-File -Append $OutputFile
}

function Check-MX {
    $message = "Analizando registros MX..."
    Write-Host $message -ForegroundColor Green
    $message | Out-File -Append $OutputFile
    try {
        $records = Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop
        foreach ($mx in $records) {
            $message = "MX encontrado: $($mx.NameExchange) con prioridad $($mx.Preference)"
            Write-Host $message -ForegroundColor Green
            $message | Out-File -Append $OutputFile
        }
    } catch {
        $message = "No se encontraron registros MX o error: $_"
        Write-Host $message -ForegroundColor Red
        $message | Out-File -Append $OutputFile
    }
    $message = "`n============================================================="
    Write-Host $message -ForegroundColor Cyan
    $message | Out-File -Append $OutputFile
}

# ============================
# Ejecución principal
# ============================
Show-Banner
$message = "Verificando autenticacion de correo en: $Domain`n"
Write-Host $message
$message | Out-File -Append $OutputFile

Check-SPF
Start-Sleep -Seconds 3

Check-DKIM
Start-Sleep -Seconds 3

Check-DMARC
Start-Sleep -Seconds 3

Check-MX
