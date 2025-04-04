param (
    [Parameter(Mandatory = $true)]
    [string]$Domain
)

function Show-Banner {
    Write-Host "`n=============================================================" -ForegroundColor Cyan
    Write-Host "  DKIM-DMARC-SPF-MX Checker by Alejandro Leon AKA GX " -ForegroundColor Cyan
    Write-Host "  Uso ético y autorizado solamente ⚡" -ForegroundColor Cyan
    Write-Host "=============================================================`n" -ForegroundColor Cyan
}

function Check-SPF {
    Write-Host "Analizando SPF..." -ForegroundColor Green
    try {
        $records = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction Stop
        $spf = $records | Where-Object { $_.Strings -match "^v=spf1" }
        if ($spf) {
            $spf | ForEach-Object { Write-Host "SPF encontrado: $($_.Strings)" -ForegroundColor Green }
        } else {
            Write-Host "SPF no encontrado." -ForegroundColor Red
        }
    } catch {
        Write-Host "Error al buscar SPF: $_" -ForegroundColor Red
    }
    Write-Host "`n=============================================================" -ForegroundColor Cyan
}

function Check-DKIM {
    Write-Host "Analizando DKIM..." -ForegroundColor Green
    $selectors = @('default', 'selector1', 'selector2', 'mail')
    $found = $false

    foreach ($selector in $selectors) {
        $dkimDomain = "$selector._domainkey.$Domain"
        try {
            $record = Resolve-DnsName -Name $dkimDomain -Type TXT -ErrorAction Stop
            foreach ($entry in $record) {
                Write-Host "DKIM encontrado con selector '$selector': $($entry.Strings)" -ForegroundColor Green
                $found = $true
            }
            break
        } catch {
            continue
        }
    }

    if (-not $found) {
        Write-Host "No se encontró DKIM con los selectores comunes." -ForegroundColor Red
    }
    Write-Host "`n=============================================================" -ForegroundColor Cyan
}

function Check-DMARC {
    Write-Host "Analizando DMARC..." -ForegroundColor Green
    $dmarcDomain = "_dmarc.$Domain"
    try {
        $record = Resolve-DnsName -Name $dmarcDomain -Type TXT -ErrorAction Stop
        foreach ($entry in $record) {
            Write-Host "DMARC encontrado: $($entry.Strings)" -ForegroundColor Green
        }
    } catch {
        Write-Host "DMARC no encontrado o error: $_" -ForegroundColor Red
    }
    Write-Host "`n=============================================================" -ForegroundColor Cyan
}

function Check-MX {
    Write-Host "Analizando registros MX..." -ForegroundColor Green
    try {
        $records = Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop
        foreach ($mx in $records) {
            Write-Host "MX encontrado: $($mx.NameExchange) con prioridad $($mx.Preference)" -ForegroundColor Green
        }
    } catch {
        Write-Host "No se encontraron registros MX o error: $_" -ForegroundColor Red
    }
    Write-Host "`n=============================================================" -ForegroundColor Cyan
}

# ============================
# Ejecución principal
# ============================
Show-Banner
Write-Host "Verificando autenticación de correo en: $Domain`n"

Check-SPF
Start-Sleep -Seconds 3

Check-DKIM
Start-Sleep -Seconds 3

Check-DMARC
Start-Sleep -Seconds 3

Check-MX
