# PowerShell script to convert all docx files in docs/ to pdf using Word COM
param(
    [string]$DocsDir = "C:\Users\Asus\.gemini\antigravity\scratch\RISE-Phish\docs"
)

Write-Host "[*] Starting Word COM Application..."
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = [Microsoft.Office.Interop.Word.WdAlertLevel]::wdAlertsNone

$files = @(
    "RISE_Phish_Major_Project_Report",
    "RISE_Phish_SRS",
    "RISE_Phish_SDD",
    "RISE_Phish_Testing_Report",
    "RISE_Phish_User_Manual"
)

foreach ($name in $files) {
    $docxPath = Join-Path $DocsDir "$name.docx"
    $pdfPath = Join-Path $DocsDir "$name.pdf"

    if (Test-Path $docxPath) {
        Write-Host "[*] Converting $docxPath -> $pdfPath"
        try {
            $doc = $word.Documents.Open($docxPath)
            # 17 corresponds to wdExportFormatPDF in ExportAsFixedFormat
            $doc.ExportAsFixedFormat($pdfPath, 17)
            $doc.Close([ref]$false)
            $len = (Get-Item $pdfPath).Length
            Write-Host "[+] Converted: $pdfPath ($len bytes)"
        }
        catch {
            Write-Warning "[-] Failed to convert $docxPath : $_"
        }
    } else {
        Write-Host "[-] Skip (not found): $docxPath"
    }
}

$word.Quit()
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
Write-Host "[+] PDF conversion process complete."
