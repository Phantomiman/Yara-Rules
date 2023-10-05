rule Detect_Darts {
meta:
author = “Sami Mirov”
description = “Detects malware DARTS.exe”
strings:
$magic = { 4D 5A ?? }
$filename = “DARTS.EXE” wide
$str = “Office.com DARTS” fullword/wide/ascii/nocase
$regex = .*darts.*
condition:
($magic at 0 and $filename) or any of $regex or $str
}
Rule bytebased {
strings:
$bytestohex = { 4D 61 72 6B 65 72 20 30 30 3A 30 30 3A 30 30 2E ?? }
$stringx = “Office.com DARTS” nocase
$regxer = /\bMarker\b/
condition:
($bytestohex and $stringx) or $regxer and $stringx
}

