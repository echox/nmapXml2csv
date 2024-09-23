# NmapXML2CSV

Just one of the many nmap xml 2 csv converters.
Quick and dirty, omitted error handling.

## Input

nmap xml logs produced via -oXML.

Filename will be used in the column "scan"

## Output CSV

"Scan", "IP", "Hostname", "Port", "Service", "Confidence", "Script", "ScriptOutput

If CSV file exists, rows will be appended without header.
