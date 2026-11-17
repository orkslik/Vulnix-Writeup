# Scan evidence

The original machine output files (`vulnix_full.nmap`, `vulnix_services.nmap`) were not attached to this project; the corresponding **real screenshots** are included in `../screenshots/`.

To regenerate raw scan files on the same isolated, authorized lab target:

```bash
nmap -p- -T4 -Pn 192.168.77.100 -oN vulnix_full.nmap
nmap -sV -sC -Pn -p 22,25,79,111,2049 192.168.77.100 -oN vulnix_services.nmap
```

Do not treat newly regenerated outputs as originals from the earlier run.
