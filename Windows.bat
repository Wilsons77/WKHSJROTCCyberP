echo Disabling Guest account...
net user Guest /active:no >nul

if ERRORLEVEL 1 (
  echo Disabling Guest Account failed.
  timeout 30 >nul
  exit
)

echo Guest account disabled


REM ~~~~~~~~~~~~~~~~~

echo Disabling Admin account...
net user Administrator /active:no >nul

if ERRORLEVEL 1 (
  echo Disabling Admin Account failed.
  timeout 30 >nul
  exit
)

echo Admin account disabled

REM ~~~~~~~~~~~~~~~~~

echo Setting MAXPWAGE to 14 days...
net accounts /maxpwage:14 >nul

if ERRORLEVEL 1 (
  echo An error occured while setting MAXPWAGE.
  timeout 30 >nul
  exit
)

echo Maximum password life set.


REM ~~~~~~~~~~~~~~~~~

echo Setting MINPWLENGTH to 10 characters...
net accounts /minpwlen:10 >nul

if ERRORLEVEL 1 (
  echo An error occured while setting MINPWLENGTH.
  timeout 30 >nul
  exit
)

echo Minimum password length set.


REM ~~~~~~~~~~~~~~~~~

echo Setting lockout duration to 45 minutes...
net accounts /lockoutduration:45 >nul

if ERRORLEVEL 1 (
  echo An error occured while setting lockout duration.
  timeout 30 >nul
  exit
)

echo Lockout duration policy is enforced.



REM ~~~~~~~~~~~~~~~~~

echo Setting lockout threshold to 3 attempts...
net accounts /lockoutthreshold:3 >nul

if ERRORLEVEL 1 (
  echo An error occured while setting lockout threshold.
  timeout 30 >nul
  exit
)

echo Lockout threshold enforced.




REM ~~~~~~~~~~~~~~~~~


echo Setting lockout window to 15 minutes...
net accounts /lockoutwindow:15 >nul

if ERRORLEVEL 1 (
  echo An error occured while setting lockout window.
  timeout 30 >nul
  exit
)

echo Lockout window enforced.



REM ~~~~~~~~~~~~~~~~~

echo Begin auditing successful and unsuccessful logon/logoff attempts...
auditpol /set /category:"Account Logon" /Success:enable /failure:enable >nul
auditpol /set /category:"Logon/Logoff" /Success:enable /failure:enable >nul
auditpol /set /category:"Account Management" /Success:enable /failure:enable >nul
auditpol /set /category:"DS Access" /failure:enable >nul
auditpol /set /category:"Object Access" /failure:enable >nul
auditpol /set /category:"policy change" /Success:enable /failure:enable >nul
auditpol /set /category:"Privilege use" /Success:enable /failure:enable >nul
auditpol /set /category:"System" /failure:enable >nul

if ERRORLEVEL 1 (
  echo An error occured while enabling logging for logon and logoff attempts.
  timeout 30 >nul
  exit
)

echo Now logging all logon and logoff attempts




REM ~~~~~~~~~~~~~~~~~

echo Attempting to block FTP (20, 21)...
netsh advfirewall firewall add rule name="BlockFTP20" protocol=TCP dir=in localport=20 action=block >nul
netsh advfirewall firewall add rule name="BlockFTP21" protocol=TCP dir=in localport=21 action=block >nul

if ERRORLEVEL 1 (
  echo An error occured while blocking FTP.
  timeout 30 >nul
  exit
)

echo FTP is blocked.




REM ~~~~~~~~~~~~~~~~~

echo Attempting to block TCP/Telnet (23)...
netsh advfirewall firewall add rule name="BlockTelNet23" protocol=TCP dir=in localport=23 action=block >nul

if ERRORLEVEL 1 (
  echo An error occured while blocking TelNet.
  timeout 30 >nul
  exit
)

echo TelNet is blocked.




REM ~~~~~~~~~~~~~~~~~


echo Attempting to deny RDP access...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f >nul

if ERRORLEVEL 1 (
  echo An error occured while denying RDP.
  timeout 30 >nul
  exit
)

echo RDP connections are now being denied.



REM ~~~~~~~~~~~~~~~~~


echo Attempting to enable Windows Firewall...
NetSh Advfirewall set allprofiles state on
Netsh Advfirewall show allprofiles

if ERRORLEVEL 1 (
  echo Error enabling Windows Firewall.
  timeout 30 >nul
  exit
)

echo Windows Firewall enabled.


REM netstat -aon | find /i "listening"

REM (wmic service get  name, startname /format:htable >out.html) && out.html
