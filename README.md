# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Selvawen/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at `2026-02-28T06:54:58.0224087Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-02-28T06:54:58.0224087Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="download1" src="https://github.com/user-attachments/assets/c5324fcc-fde5-4e89-b8ef-df204e956d1b" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string `tor-browser-windows-x86_64-portable-15.0.7.exe`. Based on the logs returned, at `2026-02-28T07:00:42.9277547Z`, on a machine named threat-hunt-lab, a user account called employee launched a newly downloaded file from their Downloads folder — specifically the Tor Browser installer (`tor-browser-windows-x86_64-portable-15.0.7.exe`). The system recorded the creation of that process, noting the exact file path on the C: drive and capturing its unique SHA256 hash, confirming that the Tor Browser executable was run directly from the Downloads directory. 

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="install2" src="https://github.com/user-attachments/assets/df7e9b2d-bf1b-43f4-92a9-51e35a2fab91" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-02-28T06:56:45.5502748Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor-browser-windows-x86_64-portable-<version>.exe", "tor-browser-windows-i686-portable-<version>.exe", "torbrowser-install-win64-<version>_ALL.exe", "Tor Browser Setup.exe", "firefox.exe", "tor.exe", "obfs4proxy.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="process-creation3" src="https://github.com/user-attachments/assets/d941e959-71ec-453c-9246-d1eec724e0f1" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At `2026-02-28T07:02:17.1919003Z`, on the computer named threat-hunt-lab, the user account employee successfully established an outbound network connection using tor.exe from the Tor Browser folder on their desktop. The program connected to the external IP address `57.131.24.118` over port `9001`, which is commonly used by Tor relay nodes — indicating that the Tor service was actively connecting to the Tor network.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="tor-usage" src="https://github.com/user-attachments/assets/82fdb6ce-e696-41af-9a78-b57221656cc3" />



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-28T06:54:58.0224087Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-28T07:00:42.9277547Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-28T06:56:45.5502748Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-28T07:02:17.1919003Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-28T07:18:08Z` - Connected to `57.131.24.118` on port `443`.
  - `2026-02-28T07:18:28Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-28T07:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
