# AZURE-HONEYPOT-WITH-LIVE-TRAFFIC

## Objective

This project began as a hands-on way to gain experience with cloud technologies and understand how attackers attempt to disrupt an organization's infrastructure. My goal was to build a cloud-based SIEM, monitor system activity, and analyze potential attack patterns. Through this process, I aimed to strengthen my cybersecurity skills and apply them in real-world scenarios.

🔗 **Read the full blog post here:**  
[Azure Honeypot with Live Traffic]( )

### Skills Learned

- Hands-on experience with Microsoft Sentinel for cloud-based SIEM deployment and monitoring.
- Automation of incident response using Microsoft Sentinel Analytics rules and automation rules (SOAR).
- Practical application of SIEM concepts through real-time log analysis using Kusto Query Language (KQL).
- Detection and visualization of brute-force attack patterns using Sentinel Workbooks and custom attack maps.
- Proficient in configuring and managing Azure components, including Virtual Machines, NSGs, VNETs, and Log Analytics Workspace.
- Enhanced understanding of cloud security architecture and network-based threat detection.
- Strengthened analytical thinking and problem-solving skills through investigating real-world attack data.

### Tools Used

- Cloud-based SIEM system using Microsoft Sentinel for log ingestion, correlation, and incident management.
- Log Analytics Workspace for centralized data collection and integration with Sentinel.
- Virtualized honeypot environment in Microsoft Azure using Virtual Machines, Network Security Groups (NSGs), and Virtual Networks (VNets).
- Telemetry analysis using Kusto Query Language (KQL) for querying and investigating security events.
- Microsoft Sentinel Analytics Rules and Automation Rules for real-time threat detection and automated incident handling.
- Microsoft Sentinel Workbooks for creating visual attack maps and summarizing brute-force activity.
- Task and incident orchestration using tagging, prioritization, and status assignment via automation rules.

## Steps
- Create a Resource Group in Azure.
- Inside the Resource Group, create a Virtual Network (VNet).
- Deploy a Virtual Machine (Windows) in the same Resource Group.
- Locate the Network Security Group (NSG) associated with the VM.
- Delete the default RDP rule.
![RDP](Img/rdp.png)
- Create a new inbound security rule to allow all traffic.
![Inbound](Img/Inbound.png)
- Connect to the VM using Remote Desktop.
- Disable the Windows Firewall for unrestricted traffic capture.
- Create a Log Analytics Workspace in the same Resource Group.
- Enable Microsoft Sentinel and attach it to the Workspace.
- Create a Scheduled Analytics Rule to detect brute-force login attempts.
- Define the detection query logic in the rule.
- Set up an Automation Rule that:
    - Triggers when the brute-force rule fires.
    - Sets the incident status to Active.
    - Adds priority, tags, and tasks for triaging.
- Connect Windows Security Events to the Log Analytics Workspace using Azure Monitor Agent (AMA).
![AMA](Img/AMA.png)
- Create a Watchlist and import the following GeoIP CSV file as the source.
    - [GeoIP](https://sacyberrange00.blob.core.windows.net/vm-applications/geoip-summarized.csv?sp=r&st=2025-05-16T00:31:16Z&se=2030-01-01T08:31:16Z&spr=https&sv=2024-11-04&sr=b&sig=taUGULhhgRiY0BRwEEbhusoh%2BxaIQJWAFwxN2%2FOWWhc%3D)
- Create a Workbook in Sentinel
- Import your map.json file to visualize attacks geographically.
- Wait ~24 hours for data collection and incident generation.
- Use the Kusto Query Language (KQL) query below to enrich brute-force events with GeoIP data:
```
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```
- Open the Sentinel Workbook to view your attack map.
![Attack Map](Img/Attack_Map.png)
- Check the Incidents tab to view captured brute-force attempts.
![Incidents](Img/Incidents.png)



