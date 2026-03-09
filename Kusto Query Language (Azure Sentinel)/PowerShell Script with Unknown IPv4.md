// let LegitimateIPs = ("127.0.0.1", "0.0.0.0"); // Add here the legitimate IP addresses that you may have in your environment
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend Command = tostring(AdditionalFields.Command)
| where Command matches regex @"(\b25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
| extend IPv4Extracted = extract(
    @"(\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})",
    1,
    Command
)
//| where not (IPv4Extracted has_any(LegitimateIPs)) // Remove the "//" if you want to filter by Legitimate IP Addresses
| where isnotempty(IPv4Extracted)
| project TimeGenerated, DeviceName, Command, IPv4Extracted, InitiatingProcessAccountName, InitiatingProcessFolderPath