# SOC Detection Logic: Access Control Monitoring
**Monitoring Goal:** Detect violations of the Corporate Access Control Policy (NIST AC-2/AC-3).

## 1. Scenario: Brute Force Attack Detection
This query identifies multiple failed login attempts followed by a successful login from the same IP address—indicating a potential credential stuffing or brute force success.

### Kusto Query Language (KQL) - Azure Sentinel / Microsoft Defender
```kusto
let FailureThreshold = 5;
SigninLogs
| where ResultType != "0" // Filter for failed logins
| summarize FailureCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m)
| where FailureCount >= FailureThreshold
| join kind=inner (
    SigninLogs
    | where ResultType == "0" // Filter for successful logins
    | project SuccessTime = TimeGenerated, UserPrincipalName, IPAddress
) on UserPrincipalName, IPAddress
| where SuccessTime > TimeGenerated
| project TimeOfSuccess = SuccessTime, UserPrincipalName, IPAddress, FailureCount
| extend Severity = "High"
📍 Detection Scenario 02: Impossible Travel

Objective: Detect if a user logs in from two different countries within 1 hour (violating the Access Control Policy).

Tool: Splunk Enterprise / Splunk Cloud Language: SPL (Search Processing Language)
index=security sourcetype=wineventlog_security EventCode=4624
| iplocation src_ip
| streamstats current=f last(Country) as last_country last(_time) as last_time by user
| where Country != last_country
| eval time_diff = _time - last_time
| where time_diff < 3600 
| table _time, user, Country, last_country, time_diff
