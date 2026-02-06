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
