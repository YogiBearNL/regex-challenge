
# Assessment for normalising log sources to Splunk CIM

***3 different log sources were provided***

Original request:

- Parse as many fields as possible from these logs in no more than 3 working days
- Use a field-by-field approach (don't develop one regex that matches the whole log, nor one with multiple named capturing groups)
- Do not "spend" more than 100 steps for each field's parsing (with flags "/gm" global / multivalue, like "| rex max_match=0") - you can use https://regex101.com/ to count steps. To reach this objective, advanced mechanisms may be used, like: anchoring, positive/negative lookahead/lookbehind, etc.
- Bonus: Recognize which Splunk CIM Data Model(s) these logs are about, hence parse them with proper "field" names (named capturing group)

My answers to these questions:

Although I am able to create these regular expressions, it does not always make sense to do so. Based on experience it's better to go for the most efficient way of onboarding logs using as less resources as possible and to make use of the internal functions of log management systems/platforms to achieve what you want to achieve.
One other thing is to make sure the logs/messages can be provided in the most structured way by the teams configuring the log sources. For example raw logs vs CEF / JSON objects / Key-Values. Raw logs are the worst formats for parsing, and it's error prone e.g. when the vendor creates a new release and completely rewrites there syntax and positions of field values within a raw message.
Named capturing groups make sense to keep track of what you are doing (if parsing is really necessary) this also helps for the operational teams which mostly use/understand the field names provided by the taxonomy of the vendor/product sending these logs.
This also helps when a vendor is requested to assist in a service request for wich the 'raw' logs are necessary to be provided.
CIM fields are created to support the SIEM with event correlation and to create use cases which can be reused within product categories like firewalls, proxies, A/V scanners, NIDS, Identity providers etc.
It's wise to use aliases instead of renaming the original fields provided by the vendor.
Next to this, time is very important. Looking at the syslog formats provided, it's unclear (based on the syslog header) as wo which timezone these events are provided.
To verify delays, correlate events and such it's necessary to have a clear definition.

## 1. Web Application Firewall log

```text
<111>Sep 22 16:37:06 0.0.0.0 {"logAlertUid":"b9159f25c9fe4df08e84978df375e871","@timestamp":"1790087826480","request":{"body":"","cookies":[],"headers":[{"key":"Host","value":"mysite.example.com"},{"key":"User-Agent","value":"Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity"}],"hostname":"mysite.example.com","ipDst":"0.0.0.0","ipSrc":"0.0.0.0","method":"GET","path":"/","portDst":443,"protocol":"HTTP/1.1","query":"","requestUid":"arKSknJGc7KV5ja6dXLiZQAAALw"},"context":{"tags":"","geoipCode":"US","geoipName":"United States","applianceName":"waf01","backendHost":"0.0.0.0","backendPort":443,"reverseProxyName":"rp-mysite","tunnelName":"API - mySite"},"events":[{"eventUid":"3bfe4db03397448ea1f1d97a8dc8a70a","tokens":{"date":1790087826481613,"eventType":"security","engineUid":"icxEngine","engineName":"ICX Engine","attackFamily":"Scanner","riskLevel":40,"severity":3,"resolveType":"Default Resolve","part":"Multiple","icxPolicyName":"ICX-6.11.13_Strict","icxPolicyUid":"4d3509e33e858f3d5a7ef62840a9056f","icxRuleName":"Scanner-heuristic","icxRuleUid":"eeeea8b382ef38e55f1b620c39adbbba","matchingParts":[{"part":"Header","partKey":"User-Agent","partKeyOperator":"regexp","partKeyMatch":"User-Agent","partValue":"Scanning","partValueOperator":"pattern","partValuePatternVersion":"Sca.S-00659-3.41.0"}],"reason":"ICX Engine: Scanner in Header 'User-Agent'"}}]}
```

### 1.1 Information

It's an (old/legacy) syslogformat rfc3164 which is superseeded by rfc5424 which has better datetime requirements, including the timezone, which is very important for log management platforms/SIEMs to be able to correlate events.  
Normally I would ask teams to provide syslog format in rfc5424 where timezone is enforced. Looks like ISO8601, but even there a timezone is allowed to be omitted.  
Together with the SME I would find out if it would be possible to (re)configure the syslog output to inlude the timezone, and/or to make sure the device/WAF has the timezone configured in UTC and NTP servers are configured.

### 1.2 Regular expression

Regular expression to split syslog header and JSON object/message:  

```text
^<(?<priority>\d{1,3})>(?<syslogsenddatetime>(?<month>\w+)\s(?<day>\d{1,2})\s(?<hour>\d{1,2}):(?<minute>\d{1,2}):(?<second>\d{1,2}))\s(?<devicesendingsyslog\S+)\s(?<jsonobject>\{.*\})$
```

priority = <https://www.syslog.tools/pri-calculator> -> Facility 13 Security/Log Audit + Severity Debug  
device = syslog sending device  
syslogsenddatetime = datetime when syslog source sent the event to the syslog server  
jsonobject = because of the JSON object, this can be parsed (field/value) by means of functions within log management systems / SIEM platforms.  
E.g. for Splunk you can use spath to extract key values out of JSON objects  
If necessary I am able to create specific regular expressions, but those will use more resources as opposed to using internally written functions.  
Rewriting / Alias these fields (Key/Values) will take way less resources and is easier to read. Another bonus is that if the vendor changes fieldnames / or add fieldnames in later releases, you would still be able to see the fields, only it could be that those are not mapped yet to CIM compliant fields.  

timestamp = "Tue, 22 Sep 2026 14:37:06 GMT", this indicates the sending device is setup within CEST timezone (Sep 22 16:37:06) or there's a delay of 2 hours between eventtime and when the device sends it to the syslog server.  
Configuring a timezone other than UTC is not something I would recommend. All systems, devices, servers need to be set to UTC. Because of DST, clocks are ahead of time or set back in time. This can have implications for scheduled tasks (operational risk) and/or correlation of events.  
When in a worldwide organisation this can also lead to unexpected correlation of events both operational and security wise.  

### 1.3 CIM data model

Tags = web, attack and ids  
  
Example of the field mappings for Network Traffic to map to CIM:  
<https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.7/field-mappings/network-traffic-field-mapping>
  
All CIM fields:  
<https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/cim-fields-per-associated-data-model>  

## 2. Windows Sysmon

```text
09/22/2026 06:29:12.357 PM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=11
EventType=4
ComputerName=WKS001.corp.internal
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=710132
Keywords=None
TaskCategory=Image loaded (rule: ImageLoad)
OpCode=Info
Message=File created:
RuleName: File Creation inclusion v4
UtcTime: 2026-09-22 16:29:12.339
ProcessGuid: {914528d3-acd7-6ab2-4f41-000000000600}
ProcessId: 34620
Image: C:\Program Files\Google\Chrome\Application\chrome.exe
TargetFilename: C:\Users\USR002\Downloads\spreadsheet.xlsx:Zone.Identifier
CreationUtcTime: 2026-09-22 16:29:10.713
User: CORP\USR002
```

### 2.1 Information

This looks like sysmon logs/events/message. Which can also be configured in XML. I would ask the team to configure the log output to XML for which the standard Splunk app can be used.  
App can then be downloaded from Splunk Base:  
<https://splunkbase.splunk.com/app/5709>

If it really contains multiple lines, you can use the following syntax within Splunk:

```text
[sysmon:text]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)(?=\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})
TRUNCATE = 30000
MAX_TIMESTAMP_LOOKAHEAD = 25
```

Truncate is tunable, to match largest messages. Splunk default is 10.000 characters  
The Key Values are provided, only challenge is to use separator = or :  

### 2.2 CIM data model

<https://splunk.github.io/splunk-add-on-for-microsoft-sysmon/Sysmonproductcomparisons/#cim-model-comparison-for-versions-1062-of-the-splunk-add-on-for-microsoft-sysmon-and-101-of-the-splunk-add-on-for-sysmon>  
Tags = endpoint, registry, service, process, filesystem, change, communicate, report, network, resolution, dns (Depends on what is enabled/configured per Sysmon setup)  

## 3. Trend Micro Apex Central

```text
<133>Jul 29 2026 09:49:22 0.0.0.0 CEF:0|Trend Micro|Apex Central|2019|AV:File deleted|Eicar_test_file|3|deviceExternalId=3484 rt=2026-07-29 07:46:11 +00:00 cnt=1 dhost=WKS002 TMCMLogDetectedHost=WKS002 duser=CORP\\USR003 act=File deleted cn1Label=Pattern cn1=2121500 cn2Label=Second_Action cn2=3 cs1Label=VLF_FunctionCode cs1=Real-time Scan cs2Label=Engine cs2=26.510.1005 cs3Label=Product_Version cs3=14.0 cs4Label=CLF_ReasonCode cs4=virus log cs5Label=First_Action_Result cs5=Unable to clean file cs6Label=Second_Action_Result cs6=File deleted cat=1703 dvchost=HUBL-AV16-PRD cn3Label=Overall_Risk_Rating cn3=1 fname=new test eicar file.txt filePath=C:\\Users\\USR003\\Documents\\ dst=0.0.0.0 TMCMLogDetectedIP=0.0.0.0 fileHash=3395856CE81F2B7382DEE72602F798B642F14140 deviceFacility=Apex One ApexCentralHost=HUB-APEXC16-PRD devicePayloadId=E9005650BF58-A36B11F1-8B21-B608-1746 TMCMdevicePlatform=Windows 11 10.0 (Build 22631) deviceNtDomain=CORP dntdom=CORP\\WKS\\
```

### 3.1 Information

CEF format
Based on CEF format:  
Vendor: Trend Micro  
Product: Apex Central  

There's an archived SplunkBase app for it:  
<https://splunkbase.splunk.com/app/5618>

Generic CEF parser, contains resource intense regular expressions which might not be needed, the transforms.conf within the app/5618 has all the fields needed:  
<https://splunkbase.splunk.com/app/487>

### 3.2 CIM data model

Tags = malware, attack, operations  
