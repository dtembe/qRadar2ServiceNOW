# qRadar2ServiceNOW
Python Script - GET open offenses (with time offset) from qRadar & POST them to ServiceNOW EM

Running this via Jenkins as a build, so I run the build every 5 minutes and set the offset to 5 minutes for qradar api query. 

All qRadar fields are posted to SNOW Event - Additional Information field. 

You can run this via straight CRON. 

Uses urllib3.
Uses Python3



//TODO
Optimize code with functions 
Add init
Add try/except
Map Severity in the code before posting event to SNOW

