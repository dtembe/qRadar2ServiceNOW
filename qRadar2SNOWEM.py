#!/usr/bin/env python3


import urllib3
import requests
import json
import logging
import urllib.response
import urllib.request
from datetime import datetime, timedelta


# ctx = ssl.create_default_context()
# ctx.check_hostname = False
# ctx.verify_mode = ssl.CERT_NONE

# ServiceNow - Post -

# Vars Used to Post Data to ServiceNow -
snowemurl = "https://YourInstance.service-now.com/api/now/table/em_event"
snowemuser = "UserName"
snowempassword = "Password"

#qRadar Security Token

security_token = "insert your qRadar token here"
#qRadar needs EPOCH time passed to the start_time filter in the URL so passing that now via the code below.

now = datetime.now()

nowinepoch = int(now.timestamp())

nowepochtime = nowinepoch * 1000

# The minutes=<int> is the offset. If you run this script every 5 minutes then use the 5 minutes offset.

fiveminutesago = now - timedelta(minutes=5)

etime = int(fiveminutesago.timestamp())

epochtime = etime * 1000

# Creating Logger Environment
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler('/tmp/qRadar.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

logger.info('Starting Script')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger.info("EPOCH Time after offset")
logger.info(epochtime)

#Passing second filter for only open offenses.
open = "OPEN"

#qRadar URL with all the flters passed/
url = "https://qRadarURL/api/siem/offenses?filter=status%20%3D%20%22{open}%22%20and%20start_time%20%3E%20{etime}".format(open=open, etime=epochtime)

#querystring = {"status": "OPEN"}

headers = {
    'Accept': "application/json",
    'SEC': security_token,
    'cache-control': "no-cache",
}
response = requests.request("GET", url, headers=headers, verify=False)

data = response.json()

http = urllib3.PoolManager()

if data == []:
    logger.info("No Data")
else:
    logger.info('Number of offenses retrived: ' + str(len(data)))
    for rows in data:
        logger.info('\n')
        logger.info("*****")
        logger.info('Offense ID: ' + str(rows['id']))
        logger.info('Description: ' + str(rows['description']))
        logger.info('Rules -  ID: ' + str(rows['rules'][0]['id']))
        logger.info('Rules -  Type: ' + str(rows['rules'][0]['type']))
        logger.info('Categories Listed: ' + str(rows['categories'][0]))
        logger.info('Severity:' + str(rows['severity']))
        logger.info("*****")
        logger.info('\n')
        #Create JSON Mapping
        o_source = str("qRadar-API")
        o_node = str(['offense_source'])
        o_metric_name = str(rows['rules'][0]['id'])
        o_type = str(rows['rules'][0]['type'])
        o_resource = str(rows['id'])
        o_severity = str(rows['severity'])
        o_description = str(rows['description'])
        o_event_class = str(rows['categories'][0])
        o_additional_info = str(rows)
        data = {"source": o_source, "node": o_node, "metric_name": o_metric_name, "type": o_type,
                "resource": o_resource, "severity": o_severity, "event_class": o_event_class,
                "description": o_description, "additional_info": o_additional_info}

        userName = snowemuser
        passWord = snowempassword
        top_level_url = snowemurl

        # create an authorization handler
        p = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        p.add_password(None, top_level_url, userName, passWord)

        auth_handler = urllib.request.HTTPBasicAuthHandler(p)
        opener = urllib.request.build_opener(auth_handler)

        urllib.request.install_opener(opener)

        try:
            req = urllib.request.Request(url=snowemurl, data=bytes(json.dumps(data), encoding="utf-8"),
                                         headers={'Content-Type': 'application/json'})
            result = opener.open(req)
            messages = result.read()
            logger.info(messages)
        except IOError as e:
            logger.info(e)
