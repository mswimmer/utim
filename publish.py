#!env python3
import os
import boto3
from datetime import datetime

REGION = "eu-west-1"
PROFILE = "personal.iam"

print("auto-commit on publish")
os.system("git commit -a -m \"auto-commit on publish\"")

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
s3_client = session.client('s3')

# files and where they go
s3ontos="ontologies.ti-semantics.com"
s3www="www.ti-semantics.com"

www = [
    {'file': 'www/index.html', 'bucket':s3www, 'key': 'index.html', 'ct':'text/html'},
    {'file': 'www/404.html', 'bucket':s3www, 'key': '404.html', 'ct':'text/html'},
    {'file': 'www/favicon.ico', 'bucket':s3www, 'key': 'favicon.ico', 'ct':'image/x-icon'},
    {'file': 'www/robots.txt', 'bucket':s3www, 'key': 'robots.txt', 'ct':'text/plain'},
    {'file': 'www/icon.png', 'bucket':s3www, 'key': 'icon.png', 'ct':'image/png'},
    {'file': 'www/css/normalize.css', 'bucket':s3www, 'key': 'css/normalize.css', 'ct':'text/css' },
    {'file': 'www/css/main.css', 'bucket':s3www, 'key': 'css/main.css', 'ct':'text/css'}
    ]
    
ontologies = [
    {'file': 'ontologies/platform-1.0.3.rdf', 'bucket':s3ontos, 'key': 'platform-1.0.3.rdf', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/platform-1.0.3.rdf', 'bucket':s3ontos, 'key': 'platform-1.0.3', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/platform-1.0.3.rdf', 'bucket':s3ontos, 'key': 'platform', 'ct':'application/rdf+xml'},
    
    {'file': 'ontologies/core-1.0.3.rdf', 'bucket':s3ontos, 'key': 'core-1.0.3.rdf', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/core-1.0.3.rdf', 'bucket':s3ontos, 'key': 'core-1.0.3', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/core-1.0.3.rdf', 'bucket':s3ontos, 'key': 'core', 'ct':'application/rdf+xml'},

    {'file': 'ontologies/score-1.0.3.rdf', 'bucket':s3ontos, 'key': 'score-1.0.3.rdf', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/score-1.0.3.rdf', 'bucket':s3ontos, 'key': 'score-1.0.3', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/score-1.0.3.rdf', 'bucket':s3ontos, 'key': 'score', 'ct':'application/rdf+xml'},

    {'file': 'ontologies/vulnerability-1.0.3.rdf', 'bucket':s3ontos, 'key': 'vulnerability-1.0.3.rdf', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/vulnerability-1.0.3.rdf', 'bucket':s3ontos, 'key': 'vulnerability-1.0.3', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/vulnerability-1.0.3.rdf', 'bucket':s3ontos, 'key': 'vulnerability', 'ct':'application/rdf+xml'},

    {'file': 'ontologies/weakness-1.0.3.rdf', 'bucket':s3ontos, 'key': 'weakness-1.0.3.rdf', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/weakness-1.0.3.rdf', 'bucket':s3ontos, 'key': 'weakness-1.0.3', 'ct':'application/rdf+xml'},
    {'file': 'ontologies/weakness-1.0.3.rdf', 'bucket':s3ontos, 'key': 'weakness', 'ct':'application/rdf+xml'},
    
    # TODO: need to implement versioning for attack
    {'file': 'ontologies/attack.rdf', 'bucket':s3ontos, 'key': 'attack.rdf', 'ct':'application/rdf+xml'},

    {'file': 'ontologies/index.html', 'bucket': s3ontos, 'key': 'index.html', 'ct':'text/html'},
    {'file': 'ontologies/404.html', 'bucket': s3ontos, 'key': '404.html', 'ct':'text/html'},
    {'file': 'xslt/cpe-dict2rdf.xsl', 'bucket': s3ontos, 'key': 'cpe-dict2rdf.xsl', 'ct':'application/xslt+xml'},
    {'file': 'xslt/cvss2rdf.xsl', 'bucket':s3ontos, 'key': 'cvss2rdf.xsl', 'ct':'application/xslt+xml'},
    {'file': 'xslt/cpe-lang2rdf.xsl', 'bucket':s3ontos, 'key': 'cpe-lang2rdf.xsl', 'ct':'application/xslt+xml'},
    {'file': 'xslt/cve2rdf.xsl', 'bucket': s3ontos, 'key': 'cve2rdf.xsl', 'ct':'application/xslt+xml'}
    ]

# useful functions to stay DRY

def transfer(localFile, bucket, destKey, ct="application/html"):
    #print("Getting S3 info from s3://{}/{}".format(bucket, destKey))
    try:
        response = s3_client.get_object(Bucket=bucket, Key=destKey)
        #print(response)
        file_datetime = datetime.fromtimestamp(os.path.getmtime(localFile)).astimezone()
        #print("Is", response['LastModified'], "<", file_datetime, "?")
        if response['LastModified'] < file_datetime:
            with open(localFile, 'rb') as f:
                print("Transferring", bucket, destKey)
                s3_client.put_object(Bucket=bucket, Key=destKey, ContentType=ct, Body=f)
        else:
            print("No changes to", localFile, destKey)
    except s3_client.exceptions.NoSuchKey:
        with open(localFile, 'rb') as f:
            print("Transferring", bucket, destKey)
            s3_client.put_object(Bucket=bucket, Key=destKey, ContentType=ct, Body=f)

def transfer_all(file_list):
    for o in file_list:
        transfer(localFile=o['file'], bucket=o['bucket'], destKey=o['key'], ct=o['ct'])

def validate_file(html_file):
    return os.system("html5validator {}".format(html_file)) == 0

def validate_all(file_list):
    return all([validate_file(o['file']) for o in file_list if o['ct'] =='text/html'])

# Do actual stuff

if validate_all(www):
    transfer_all(www)
else:
    print("www didn't validate")
        
if validate_all(ontologies):
    transfer_all(ontologies)
else:
    print("ontologies didn't validate")

