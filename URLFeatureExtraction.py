# -*- coding: utf-8 -*-

from urllib.parse import urlparse, urlencode
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
from datetime import datetime
import requests
# import whois  # Uncomment if using WHOIS

# Feature extraction helpers

def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    return len([segment for segment in urlparse(url).path.split('/') if segment])

def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

def httpDomain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

shortening_services = re.compile(r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|buff\.ly|...")  # add more as needed
def tinyURL(url):
    return 1 if shortening_services.search(url) else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(
            urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={url}").read(),
            "xml"
        ).find("REACH")["RANK"]
        return 1 if int(rank) < 100000 else 0
    except:
        return 1

def domainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        age = (expiration_date - creation_date).days
        return 1 if age / 30 < 6 else 0
    except:
        return 1

def domainEnd(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        end = (expiration_date - datetime.now()).days
        return 1 if end / 30 >= 6 else 0
    except:
        return 1

def iframe(response):
    try:
        return 0 if re.search(r"<iframe|frameBorder", response.text) else 1
    except:
        return 1

def mouseOver(response):
    try:
        return 1 if re.search(r"<script>.+onmouseover.+</script>", response.text) else 0
    except:
        return 1

def rightClick(response):
    try:
        return 0 if re.search(r"event.button ?== ?2", response.text) else 1
    except:
        return 1

def forwarding(response):
    try:
        return 1 if len(response.history) > 2 else 0
    except:
        return 1

# Final feature extraction

def featureExtraction(url):
    features = []
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # WHOIS Features
    dns = 0
    try:
        import whois
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
        domain_name = None

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    # HTML and JavaScript features
    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features

# Example feature name list
feature_names = [
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
    'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
]
