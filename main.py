import sys
import os
import re
import json
import yaml
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
import os
from jinja2 import Environment, FileSystemLoader



def get_indicators(indicators):
    extracted_indicators = []
    if 'ipv4' in indicators:
        for ips in indicators['ipv4']:
            extracted_indicators.append({"type": "ipv4", "value": ips})
    if 'domains' in indicators:    
        for domain in indicators['domains']:
            extracted_indicators.append({"type": "domain", "value": domain})
    if 'urls' in indicators:    
        for url in indicators['urls']:
            extracted_indicators.append({"type": "url", "value": url})
    if 'sha256' in indicators:
        for sha256 in indicators['sha256']:
            extracted_indicators.append({"type": "sha256", "value": sha256})
    print(extracted_indicators)
    return extracted_indicators
def enrich_indicators(indicators):
    enriched_indicators = []
    for indicator in indicators:
        ##Enriching IPS
        if indicator['type'] == 'ipv4':
            with open('mocks/it/anomali_ip_1.2.3.4.json', "r", encoding="utf-8") as f:
                data = json.load(f)
                if indicator['value'] == data['ip']:
                    indicator['risk'] = {'veredict': data['risk'],'score':data['confidence']}
                    indicator['sources'] = ['Anomali']
                    enriched_indicators.append(indicator)
                else:
                    indicator['risk'] = {'veredict': 'unknown','score':0}
                    indicator['sources'] = []
                    enriched_indicators.append(indicator)            
        ## Enriching domains and URLS
        elif indicator['type'] == 'domain' or indicator['type'] == 'url':
            with open('mocks/it/defender_ti_domain_bad.example.net.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                indicator_value = indicator['value']
                if 'http' in indicator['value']:
                    indicator_value = re.findall(r'://([^/]+)', indicator['value'])[0]
                if indicator_value == data['domain']:
                    indicator['risk'] = {'veredict': data['reputation'],'score':data['score']}
                    indicator['sources'] = ['DefenderTI']
                    enriched_indicators.append(indicator)  
                else:
                    indicator['risk'] = {'veredict': 'unknown','score':0}
                    indicator['sources'] = []
                    enriched_indicators.append(indicator)
        
        ## Enriching SHA        
        elif indicator['type'] == 'sha256':
            with open('mocks/it/reversinglabs_sha256_7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
                if indicator['value'] == data['sha256']:
                    indicator['risk'] = {'veredict': data['classification'],'score':data['score']}
                    indicator['sources'] = ['ReversingLabs']
                    enriched_indicators.append(indicator)
                else:
                    indicator['risk'] = {'veredict': 'unknown','score':0}
                    indicator['sources'] = []
                    enriched_indicators.append(indicator)
    
    return enriched_indicators
            

def processalert(alert):
    incident = {}
    incident['id'] = str(uuid.uuid4())
    incident['source_alert'] = alert
    incident['title'] = alert['source'] + " - " + alert['alert_id'] + " - " + alert['type']
    incident['indicators'] = get_indicators(alert['indicators'])
    incident["indicators"] = enrich_indicators(incident["indicators"])
    incident['asset'] = alert['asset']
    incident['type'] = alert['type']
    incident['severity'] = 40
    incident['tags'] = []

    if incident['type'] == "Malware":
        incident['severity'] = 70
    elif incident['type'] == "Phishing":
        incident['severity'] = 60
    elif incident['type'] == "Beaconing":
        incident['severity'] = 65
    elif incident['type'] == "CredentialAccess":
        incident['severity'] = 75
    elif incident['type'] == "C2":
        incident['severity'] = 80
    ## Intel Boosts
    flagmalicious = False
    flagsuspicious = False
    for indicator in incident['indicators']:
        if indicator['risk']['veredict'] == 'malicious' and not flagmalicious:
            incident['severity'] += 20
            flagmalicious = True
        elif indicator['risk']['veredict'] == 'suspicious' and not flagsuspicious:
            incident['severity'] += 10
            flagsuspicious = True
        if indicator['risk']['veredict'] == 'malicious' and flagmalicious:
            incident['severity'] += 5
            flagmalicious = True
        elif indicator['risk']['veredict'] == 'suspicious' and  flagsuspicious:
            incident['severity'] += 5
            flagsuspicious = True

    ## Allowlist suppression (from YAML):
#○ If an IOC is allowlisted: subtract 25 and add tag allowlisted
#○ If all IOCs are allowlisted → severity=0, add tag suppressed=true, skip response
    analized_indicators = []
    with open('configs/allowlists.yml', 'r') as file:
        allowlists = yaml.safe_load(file)
        print(allowlists)
        cant = len(incident['indicators'])
        cont = 0
        for indicator in incident['indicators']:
            if indicator['type'] == 'ipv4':
                if indicator['value'] in allowlists['indicators']['ipv4']:
                    cont += 1
                    incident['severity'] -= 25
                    indicator['allowlisted'] = "True"
            if indicator['type'] == 'domain':
                if indicator['value'] in allowlists['indicators']['domains']:
                    cont += 1
                    incident['severity'] -= 25
                    indicator['allowlisted'] = "True"
         
            if indicator['type'] == 'url':
                if indicator['value'] in allowlists['indicators']['urls']:
                    cont += 1
                    incident['severity'] -= 25
                    indicator['allowlisted'] = "True"
            if indicator['type'] == 'sha256':
                if indicator['value'] in allowlists['indicators']['sha256']:
                    cont += 1
                    incident['severity'] -= 25
                    indicator['allowlisted'] = "True"
            analized_indicators.append(indicator)

            if incident['asset']['device_id'] in allowlists['assets']['device_ids']:
                incident['asset']['allowlisted'] = "True"
                
            else:
                incident['asset']['allowlisted'] = "False"
        if cant == cont:
            incident['severity'] = 0
        incident['indicators'] = analized_indicators

        ## Clamp and bucket:
##○ Clamp to 0..100
##○ Buckets: 0=Suppressed, 1–39 Low, 40–69 Medium, 70–89 High, 90–100 Critical
        incident['triage'] = {}
        print(incident['severity'])
        if incident['severity'] <= 0:
            incident['severity'] = 0
            incident['triage']['severity'] = 0
            incident['triage']['bucket'] = 'Suppressed'
            incident['triage']['suppresed'] = True

        
        if incident['severity'] >= 100:
            incident['severity'] = 100
            incident['triage']['severity'] = 100
            incident['triage']['bucket'] = 'Critical'
            incident['triage']['suppresed'] = False

        if incident['severity'] >= 1 and incident['severity'] <= 39:
            incident['triage']['severity'] = incident['severity']
            incident['triage']['bucket'] = 'Low'
            incident['triage']['suppresed'] = False
        if incident['severity'] >= 40 and incident['severity'] <= 69:
            incident['triage']['severity'] = incident['severity']
            incident['triage']['bucket'] = 'Medium'
            incident['triage']['suppresed'] = False
        if incident['severity'] >= 70 and incident['severity'] <= 89:
            incident['triage']['severity'] = incident['severity']
            incident['triage']['bucket'] = 'High'
            incident['triage']['suppresed'] = False
    incident['MITRE'] = {}
    incident['MITRE']['Techniques'] = []
    with open('configs/mitre_map.yml', 'r') as file:
        mitremappings = yaml.safe_load(file)
        if incident['type'] in mitremappings['types']:
            for technique in mitremappings['types'][incident['type']]:
                incident['MITRE']['Techniques'].append(technique)
        else:
            incident['MITRE']['Techniques'] = mitremappings['default']       


#If fi nal severity ≥ 70 and asset.device_id present and not allowlisted:
#○ Append a line to out/isolation.log:
#■ <ISO-TS> isolate device_id=<ID> incident=<INCIDENT_ID> result=isolated
    incident['actions'] = []
    if incident['triage']['severity'] >= 70 and 'device_id' in incident['asset'] and incident['asset']['allowlisted'] == "False":
        with open('out/isolation.log', 'a', encoding='utf-8') as f:
            incident['actions'] = [{'type':'isolated','target':incident['asset']['device_id']}]
            f.write(f"{datetime.now(timezone.utc).isoformat()} isolate device_id={incident['asset']['device_id']} incident={incident['id']} result=isolated\n")

    with open(f"out/incidents/{incident['id']}.json", "w", encoding="utf-8") as f:
        json.dump(incident, f, indent=4, ensure_ascii=False)
    print(f"Incidente {incident['id']} procesado con severidad {incident['triage']['severity']} y bucket {incident['triage']['bucket']}")

### Analyst summary (Jinja2 → Markdown) → out/summaries/<incident_id>.md:
###● Incident, indicators table, severity & tags, ATT&CK techniques, actions taken.
    env = Environment(loader=FileSystemLoader('out/templates'))
    template = env.get_template('analyst_summary.j2')
    
    # Render the template with the incident data
    markdown_output = template.render(incident=incident)
    
    # Save the rendered Markdown to a file
    output_dir = "out/summaries"
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, f"{incident['id']}.md"), "w", encoding="utf-8") as f:
        f.write(markdown_output)

def main(argv):
    if len(argv) < 2:
        print("Modo de uso: python main.py alerts/sentinel.json")
        sys.exit(1)
    input_file = argv[1]
    if not os.path.isfile(input_file):
        print(f"El archivo {input_file} no existe.")
        sys.exit(1)
    
    with open(input_file, 'r', encoding='utf-8') as f:
        alerts = json.load(f)
        processalert(alerts)

if __name__ == "__main__":
    main(sys.argv)