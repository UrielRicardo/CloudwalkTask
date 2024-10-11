import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import re
import subprocess

columns = [
    "ClientIP", "ClientRequestHost", "ClientRequestMethod", "ClientRequestURI",
    "EdgeStartTimestamp", "ZoneName", "ClientASN", "ClientCountry",
    "ClientDeviceType", "ClientSrcPort", "ClientRequestBytes",
    "ClientRequestPath", "ClientRequestReferer", "ClientRequestScheme",
    "ClientRequestUserAgent"
]

data = pd.read_csv('test-dataset.csv', names=columns, header=0)
data['EdgeStartTimestamp'] = pd.to_datetime(data['EdgeStartTimestamp'])
data['ClientRequestBytes'] = pd.to_numeric(data['ClientRequestBytes'], errors='coerce')

def check_injection(paths):
    injection_patterns = [
        r"\'", r"\"", r"\-\-", r"\;", r"\/\*", r"\*\/", r"UNION", r"SELECT", r"INSERT",
        r"DELETE", r"DROP", r"TABLE", r"\&\&", r"\|\|", r"\|", r"\>", r"\<", r"!",
        r"exec", r"system", r"cmd", r"javascript:", r"<", r">", r"\&", r"\#"
    ]
    injection_regex = re.compile('|'.join(injection_patterns), re.IGNORECASE)
    detected_injections = {}
    for pattern in injection_patterns:
        count = paths.str.contains(pattern, na=False).sum()
        if count > 0:
            detected_injections[pattern] = count
    return detected_injections

detected_injections = check_injection(data['ClientRequestPath'])

if detected_injections:
    print(f"Injeções detectadas (Total: {len(detected_injections)}):")
    for injection, count in detected_injections.items():
        print(f"{injection}: {count}")
    plt.figure(figsize=(12, 6))
    plt.bar(detected_injections.keys(), detected_injections.values(), color='red', alpha=0.7)
    plt.xlabel('Tipos de Injeção')
    plt.ylabel('Contagem')
    plt.title('Contagem de Tipos de Injeção Detectadas nos Paths')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
else:
    print("Nenhuma injeção detectada.")

injection_ip_counts = data[data['ClientRequestPath'].str.contains('|'.join(detected_injections.keys()), na=False)]['ClientIP'].value_counts()
ips_to_block = injection_ip_counts[injection_ip_counts > 5].index.tolist()

for ip in ips_to_block:
    print(f"Bloqueando IP: {ip}")
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

if len(ips_to_block) > 5:
    print("Bloqueando o range de IPs...")
    ip_range = ips_to_block[0].rsplit('.', 1)[0] + ".0/24"
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip_range, "-j", "DROP"])

ip_counts = data['ClientIP'].value_counts().nlargest(10)
plt.figure(figsize=(10, 6))
plt.bar(ip_counts.index, ip_counts.values, color='brown', alpha=0.7)
plt.xlabel('IP')
plt.ylabel('Contagem de Requisições')
plt.title('Top 10 IPs por Contagem de Requisições')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

country_counts = data['ClientCountry'].value_counts()
plt.figure(figsize=(10, 6))
plt.bar(country_counts.index, country_counts.values, color='lime', alpha=0.7)
plt.xlabel('País')
plt.ylabel('Contagem de Requisições')
plt.title('Contagem de Requisições por País')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

method_counts = data['ClientRequestMethod'].value_counts()
plt.figure(figsize=(8, 5))
plt.bar(method_counts.index, method_counts.values, color='blue', alpha=0.7)
plt.xlabel('Método de Requisição')
plt.ylabel('Contagem')
plt.title('Contagem de Métodos de Requisição')
plt.tight_layout()
plt.show()

uri_counts = data['ClientRequestURI'].value_counts().nlargest(10)
plt.figure(figsize=(10, 6))
plt.bar(uri_counts.index, uri_counts.values, color='green', alpha=0.7)
plt.xlabel('URL')
plt.ylabel('Contagem')
plt.title('Top 10 URLs Acessadas')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

referer_counts = data['ClientRequestReferer'].value_counts().nlargest(10)
plt.figure(figsize=(10, 6))
plt.bar(referer_counts.index, referer_counts.values, color='orange', alpha=0.7)
plt.xlabel('Referenciador')
plt.ylabel('Contagem')
plt.title('Top 10 Referenciadores')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

user_agent_counts = data['ClientRequestUserAgent'].value_counts().nlargest(10)
plt.figure(figsize=(10, 6))
plt.bar(user_agent_counts.index, user_agent_counts.values, color='purple', alpha=0.7)
plt.xlabel('User Agent')
plt.ylabel('Contagem')
plt.title('Top 10 User Agents')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

data['Hour'] = data['EdgeStartTimestamp'].dt.hour
hourly_counts = data['Hour'].value_counts().sort_index()
plt.figure(figsize=(10, 6))
plt.plot(hourly_counts.index, hourly_counts.values, marker='o', color='red')
plt.xlabel('Hora do Dia')
plt.ylabel('Contagem de Requisições')
plt.title('Contagem de Requisições por Hora do Dia')
plt.xticks(range(24))
plt.tight_layout()
plt.show()

device_counts = data['ClientDeviceType'].value_counts()
plt.figure(figsize=(8, 5))
plt.bar(device_counts.index, device_counts.values, color='cyan', alpha=0.7)
plt.xlabel('Tipo de Dispositivo')
plt.ylabel('Contagem')
plt.title('Contagem de Requisições por Tipo de Dispositivo')
plt.tight_layout()
plt.show()

asn_counts = data['ClientASN'].value_counts().nlargest(10)
plt.figure(figsize=(10, 6))
plt.bar(asn_counts.index.astype(str), asn_counts.values, color='magenta', alpha=0.7)
plt.xlabel('ASN')
plt.ylabel('Contagem')
plt.title('Top 10 ASN por Contagem de Requisições')
plt.tight_layout()
plt.show()
