from ipwhois import IPWhois

def obter_asn(ip):
    try:
        ip_info = IPWhois(ip)
        resultado = ip_info.lookup_whois()
        return resultado.get('asn')
    except Exception as e:
        return f"Erro ao obter ASN para {ip}: {e}"

def main():
    with open('lista_ips.txt', 'r') as file:
        ips = [linha.strip() for linha in file.readlines()]

    for ip in ips:
        asn = obter_asn(ip)
        print(f"IP: {ip}, ASN: {asn}")

if __name__ == "__main__":
    main()
