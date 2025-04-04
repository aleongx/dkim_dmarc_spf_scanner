import dns.resolver
import argparse
import time
from colorama import Fore, init

init(autoreset=True)

# Función para mostrar el banner
def banner():
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + "  DKIM-DMARC-SPF-MX Checker by Alejandro Leon AKA GX ")
    print(Fore.CYAN + "  Uso ético y autorizado solamente ⚡")
    print(Fore.CYAN + "="*60 + "\n")

# Función para analizar SPF
def check_spf(domain):
    print(Fore.GREEN + "Analizando SPF...")
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text()
            if txt_record.startswith('"v=spf1'):
                print(Fore.GREEN + f"SPF encontrado: {txt_record}")
                print(Fore.CYAN + "="*60 + "\n")  # Separador estético
                return
        print(Fore.RED + "SPF no encontrado")
        print(Fore.CYAN + "="*60 + "\n")
    except Exception as e:
        print(Fore.RED + f"Error al buscar SPF: {e}")
        print(Fore.CYAN + "="*60 + "\n")

# Función para analizar DKIM
def check_dkim(domain):
    print(Fore.GREEN + "Analizando DKIM...")
    selectores_comunes = ['default', 'selector1', 'selector2', 'mail']
    for selector in selectores_comunes:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                print(Fore.GREEN + f"DKIM encontrado con selector '{selector}': {rdata.to_text()}")
                print(Fore.CYAN + "="*60 + "\n")  # Separador estético
                return
        except dns.resolver.NoAnswer:
            continue  # Si no se encuentra, seguir probando con otros selectores
        except Exception as e:
            print(Fore.RED + f"Error al buscar DKIM con selector '{selector}': {e}")
            print(Fore.CYAN + "="*60 + "\n")
    
    print(Fore.RED + "No se encontró DKIM con los selectores comunes")
    print(Fore.CYAN + "="*60 + "\n")

# Función para analizar DMARC
def check_dmarc(domain):
    print(Fore.GREEN + "Analizando DMARC...")
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            print(Fore.GREEN + f"DMARC encontrado: {rdata.to_text()}")
            print(Fore.CYAN + "="*60 + "\n")  # Separador estético
            return
        print(Fore.RED + "DMARC no encontrado")
        print(Fore.CYAN + "="*60 + "\n")
    except Exception as e:
        print(Fore.RED + f"Error al buscar DMARC: {e}")
        print(Fore.CYAN + "="*60 + "\n")

# Función para analizar los registros MX
def check_mx(domain):
    print(Fore.GREEN + "Analizando registros MX...")
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        if answers:
            for rdata in answers:
                print(Fore.GREEN + f"Registro MX encontrado: {rdata.exchange} con prioridad {rdata.preference}")
            print(Fore.CYAN + "="*60 + "\n")  # Separador estético
        else:
            print(Fore.RED + "No se encontraron registros MX")
            print(Fore.CYAN + "="*60 + "\n")
    except Exception as e:
        print(Fore.RED + f"Error al buscar registros MX: {e}")
        print(Fore.CYAN + "="*60 + "\n")

# Función principal para coordinar el análisis
def main():
    # Mostrar el banner
    banner()

    # Configuración del parser para recibir el dominio
    parser = argparse.ArgumentParser(description='Verifica registros DMARC, DKIM, SPF y MX de un dominio')
    parser.add_argument('-d', '--domain', required=True, help='Dominio a verificar')
    args = parser.parse_args()
    
    domain = args.domain
    print(f"Verificando autenticación de correo en: {domain}\n")

    # Llamar a la función para verificar SPF
    check_spf(domain)
    time.sleep(5)  # Esperar 5 segundos entre verificaciones

    # Llamar a la función para verificar DKIM
    check_dkim(domain)
    time.sleep(5)

    # Llamar a la función para verificar DMARC
    check_dmarc(domain)
    time.sleep(5)

    # Llamar a la función para verificar MX
    check_mx(domain)

# Ejecutar la función principal si es el archivo principal
if __name__ == '__main__':
    main()
