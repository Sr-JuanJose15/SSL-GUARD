import asyncio
import json
from app.scanner import analyze_domain, poll_status

async def main():
    
    dominio = input("Ingrese el dominio a analizar: ")
    
    print(f"[*] Iniciando análisis de seguridad para: {dominio}")
    
    try:
        # Le pusimos start_new=True para forzar el análisis y ver el porcentaje avanzar
        estado_inicial = await analyze_domain(dominio, start_new=True)
        print(f"[+] Análisis iniciado en servidores de Qualys.\n")
        
        # El polling ahora mostrará el progreso dinámico en la misma línea
        resultado_final = await poll_status(dominio)
        
        print(f"\n\n[+] ¡Análisis Completado!")
        print(f"Calificación general TLS (Grade): {resultado_final['endpoints'][0]['grade']}")
        
        # Guardamos la "mina de oro" de datos
        with open("resultado_prueba.json", "w", encoding="utf-8") as f:
            json.dump(resultado_final, f, indent=4)
            
        print("[+] Se ha guardado el reporte COMPLETO en 'resultado_prueba.json'")
        
    except Exception as e:
        print(f"\n[-] Ocurrió un error: {e}")

if __name__ == "__main__":
    asyncio.run(main())