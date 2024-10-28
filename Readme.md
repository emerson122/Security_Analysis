LogAnomalyDetector: Detecta anomalías en logs usando machine learning

Características principales:

Usa Isolation Forest para detectar comportamientos anómalos
Analiza patrones en los logs de autenticación
Extrae características como frecuencia de eventos, ratio de fallos, etc.
Genera reportes detallados de anomalías




LogEnrichment: Enriquece los datos con información adicional

Características principales:

Integración con múltiples APIs (VirusTotal, AbuseIPDB)
Obtiene geolocalización de IPs
Verifica reputación y amenazas activas
Sistema de caché para optimizar consultas





Para usar los scripts:

Instala las dependencias necesarias:

``` bash
pip install pandas numpy scikit-learn aiohttp

```

Configura las API keys en el script (opcional):
``` bash
enricher = LogEnrichment(
    virustotal_api_key="TU_API_KEY",
    abuseipdb_api_key="TU_API_KEY"
)
```