# anomaly_detector.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
import re
from datetime import datetime
import logging
from pathlib import Path

class LogAnomalyDetector:
    def __init__(self, log_path="/var/log/auth.log", model_contamination=0.1):
        """
        Inicializa el detector de anomalías para logs.
        
        Args:
            log_path (str): Ruta al archivo de log
            model_contamination (float): Proporción esperada de anomalías
        """
        self.log_path = Path(log_path)
        self.contamination = model_contamination
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=self.contamination, random_state=42)
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('AnomalyDetector')

    def parse_log_line(self, line):
        """Parsea una línea de log y extrae características relevantes."""
        try:
            # Patrón básico para logs de autenticación
            pattern = r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*?((?:Failed|Invalid|Success|Accepted).*?)(?:from\s+(\d+\.\d+\.\d+\.\d+))?'
            match = re.search(pattern, line)
            
            if match:
                timestamp = match.group(1)
                event_type = match.group(2)
                ip = match.group(3) if match.group(3) else "local"
                
                return {
                    'timestamp': timestamp,
                    'event_type': event_type,
                    'ip': ip
                }
            return None
        except Exception as e:
            self.logger.error(f"Error parsing log line: {e}")
            return None

    def extract_features(self, logs_df):
        """Extrae características numéricas de los logs para el análisis."""
        features = pd.DataFrame()
        
        # Agrupar eventos por IP
        ip_groups = logs_df.groupby('ip')
        
        features['event_count'] = ip_groups.size()
        features['failed_ratio'] = ip_groups.apply(
            lambda x: len([e for e in x.event_type if 'Failed' in e]) / len(x)
        )
        features['unique_events'] = ip_groups.event_type.nunique()
        
        return features.fillna(0)

    def train_and_detect(self):
        """Entrena el modelo y detecta anomalías en los logs."""
        try:
            # Leer y parsear logs
            logs = []
            with open(self.log_path, 'r') as file:
                for line in file:
                    parsed = self.parse_log_line(line)
                    if parsed:
                        logs.append(parsed)
            
            if not logs:
                self.logger.warning("No logs found to analyze")
                return []
            
            logs_df = pd.DataFrame(logs)
            
            # Extraer características
            features = self.extract_features(logs_df)
            
            # Normalizar datos
            X = self.scaler.fit_transform(features)
            
            # Entrenar modelo y detectar anomalías
            predictions = self.model.fit_predict(X)
            
            # Identificar anomalías
            anomalies = features[predictions == -1]
            
            # Generar reporte
            report = []
            for ip in anomalies.index:
                events = logs_df[logs_df.ip == ip]
                report.append({
                    'ip': ip,
                    'event_count': int(features.loc[ip, 'event_count']),
                    'failed_ratio': float(features.loc[ip, 'failed_ratio']),
                    'unique_events': int(features.loc[ip, 'unique_events']),
                    'recent_events': events.tail(5).to_dict('records')
                })
            
            self.logger.info(f"Detected {len(report)} anomalies")
            return report
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return []

# enrichment_analyzer.py
class LogEnrichment:
    def __init__(self, virustotal_api_key=None, abuseipdb_api_key=None):
        """
        Inicializa el enrichment de logs con APIs de terceros.
        
        Args:
            virustotal_api_key (str): API key para VirusTotal
            abuseipdb_api_key (str): API key para AbuseIPDB
        """
        self.vt_api_key = virustotal_api_key
        self.abuse_api_key = abuseipdb_api_key
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('LogEnrichment')
        
        # Cache para evitar consultas repetidas
        self.ip_cache = {}

    async def get_ip_info(self, ip):
        """Obtiene información de una IP desde múltiples fuentes."""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        info = {
            'ip': ip,
            'geolocation': await self._get_geolocation(ip),
            'reputation': await self._get_reputation(ip),
            'active_threats': await self._check_threats(ip)
        }
        
        self.ip_cache[ip] = info
        return info

    async def _get_geolocation(self, ip):
        """Obtiene información de geolocalización de una IP."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://ipapi.co/{ip}/json/') as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'country': data.get('country_name'),
                            'city': data.get('city'),
                            'region': data.get('region'),
                            'org': data.get('org')
                        }
        except Exception as e:
            self.logger.error(f"Error getting geolocation for {ip}: {e}")
        return None

    async def _get_reputation(self, ip):
        """Consulta la reputación de una IP en AbuseIPDB si está disponible."""
        if not self.abuse_api_key:
            return None
            
        try:
            headers = {
                'Key': self.abuse_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'abuse_confidence_score': data['data']['abuseConfidenceScore'],
                            'total_reports': data['data']['totalReports'],
                            'last_reported_at': data['data'].get('lastReportedAt')
                        }
        except Exception as e:
            self.logger.error(f"Error checking IP reputation: {e}")
        return None

    async def _check_threats(self, ip):
        """Verifica amenazas activas usando VirusTotal si está disponible."""
        if not self.vt_api_key:
            return None
            
        try:
            headers = {
                'x-apikey': self.vt_api_key
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'malicious_count': data['data']['attributes']['last_analysis_stats']['malicious'],
                            'suspicious_count': data['data']['attributes']['last_analysis_stats']['suspicious']
                        }
        except Exception as e:
            self.logger.error(f"Error checking threats: {e}")
        return None

    async def enrich_anomalies(self, anomalies):
        """Enriquece una lista de anomalías con información adicional."""
        enriched_anomalies = []
        
        for anomaly in anomalies:
            if 'ip' in anomaly and anomaly['ip'] != 'local':
                ip_info = await self.get_ip_info(anomaly['ip'])
                enriched_anomaly = {**anomaly, 'enrichment': ip_info}
                enriched_anomalies.append(enriched_anomaly)
            else:
                enriched_anomalies.append(anomaly)
        
        return enriched_anomalies

# Ejemplo de uso
if __name__ == "__main__":
    import asyncio
    import json
    
    async def main():
        # Inicializar detector de anomalías
        detector = LogAnomalyDetector()
        anomalies = detector.train_and_detect()
        
        if anomalies:
            # Inicializar enrichment (reemplazar con tus API keys)
            enricher = LogEnrichment(
                virustotal_api_key="YOUR_VT_API_KEY",
                abuseipdb_api_key="YOUR_ABUSE_API_KEY"
            )
            
            # Enriquecer anomalías
            enriched_data = await enricher.enrich_anomalies(anomalies)
            
            # Guardar resultados
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f'security_analysis_{timestamp}.json'
            
            with open(output_file, 'w') as f:
                json.dump(enriched_data, f, indent=2)
            
            print(f"Analysis complete. Results saved to {output_file}")
        else:
            print("No anomalies detected")

    asyncio.run(main())