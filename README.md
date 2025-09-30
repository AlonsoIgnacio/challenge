# Desafío de Procesamiento de Alertas de Seguridad

Este proyecto contiene un script de Python (`main.py`) diseñado para automatizar el procesamiento de alertas de seguridad. El script lee archivos de alerta en formato JSON, los enriquece con inteligencia de amenazas, calcula una severidad basada en una lógica de triaje y genera un informe de incidente detallado.

## Requisitos Previos

Asegúrate de tener **Python 3.x** instalado en tu sistema. Puedes verificarlo abriendo una terminal y ejecutando:

```bash
python --version

```

## Instalación

El script depende de las bibliotecas Jinja2 y PyYAML. Para instalarlas, navega a la carpeta del proyecto en tu terminal y ejecuta:
```bash
pip install jinja2 PyYAML


```


## Uso

Para procesar una alerta, simplemente ejecuta el script main.py pasando la ruta al archivo de alerta JSON como argumento.

Por ejemplo, para procesar la alerta de Sentinel o SUMO logic, usa:

```bash

python main.py alerts/sentinel.json

python main.py alerts/sumologic.json

```

Tras la ejecución, el script generará nuevos archivos en el directorio out/:

- Un archivo JSON del incidente completo en out/incidents/.
- Un resumen del incidente en formato Markdown en out/summaries/.
- Si la condicion lo requiere, se registrará una acción de aislamiento en out/isolation.log.

## Estructura del Proyecto

- main.py: El script principal de Python que ejecuta toda la lógica de procesamiento.

- alerts/: Contiene los archivos de alerta de entrada que simulan las alertas del sistema de seguridad.

- configs/: Incluye archivos de configuración en formato YAML para la lista de permitidos (allowlists.yml) y el mapeo de técnicas MITRE ATT&CK (mitre_map.yml).

- mocks/it/: Simula las respuestas de servicios de inteligencia de amenazas para enriquecer los indicadores de compromiso.

- out/: Directorio de salida para todos los archivos generados:

- incidents/: Archivos JSON de incidentes generados.

- summaries/: Resúmenes de incidentes en formato Markdown.

- isolation.log: Registro de los dispositivos que fueron aislados automáticamente.

- templates/analyst_summary.j2: Plantilla Jinja2 utilizada para generar los resúmenes en Markdown.


## Deficiencias y posibles mejoras:


- Lógica de enriquecimiento "hardcodeada": Actualmente usa rutas fijas a archivos mock. Se podría hacer dinámico según tipo y valor de indicador, o incluso integrar llamadas a APIs reales usando connectors.yml.

- Alineado con lo anterior -> Configuración no utilizada: configs/connectors.yml no se integra al script; Esto seguramente seria remplazado por una integracion por API contra la fuente de CTI.

- Manejo de errores: Hoy el script asume que los archivos siempre existen y son correctos. Usar try...except para errores como FileNotFoundError o json.JSONDecodeError haría el código más robusto.

- Refactorización de código: Hay repetición en la función enrich_indicators y la verificación de allowlists. Crear una función genérica para manejar distintos tipos de indicadores reduciría duplicación y mejoraría mantenibilidad.
