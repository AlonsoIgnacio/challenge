Desafío de Procesamiento de Alertas de Seguridad
Este proyecto contiene un script de Python (main.py) diseñado para automatizar el procesamiento de alertas de seguridad. El script lee archivos de alerta en formato JSON, los enriquece con inteligencia de amenazas, calcula una severidad basada en una lógica de triaje y genera un informe de incidente detallado.

Requisitos Previos
Asegúrate de tener Python 3.x instalado en tu sistema. Puedes verificarlo abriendo una terminal y ejecutando:

Bash

python --version
Instalación
El script depende de las bibliotecas Jinja2 y PyYAML. Para instalarlas, navega a la carpeta del proyecto en tu terminal y ejecuta el siguiente comando:

Bash

pip install jinja2 PyYAML
Uso
Para procesar una alerta, simplemente ejecuta el script main.py pasando la ruta al archivo de alerta JSON como argumento.

Por ejemplo, para procesar la alerta de Sentinel, usa:

Bash

python main.py alerts/sentinel.json
O, para la alerta de Sumologic:

Bash

python main.py alerts/sumologic.json
Tras la ejecución, el script generará nuevos archivos en el directorio out/:

Un archivo JSON del incidente completo en out/incidents/.

Un resumen del incidente en formato Markdown en out/summaries/.

Si la severidad es alta, se registrará una acción de aislamiento en out/isolation.log.

Estructura del Proyecto
main.py: El script principal de Python que ejecuta toda la lógica de procesamiento.

alerts/: Contiene los archivos de alerta de entrada que simulan las alertas del sistema de seguridad.

configs/: Incluye archivos de configuración en formato YAML para la lista de permitidos (allowlists.yml) y el mapeo de técnicas MITRE ATT&CK (mitre_map.yml).

mocks/it/: Simula las respuestas de servicios de inteligencia de amenazas para enriquecer los indicadores de compromiso.

out/: El directorio de salida para todos los archivos generados:

incidents/: Los archivos JSON de incidentes generados.

summaries/: Los resúmenes de incidentes en formato Markdown.

isolation.log: Un registro de los dispositivos que fueron aislados automáticamente.

templates/analyst_summary.j2: La plantilla Jinja2 utilizada para generar los resúmenes en Markdown.
