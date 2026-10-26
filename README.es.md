# LogShield

### Comparte el log. No tus secretos.

Revisa y censura credenciales en archivos de texto y JSON **dentro de tu navegador**. Sin subidas, cuentas, dependencias ni compilación.

[Demo en vivo](https://0xsixtos.github.io/logshield/) · [English](README.md) · [Reglas del detector](dist/detector.js) · [Contribuir](CONTRIBUTING.md)

![Vista de LogShield](docs/preview.svg)

## Empezar

Requiere Node.js 20 o posterior. No necesitas instalar paquetes.

```sh
git clone https://github.com/0xSixtos/logshield.git
cd logshield
npm start
```

Abre **http://127.0.0.1:4317**. También puedes servir `dist/` desde cualquier servidor estático. Abrir directamente el HTML con `file://` no está soportado: la app utiliza módulos ES y un Web Worker.

1. Prueba el ejemplo ficticio o abre un archivo UTF-8 de hasta 2 MB.
2. Pulsa **Analizar texto** o `Ctrl+Enter` / `⌘+Enter`.
3. Revisa cada detección. Desmarcarla deja ese valor visible; la app te avisa cuántos quedan sin ocultar.
4. Descarga una copia, copia el texto o exporta un resumen de categorías y posiciones que no contiene los valores ni el nombre del archivo original.

## Incluido en v0.1

- Contraseñas, claves API, tokens, autorizaciones, cookies, claves privadas, credenciales en URL y correos electrónicos.
- Detección opcional de IPv4.
- Original y copia censurada lado a lado en escritorio; disposición vertical en pantallas pequeñas.
- Revisión individual y selección de todas las detecciones.
- JSON válido conserva su formato y sigue siendo válido al exportar. Las claves duplicadas se revisan por posición.
- Interfaz en español e inglés, sin servicios externos de traducción.
- Bloqueo de exportación si cambió el texto o se alcanzó el límite de detecciones.

## Privacidad y límites

El contenido se procesa en memoria en la pestaña. La app no implementa subidas, almacenamiento del navegador, historial, cookies ni analítica. La política de contenido bloquea conexiones salientes de la aplicación. Una versión alojada sí descarga sus recursos estáticos y su proveedor puede conservar registros normales de acceso.

**Los patrones pueden omitir secretos y producir falsos positivos.** No verifican que una credencial exista o esté activa. No se garantiza detectar datos codificados, formatos inusuales o secretos sin una forma reconocible. No incluye OCR, teléfonos, tarjetas, tratamiento específico de HAR ni escaneo de repositorios.

Revisa siempre el resultado antes de compartir. Limpiar elimina el contenido de la interfaz; no promete borrado forense de la memoria del navegador. Si una credencial ya se filtró, reemplázala en el servicio correspondiente.

## Probar el detector

```sh
npm test
```

Las pruebas usan datos ficticios e incluyen JSON, escapes, coincidencias superpuestas, límites, posiciones y exclusiones manuales.

## Contribuir

Se agradecen casos de prueba ficticios, mejoras de accesibilidad y traducciones. No incluyas credenciales reales ni archivos personales en incidencias o solicitudes de cambios.

Licencia [MIT](LICENSE). Creado por [0xSixtos](https://github.com/0xSixtos).
