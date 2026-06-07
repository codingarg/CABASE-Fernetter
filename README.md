# CABASE-Fernetter
## 🕵️‍♂️ Ataque quirúrgico al IXP: Cómo tumbaron sesiones BGP con solo 1 paquete por segundo (y cómo lo descubrimos)

No es la primera vez que vemos que para causar un impacto masivo en una infraestructura crítica no se necesitan gigabits de tráfico malicioso. A veces, el conocimiento profundo de los protocolos permite a un atacante diseñar un ataque invisible para los sistemas de monitoreo tradicionales. 

Hace poco se detectó una anomalía sumamente grave en la estructura de interconexión de CABASE que dejó fuera de juego las sesiones BGP de múltiples miembros en cuestión de segundos.

### 👀 El Contexto y la Maniobra Genial (pero destructiva)
El objetivo del atacante eran los **Route Servers**. En lugar de inundarlos con tráfico (flood), idearon una estrategia de suplantación de identidad utilizando paquetes ICMP modificados y haciendo *IP Spoofing* con la dirección IP de los propios Route Servers.

Para distribuir el ataque hacia todos los miembros de la IX sin levantar sospechas, inyectaron estos paquetes a través de diferentes carriers conectados, como HE, EdgeUno y nuestra propia red de LINKEAR. 

¿Cuál era el fin? Al recibir estos paquetes forjados, los equipos de los miembros **reemplazaban la tabla ARP**, asociando falsamente la IP del Route Server a las direcciones MAC de los carriers intermediarios. Con solo **1 paquete por segundo por miembro**, desviaban el tráfico, rompiendo el saludo de red y tumbando las sesiones BGP al instante. Lo peor: no dejaba rastro de saturación en los gráficos de ancho de banda.

### 👌 El Diagnóstico: Cazando el fantasma en los logs
Cuando las sesiones BGP caen a gran escala pero los enlaces están vacíos, la mayoría de los administradores buscan problemas de hardware o caídas generales de enlaces. Sin embargo, gracias a una lectura minuciosamente detallada de los logs, notamos algo extraño: las sesiones morían reportando un estado de **"Unreachable"** (inalcanzable).

Decidimos sniffear el tráfico directamente en la interfaz de uno de los miembros afectados en tiempo real. 

Ahí apareció la confirmación: en el milisegundo exacto en que ingresaba el paquete ICMP forjado desde el exterior, la tabla ARP del router miembro mutaba, apuntando el tráfico del Route Server hacia una ruta completamente incorrecta. El misterio estaba resuelto.

### ⚠️ La variante crítica: Ataques silenciosos dirigidos al Puerto 179 (BGP)

El ataque también es completamente válido (y se vuelve exponencialmente más difícil de detectar) si el atacante, en lugar de enviar un paquete ICMP echo request, envía un paquete `SYN` dirigido directamente al **puerto 179** (el puerto estándar que utiliza BGP). 

Dado que tanto los Route Servers como los routers de los miembros de la IXP tienen este puerto lógicamente abierto para permitir el vecindario, los equipos siempre procesarán la petición y responderán con un `SYN-ACK`. En ese milisegundo, debido a la suplantación de identidad (spoofing), los dispositivos actualizan de inmediato su tabla de direcciones MAC y su caché ARP con la información del carrier intermediario por donde ingresó el paquete. 

¿El resultado? El tráfico legítimo de la sesión BGP se desvía instantáneamente hacia una ruta muerta, destruyendo la adyacencia de los *peers* de forma silenciosa y sin levantar una sola alerta por inundación o denegación de servicio tradicional.

### 🎩 La Solución Definitiva (Seguridad en el plano de acceso y control)
Para solucionar esta vulnerabilidad de inmediato y blindar la infraestructura a nivel de capa 2 y capa 3, implementamos dos medidas complementarias en caliente:

1. **Inspección de puertos en los Switches (Switchport Security / IP Source Guard):** Configuramos reglas estrictas en las interfaces de los switches del IXP. A partir de ese momento, el sistema descarta en el acto cualquier paquete cuyo *Source IP* (IP de origen) intente suplantar a la de los Route Servers, bloqueando el spoofing desde el origen.
2. **ARP Estático en los Route Servers:** Para evitar que el ataque se replicara a la inversa (atacar a los Route Servers envenenando su propia tabla respecto a los miembros), fijamos las entradas ARP de forma estática en los servidores de enrutamiento.

### 🤓 Conclusión de la Resiliencia
> Una vez aplicadas las directrices de inspección en los switchports y el ARP estático, volvimos a monitorear la red. Las tablas ARP se mantuvieron inmutables, el tráfico fluyó por los caminos correctos y **las sesiones BGP no volvieron a caer**. El plano de control recuperó su estabilidad absoluta frente a ataques de manipulación de identidad.

---

Este caso nos recuerda que en redes de gran escala, la seguridad no se limita a comprar un firewall gigante para frenar ataques volumétricos; se trata de entender la lógica de los protocolos básicos (como ARP e ICMP) y auditar los logs con ojo clínico.

¿Tu red cuenta con mecanismos de mitigación contra spoofing de IP o manipulación de tablas de direccionamiento local?

Si querés auditar la seguridad de tu infraestructura de red o conocer más sobre cómo protegemos entornos críticos en Waugi, escribinos a **hola@waugi.com** o por mensaje privado. ¡Coordinemos una sesión técnica!
