# Linux Infra Audit Tool

Script de auditoría en Python para diagnosticar **saturación de servidores Linux** con servicios web y base de datos (cPanel/WHM, CloudLinux, Ubuntu, Debian). Identifica qué servicio, usuario o query está consumiendo los recursos **en este momento** y genera recomendaciones de tuning para PHP-FPM, MySQL/MariaDB, Apache y Nginx.

## Qué analiza

1. **Consumo actual**: CPU instantáneo (ventana de 1s) y RAM por proceso, por usuario y por servicio — leído directamente de `/proc`, sin depender de `ps`.
2. **Recursos**: RAM, swap, eventos del OOM killer, I/O wait.
3. **Disco**: uso de particiones, inodos, latencia I/O por dispositivo (incluye NVMe).
4. **MySQL/MariaDB**: processlist, queries lentas activas, eficiencia del buffer pool, tablas MyISAM (genera script de migración a InnoDB), deadlocks, MySQLTuner.
5. **PHP-FPM**: workers activos y RAM real, pools cPanel ordenados por `max_children`, slow logs por usuario.
6. **Apache/Nginx**: workers, validación de configuración, detección de `MaxRequestWorkers` alcanzado.
7. **Correo**: cola de Exim, top remitentes, buzones pesados en Dovecot.
8. **CloudLinux**: LVE (`lvectl`/`lveinfo`) y DB Governor (usuarios restringidos por consumo MySQL).
9. **Seguridad básica**: intentos SSH fallidos, puertos en escucha, UID 0, firewall (CSF/UFW).
10. **Servicios y logs**: estado systemd de servicios críticos, errores recientes.
11. **Conexiones web por IP**: detecta floods/bots que saturan Apache y PHP-FPM.

Al final produce un **resumen ejecutivo** con hallazgos críticos, advertencias y recomendaciones, más un reporte en texto plano.

## Requisitos

- Linux con `/proc` (CentOS 7/8, RHEL 8, AlmaLinux/CloudLinux 8, Ubuntu 20/22, Debian 10/11)
- Python 3.6+
- Ejecutar como **root**
- Opcional: `perl` (para MySQLTuner), acceso MySQL como root sin contraseña interactiva (usa `~/.my.cnf` o socket auth)

## Uso

```bash
sudo python3 infra_audit.py
```

Salidas:

```
/root/infra_audit_FECHA.txt          # reporte completo sin colores ANSI
/root/migrate_myisam_to_innodb.sql   # solo si hay tablas MyISAM
```

Filtros rápidos sobre el reporte:

```bash
grep '✘' /root/infra_audit_*.txt   # críticos
grep '⚠' /root/infra_audit_*.txt   # advertencias
grep '→' /root/infra_audit_*.txt   # recomendaciones
```

## Notas importantes

- La métrica de CPU es una **ventana de 1 segundo**: ejecuta el script *durante* el episodio de saturación, no después.
- Las recomendaciones son **puntos de partida**, no valores finales. Valida cada cambio contra la RAM/CPU real del servidor antes de aplicarlo.
- El script de migración MyISAM→InnoDB debe ejecutarse en ventana de mantenimiento, con backup verificado y espacio libre en disco ≥ 2× la tabla más grande.
- **El reporte generado contiene información sensible del servidor** (IPs, usuarios, dominios, rutas). No lo subas a repositorios públicos ni lo compartas sin revisar.
- El script es de solo lectura: no modifica configuraciones. Las únicas escrituras son el reporte, el `.sql` de migración (que no se ejecuta automáticamente) y la descarga opcional de MySQLTuner.

## Licencia

MIT — ver [LICENSE](LICENSE).
