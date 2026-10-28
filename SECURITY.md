# Uso seguro del laboratorio

Este laboratorio levanta, **a propósito**, un contenedor con software vulnerable. Está
pensado para estudiar y defender, no para atacar.

## Reglas

1. **Entorno aislado.** Correr solo en tu máquina, dentro de los contenedores que define
   este repo. Nunca contra sistemas de producción, de la facultad ni de terceros.
2. **Sin exponer a la red.** El contenedor no publica puertos hacia afuera: se opera por
   `docker exec` y por el dashboard local. No lo expongas en `0.0.0.0` ni detrás de un dominio.
3. **Desechable.** El contenedor es de usar y tirar: `docker compose down -v` lo elimina
   por completo. No guardes datos reales adentro.
4. **No contiene exploits weaponizados.** Ver el README. El punto de explotación está
   documentado conceptualmente; cualquier PoC se usa bajo tu responsabilidad y en
   aislamiento.
5. **Divulgación responsable.** Las vulnerabilidades estudiadas ya están parcheadas por el
   proyecto sudo (1.9.17p1+). La mejor mitigación real siempre es actualizar.

## Qué hacer si algo sale mal

- Apagar y limpiar todo: `docker compose down -v`.
- Verificar que no quedaron contenedores: `docker ps -a | grep sudo-lab`.

## Vulnerabilidades reales corregidas

| CVE | Corregida en |
| --- | --- |
| CVE-2025-32463 | sudo 1.9.17p1 |
| CVE-2025-32462 | sudo 1.9.17p1 |
| CVE-2023-22809 | sudo 1.9.12p2 |
| CVE-2021-3156  | sudo 1.9.5p2 |
| CVE-2019-14287 | sudo 1.8.28 |

Si administrás sistemas reales: actualizá sudo y verificá con `sudo -V`.
