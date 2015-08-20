# SpoofIP
##Introducción
Código desarrolado en C que permite la creación de datagramas de usuario (UDP) usando la técnica de IP spoofing. 
Para la creación de los sockets se usa Winsock2 por lo que solo se puede compìlar y usar en SO Windows. 

A diferencia de otras muchas herramientas, es capaz de generar correctamente el datagrama de usuario usando una pseudo-cabecera IP y realizando el cálculo del campo checksum de UDP.

##Cosas a tener en cuenta
- Los datos enviados están *hardcodeados* en la variable ```char *data```.
- No se pueden crear segmentos TCP (To-Do).
- Puedes cambiar el número de datagramas de usuario a enviar modificando la línea ```for (int count = 0; count < 1; count++)``` y cambiar el retraso entre cada datagrama de usuario modificando ```Sleep(2);``` (To-Do, #define o parámetro de consola).
- No funciona si vuestro router hace NAT (obvio, pero para algunos no tan obvio).
