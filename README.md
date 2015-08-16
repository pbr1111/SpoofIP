# SpoofIP
##Introducción
Código desarrolado en C que permite la creación de datagramas de usuario (UDP) usando la técnica de IP spoofing. 
Para la creación de los sockets se usa Winsock2 por lo que solo se puede compìlar y usar en SO Windows. 

A diferencia de otras muchas herramientas, es capaz de generar correctamente el datagrama de usuario usando una pseudo-cabecera IP y realizando el cálculo del campo checksum de UDP.


##Cosas a tener en cuenta
- Los datos enviados están *hardcodeados* en la variable ```char *data```.
- No se pueden crear segmentos TCP (To-Do).
