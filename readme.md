https://www.youtube.com/watch?v=U7dp9bTwf3Q
IP Адресс, Маска подсети - 32бита
Адресс подсети = IP-Адресс (IXOR) Маска подсети. 	
Номер узла = IP-Адресс (XORI) Маска подсети
Любое устройство в локальной сети должно отвечать на arp запросы, иначе обмениваться данными используя ip протокол не получится.

ARP - MAC by IP
RARP - IP by MAC

UNICAST/BROADCAST/MULTICAST

ARP (Address Resolution Protocol – протокол определения адреса) – протокол в компьютерных сетях, предназначенный для определения MAC адреса по известному IP адресу.
http://csharpcoderr.com/2012/06/arp.html
https://www.youtube.com/watch?v=EZkkodleWqc
https://ab57.ru/cmdlist/arp.html

https://ru.wikipedia.org/wiki/%D0%9C%D0%B0%D1%81%D0%BA%D0%B0_%D0%BF%D0%BE%D0%B4%D1%81%D0%B5%D1%82%D0%B8
ARP

Programming:
1) Get SubNet MASK IPv4
GET SUBNET: https://weblogs.asp.net/razan/finding-subnet-mask-from-ip4-address-using-c 
2) GET NICS
https://docs.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface?redirectedfrom=MSDN&view=netframework-4.8
3) https://help.keenetic.com/hc/ru/articles/213965829-%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D1%80-%D1%80%D0%B0%D1%81%D1%87%D0%B5%D1%82%D0%B0-%D0%BA%D0%BE%D0%BB%D0%B8%D1%87%D0%B5%D1%81%D1%82%D0%B2%D0%B0-%D1%85%D0%BE%D1%81%D1%82%D0%BE%D0%B2-%D0%B8-%D0%BF%D0%BE%D0%B4%D1%81%D0%B5%D1%82%D0%B5%D0%B9-%D0%BD%D0%B0-%D0%BE%D1%81%D0%BD%D0%BE%D0%B2%D0%B5-IP-%D0%B0%D0%B4%D1%80%D0%B5%D1%81%D0%B0-%D0%B8-%D0%BC%D0%B0%D1%81%D0%BA%D0%B8