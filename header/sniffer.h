#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <pcap.h>

#define TYPE_IP     0x08
#define TYPE_TCP    0x06

/*
 * Структура заголовка ethernet. В отличии от других заголовков имеет 
 * фиксированный размер, равный размеру структуры
 */
struct hdr_ethernet
{
    u_char  mac_dst[6];    // MAC адрес получателя    
    u_char  mac_src[6];    // MAC адрес отправителя
    short   type;          // Тип инкапсулированного протокала
};

/*
 * Структура заголовка ip. Реальный размер заголовка определяется 
 * соответствующим полем в структуре, а не размером структуры
 */
struct hdr_ip
{
    u_char  vhs;        // Первые 4 бита - размер заголовка, остальные версия
    u_char  ed;         // Первые 2 бита - Explicit Congestion Notification, 
                        // остальные Differentiated Services Code Point
    short   psize;      // Полный размер пакета
    short   id;         // Идентификатор фрагмента
    short   foffset;    // Последние 3 бита - флаги, остальное смещение 
                        // фрагмента 
    u_char  ttl;        // Время жизни
    u_char  type;       // Тип инкапсулированного протокала
    short   chsum;      // Контрольная сумма заголовка
    int     ipsrc;      // IP адрес источника
    int     ipdst;      // IP адрес назначения
    int     opt;        // Дополнительные опции, если размер заголовка > 5
};

/*
 * Структура заголовка tcp. Реальный размер заголовка определяется 
 * соответствующим полем в структуре, а не размером структуры
 */
struct hdr_tcp
{
    short   portsrc;    // Порт источника
    short   portdst;    // Порт назначения
    int     seqnum;     // Порядковый номер
    int     acknum;     // Номер подтверждения
    short   orflag;     // Длина заголовка (4бита), резерв (3бита), флаги - 
                        // остальное
    short   winsize;    // Размер окна
    short   chsum;      // Контрольная сумма пакета
    short   urgent;     // Смещение, до конца данных
    int     opt;        // Дополнительные опции, если размер заголовка > 5
};

// Модуль ethernet.c
short ethernet_print(struct hdr_ethernet *header);
size_t ethernet_getsize(struct hdr_ethernet *header);

// Модуль ip.c
u_char ip_print(struct hdr_ip *header);
short ip_checksum(u_char *header);
size_t ip_getsize(struct hdr_ip *header);

//Модуль tcp.c
u_char tcp_print(struct hdr_tcp *header);
u_short tcp_checksum(u_char *header_tcp, u_char *header_ip, size_t psize);
size_t tcp_getsize(struct hdr_tcp *header);