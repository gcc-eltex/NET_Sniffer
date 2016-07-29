#include "../header/sniffer.h"

/*
 * Печатает IP заголовок.
 *
 * @param header    Заголовок IP
 *
 * @retval          Тип инкапсулированного протокола
 */
u_char ip_print(struct hdr_ip *header)
{
    struct in_addr  ip;         // IP аддрес для конвертации в точечный вид

    printf("\nIP:\t\t");
    ip.s_addr = header->ipsrc;
    printf("dst %-20s", inet_ntoa(ip));
    ip.s_addr = header->ipdst;
    printf("src %-20s", inet_ntoa(ip));
    printf("type: %#-19x\n\t\t", header->type);
    printf("ttl: %-19d", header->ttl);
    /*
     * Следует учесть, что поля размером более одного байта нужно привести к 
     * хостовому виду из сетевого
     */ 
    printf("chsum: %#-17x", ntohs(header->chsum));
    printf("calc_chsum: %#x\n", (u_short)ip_checksum((u_char *)header));
    return header->type;
}

/*
 * Выполняет подсчет контрольной суммы заголовка IP
 *
 * @param packet    Указатель на начало заголовка
 *
 * @param size      Длина заголовка в октетах
 */
short ip_checksum(u_char *header)
{
    int     chsum;  // Контрольная сумма
    u_short fbyte;  // Первый байт 16ти битного блока
    u_short sbyte;  // Второй байт 16ти битного блока
    int 	size;	// Размер заголовка

    /*
     * Считаем сумму пропуская поле контрольной суммы в заголовке. 
     * Суммирование производим 16ти битными блоками
     */
    chsum = 0;
    size = ip_getsize((struct hdr_ip *)header);
    for (int i = 0; i < size * 4; i+=2){
        if(i == 10)
            continue;
        fbyte = header[i];
        sbyte = header[i + 1];
        chsum += (fbyte<<8)|sbyte;
    }
    /*
    * Добавляем переполненое значение к основному, и инвертируем. При 
    * возврате оставляем только 16 младших бит, а остальное обнуляем
    */
    chsum = chsum + (chsum>>16);
    return (u_short)~chsum;
}

/*
 * Получает размер заголовка IP
 *
 * @param packet    Заголовок IP
 *
 * @retval          Размер заголовка IP
 */
size_t ip_getsize(struct hdr_ip *header)
{
    return header->vhs&0x0F;
}