#include "../header/sniffer.h"

/*
 * Печатает ethernet заголовок.
 *
 * @param packet    Заголовок ethernet
 *
 * @retval          Тип инкапсулированного протокола
 */
short ethernet_print(struct hdr_ethernet *header)
{
    /*
     * Выводим MAC назначения в цикле побайтно. Последний байт печатаем 
     * отдельно, тобы не напечатать лишнее двоеточее
     */
    printf("ETHERNET:\t");
    printf("dst ");
    for(int i = 0; i < 5; i++)
        printf("%x:", header->mac_dst[i]);
    printf("%x\t", header->mac_dst[5]);

    // Аналогично выводим MAC источника
    printf("src ");
    for(int i = 0; i < 5; i++)
        printf("%x:", header->mac_src[i]);
    printf("%x\t", header->mac_src[5]);
    /*
     * Следует учесть, что поля размером более одного байта нужно привести к 
     * хостовому виду из сетевого
     */ 
    header->type = ntohs(header->type);
    printf("type: %#04x\n", header->type);
    return ntohs(header->type);
}

/*
 * Получает размер заголовка ethernet
 *
 * @param packet    Заголовок ethernet
 *
 * @retval          Размер заголовка ethernet
 */
size_t ethernet_getsize(struct hdr_ethernet *header)
{
    return sizeof(struct hdr_ethernet);
}