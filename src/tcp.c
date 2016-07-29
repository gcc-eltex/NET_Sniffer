#include "../header/sniffer.h"

/*
 * Печатает TCP заголовок.
 *
 * @param packet    Заголовок TCP
 *
 * @retval          Тип инкапсулированного протокола
 */
u_char tcp_print(struct hdr_tcp *header)
{
    printf("\nTCP:\t\t");
    printf("src %-20d", ntohs(header->portsrc));
    printf("dst %-20d", ntohs(header->portdst));
    printf("wsize: %-17d\n\t\t", ntohs(header->winsize));
    printf("hsize: %-17d", (int)tcp_getsize(header));
    printf("chsum: %#-17x", ntohs(header->chsum));
    return 0;
}

/*
 * Выполняет подсчет контрольной суммы TCP
 *
 * @param header_tcp    Указатель на начало заголовка TCP
 * @param header_ip     Указатель на начало заголовка IP
 * @param psize         Размер TCP пакета(заголовок + данные)
 *
 * @param size          Контрольная сумма
 */
u_short tcp_checksum(u_char *header_tcp, u_char *header_ip, size_t psize)
{
    u_char  header_psd[12]; // Псевдозаголовок
    int     chsum;          // Check сумма
    u_short fbyte;          // Первый байт 16ти битного блока
    u_short sbyte;          // Второй байт 16ти битного блока
    u_short tcpsize;

    // Формируем псевдозаголовок
    *((int *)header_psd) = ((struct hdr_ip *)header_ip)->ipsrc;
    *((int *)(header_psd + 4)) = ((struct hdr_ip *)header_ip)->ipdst;
    header_psd[8] = 0;
    header_psd[9] = ((struct hdr_ip *)header_ip)->type;
    tcpsize = ntohs(tcp_getsize((struct hdr_tcp *)header_tcp)) * 4;
    *((u_short *)(header_psd + 10)) = tcpsize;

    // Считаем контрольную сумму псевдозаголовка
    chsum = 0;
    for (int i = 0; i < 12; i+=2){
        fbyte = header_psd[i];
        sbyte = header_psd[i + 1];
        chsum += (fbyte<<8)|sbyte;
    }

    // Считаем контрольную сумму TCP заголовка и данных
    for (int i = 0; i < psize; i+=2){
        if (i == 16)
            continue;
        fbyte = header_tcp[i];
        sbyte = header_tcp[i + 1];
        chsum += (fbyte<<8)|sbyte;
    }

    chsum = chsum + (chsum>>16);
    return (u_short)~chsum;
}

/*
 * Получает размер заголовка TCP
 *
 * @param packet    Заголовок TCP
 *
 * @retval          Размер заголовка TCP
 */
size_t tcp_getsize(struct hdr_tcp *header)
{
    return (header->orflag&0xF0)>>4;
}

