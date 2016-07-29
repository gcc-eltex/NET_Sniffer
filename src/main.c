#include "../header/sniffer.h"

#define DEV_NAME    "enp3s0"    // Имя прослушиваемого интерфейса
#define LINE_LEN    22          // Количество байт, выводимых в строку

void print_data(u_char *packet, int length);
void handler_packet(u_char *args, struct pcap_pkthdr *header, u_char *packet);

int main()
{
    pcap_t      *live;                  // Дескриптор pcap сессии
    char        emsg[PCAP_ERRBUF_SIZE]; // Описание ошибки

    // Инициализируем pcap сессию
    live = pcap_open_live(DEV_NAME, BUFSIZ, 0, 0, emsg);
    if (live == NULL){
        printf("ERROR: %s\n", emsg);
        exit(-1);
    }
    // Запускаем прослушивание
    if (pcap_loop(live, -1, (pcap_handler)handler_packet, NULL) < 0){
        pcap_close(live);
        printf("ERROR: pcap_close\n");
        exit(-1);
    }
    pcap_close(live);
    exit(0);
}

/*
 * Функция, вызываемая pcap_loop при получении пакета. Производит 
 * форматированный вывод его содержимого. Прототип обязательно такого вида.
 */ 
void handler_packet(u_char *args, struct pcap_pkthdr *info, u_char *packet)
{
    short   proto;          // Инкапсулированный протокол текущего заголовка
    u_char  *header;        // Указатель на текущий заголовок
    u_char  *header_prev;   // Указатель на предыдущий заголовок
    u_short chsum;          // Контрольная сумма

    // Выводим симолы для разделения вывода пакетов
    for (int i = 0; i< 93; i++)
        printf("=");
    printf("\n\n");

    // Поочередно разворачиваем пакет, смещаясь до следующего заголовка
    header = packet;
    proto = ethernet_print((struct hdr_ethernet *)header);
    header += ethernet_getsize((struct hdr_ethernet *)header);
    while(proto != 0){
        switch (proto){
            case TYPE_IP:
                proto = ip_print((struct hdr_ip *)header);
                header_prev = header;
                header += ip_getsize((struct hdr_ip *)header) * 4;
            break;
            case TYPE_TCP:
                proto = tcp_print((struct hdr_tcp *)header);
                chsum = tcp_checksum(header, header_prev, info->caplen - 
                                     (int)(header - packet));
                printf("calc_chsum: %#x\n", chsum);
                header += tcp_getsize((struct hdr_tcp *)header);
            break;
            default:
                proto = 0;
        }
    }

    // Выводим оставшиеся данные
    print_data(header, info->caplen - (int)(header - packet));
    printf("\n");
}

/*
 * Выводит содерщимое пакета в 2 солбика. Слева в hex, справа в ascii
 *
 * @param packet    Указатель на начало данных
 * @param length    Длина данных в байтах
 */
void print_data(u_char *packet, int length)
{
    int nbyte;                      // Номер байта для печати

    // Выводим построчно по LINE_LEN байт в каждой строке
    printf("DATA:\n");
    for (int line = 0; line < length; line += LINE_LEN){
        /*
         * Выводим в левой части в 16ом формате. Если пакет кончился, то
         * дописываем стрку пробелами
         */
        for (int i = 0; i < LINE_LEN; i++){
            nbyte = line + i;
            if (nbyte < length)
                printf("%.2x ", packet[nbyte]);
            else
                printf("%2s ", " ");
        }
        printf("\t");
        /*
         * Выводим в правой части пакет в ascii. Если символ непечатный, то
         * выводим точку, а если пакет кончился, то пробел
         */
        for(int i = 0; i < LINE_LEN; i++){
            nbyte = line + i;
            if (nbyte >= length)
                printf(" ");
            else if (packet[nbyte] > 31 && packet[nbyte] < 127)
                printf("%c", packet[nbyte]);
            else
                printf(".");
        }
        printf("\n");
    }
}