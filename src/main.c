#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <pcap.h>

#define DEV_NAME    "enp3s0"    // Имя прослушиваемого интерфейса
#define LINE_LEN    30          // Количество байт, выводимых в строку

void sniffer_packet(u_char *args, struct pcap_pkthdr *header, u_char *packet);

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
    if (pcap_loop(live, -1, (pcap_handler)sniffer_packet, NULL) < 0){
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
void sniffer_packet(u_char *args, struct pcap_pkthdr *header, u_char *packet)
{
    int nbyte;                      // Номер байта для печати
    int length = header->caplen;    // Длина пакета

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
    printf("\n");
}
