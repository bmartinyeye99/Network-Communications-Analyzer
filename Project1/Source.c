#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>



typedef struct tftp {

    int SIP[4];
    int TIP[4];
    int SMAC[6];
    int DMAC[6];
    int id;
    int type;
    char msg[100];
    int dport;
    int sport;
} TFTP;

typedef struct icmp {

    int SIP[4];
    int DIP[4];
    int id;
    char icmp_messege[200];
    char msgid;
    int SMAC[6];
    int DMAC[6];
} ICMP;


typedef struct Arps {

    int SIP[4];
    int DIP[4];
    int id;
    int SMAC[6];
    int TMAC[6];
    int type;
    char in_comunication;
} ARP;


typedef struct Tcps {

    int sport;
    int dport;
    char complete;
    int SIP[4];
    int DIP[4];
    int id;
    int SMAC[6];
    int DMAC[6];
    char subprotocol[20];
    char has_subprot;
} TCP;


typedef struct tcp_comunication {
    int dport;
    int sport;
    int complete;
    int flag;
    int syn, ack, synack;
    int finack, rst;
    int open;
} OPEN_TCP;


void print_ip_mac_port(int sip[], int dip[], int smac[], int dmac[]) {
    printf("Source IP address : ");

    for (int s = 0; s < 4; s++) {
        printf("%d", sip[s]);
        if (s < 3)
            printf(".");
    }

    printf("\n");
    printf("Destination/Target IP address : ");
    for (int s = 0; s < 4; s++) {
        printf("%d", dip[s]);
        if (s < 3)
            printf(".");
    }
    printf("\n");
    printf("Source MAC address : ");
    for (int s = 0; s < 6; s++) {
        printf("%.2x", smac[s]);
        if (s < 5)
            printf(":");
    }

    printf("\n");
    printf("Destination/Target MAC address : ");
    for (int s = 0; s < 6; s++) {
        printf("%.2x", dmac[s]);
        if (s < 5)
            printf(":");
    }
    return;
}

//void print_packet(const u_char* packet) {
//
//}

int main()
{
    pcap_t* descr;
    char errbuf[1000];
    int arp_count = 0;
    ARP* arp_buff = malloc(100 * sizeof(*arp_buff));

    OPEN_TCP* comunication_buff = malloc(500 * sizeof(*comunication_buff));

    TCP* tcp_buff = malloc(2500 * sizeof(*tcp_buff));

    TFTP* tftp_buff = malloc(4000 * sizeof(*tftp_buff));

    ICMP* icmp_buff = malloc(2500 * sizeof(*icmp_buff));

    int number_of_tcp = 0;

    int number_of_udp = 0;
    int number_of_icmp = 0;
    int number_of_tftp = 0;
    int tftp_coms = 0;

    char duplicate = 0;

    char found_complet_TCP_com = 0;
    char found_not_complet_TCP_com = 0;
    char tcpsubprotocol_found = 0;

    int index_of_first_complete_TCP_com = -1;
   
    int index_of_first_open_TCP = -1;
    char opened_already;



    char file[] = "D:/MRc/FIIT/4.rocnik - 7.semester/PKS/vzorky_pcap_na_analyzu/";
    char subor[500];
    printf("Dajte subor, ktory chcete nacitat:\n");
    scanf("%s", &subor);
    strcat(subor, ".pcap");
    strcat(file, subor);

    descr = pcap_open_offline(file, errbuf);

    int packet_number = 0, sum2 = 0, tftp = 69, arpc = 0;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int tftpc[2];
    FILE* fp = fopen("results.txt", "w+");

    int uzly[5000][5] = { 0 }, uzol[4] = { 0 };


    int riad = 1, tcp = 0, kom = 0;
    int tftp_control;



    if (descr == NULL)
    {
        printf("pcap_file cannot be open\n");
        return 0;
    }

    FILE* protocols_file = fopen("protokoly.txt", "r");

    char icmpwarn_save[100] = { 0 };
    char icmpwarn[100] = { 0 };
    int icnum = 0;
    char EthType[100] = { 0 };
    int eth;


    while (pcap_next_ex(descr, &header, &packet) >= 0)      //pocitanie paketov
        sum2++;

    pcap_close(descr);
    descr = pcap_open_offline(file, errbuf);

    printf("Pocet paketov: %d\n\n", sum2);
    int number_of_open_TCP_comunications = 0;
    while (pcap_next_ex(descr, &header, &packet) >= 0) {
        int i;
        int tmp = 1;

        if (packet[12] == 8 && packet[13] == 0) {                 //ošetrím v IPv4 TCP protokoly, aby som uložil používané uzly
                                                                // keby som chcel filtrovat len TCP packety
            uzol[0] = packet[26];
            uzol[1] = packet[27];
            uzol[2] = packet[28];
            uzol[3] = packet[29];

            for (i = 0; i < riad; i++) {        //bez duplikátov ulozim adresy, ked nová adresa v 2 rozmernom poli sa už nachádza, tak
                tmp = 1;                        // zvyšujem jeho počet
                if (uzly[i][4] == 0) {          //ked pocet ip adresy v 2d poli je nule (este nebolo ulozene)
                    uzly[i][0] = uzol[0];
                    uzly[i][1] = uzol[1];
                    uzly[i][2] = uzol[2];
                    uzly[i][3] = uzol[3];
                    uzly[i][4]++;               //pocet danej IP adresy
                    riad++;
                    break;
                }
                else {
                    for (int j = 0; j < 4; j++) {       //kontrolujem vsetky 4 uzly ktore boli ulozene z hexa matice
                        if (uzly[i][j] != uzol[j]) {
                            tmp = 0;
                            break;
                        }
                    }
                    if (tmp == 1)           //Ked sa vsetky zhodli, tak zvysujem pocet
                    {
                        uzly[i][4]++;
                        break;
                    }
                }
            }

        }


        packet_number++;      //poradove cislo ramca


        printf("Ramec %d\n", packet_number);
        printf("Dlzka ramca poskytnuta pcap API - %d\n", header->len);

        if (header->len >= 60)
            printf("Dlzka rámca prenasaneho po mediu - %d\n", header->len + 4);
        else
            printf("Dlzka ramca prenasaneho po mediu - %d\n", 64);


        if (packet[12] * 256 + packet[13] > 0x5DC)  //1536
            printf("Ethernet II\n");
        else {
            if (packet[14] == 0xaa && packet[15] == 0xaa) { //43690
                printf("IEEE 802.3 LLC + SNAP\n");
                if (packet[22] == 0 && packet[23] == 0)
                    printf("STP\n");
                else if (packet[34] == 6)
                    printf("ZIP\n");
                else if (packet[32] == 81)
                    printf("DTP\n");
            }

            else if (packet[14] == 0xff && packet[15] == 0xff) { //65535
                printf("IEEE 802.3 RAW\n");
                printf("IPX\n");
            }

            else {
                printf("IEEE 802.3 LLC \n");
                if (packet[22] == 0 && packet[23] == 0)
                    printf("STP\n");
                else if (packet[34] == 6)
                    printf("ZIP\n");
                else if (packet[32] == 81)
                    printf("DTP\n");
            }
        }

        eth = icnum = 0;
        //rewind(protocols_file);


            //rewind(protocols_file);
        printf("Zdrojova MAC adresa: ");
        for (i = 6; i < 12; i++) {
            printf("%.2x", packet[i]);
            if (i < 11 && i >= 6)
                printf(":");
        }
        printf("\n");

        printf("Cieleova MAC adresa: ");
        for (i = 0; i < 6; i++) {
            printf("%.2x", packet[i]);
            if (i < 5)
                printf(":");
        }

        if (packet[12] * 256 + packet[13] == 1500) {        //IPV 4

            printf("\nIPv4\n");
            printf("Zdrojova IP adresa: ");
            for (i = 26; i < 30; i++) {
                printf("%d", packet[i]);

                if (i < 29)
                    printf(".");
            }

            printf("\n");
            printf("Cielova IP adresa: ");
            for (i = 30; i < 34; i++) {
                printf("%d", packet[i]);
                if (i < 33)
                    printf(".");
            }
        }
        else if (packet[12] * 256 + packet[13] == 34525) 
            printf("\nIPv6\n");

       
        
        
        else if (packet[12] == 8 && packet[13] == 6) {

            printf("\nARP\n");
            /*printf("Source IP adress: ");
            for (i = 28; i < 32; i++) {
                printf("%d", packet[i]);

                if (i < 31)
                    printf(".");
            }

            printf("\n");
            printf("Target IP adress: ");
            for (i = 38; i < 42; i++) {
                printf("%d", packet[i]);
                if (i < 41)
                    printf(".");
            }*/

            arp_buff[arp_count].type = packet[21];

            for (int i = 22; i < 28; i++)
                arp_buff[arp_count].SMAC[i - 22] = packet[i];

            for (int i = 28; i < 32; i++)
                arp_buff[arp_count].SIP[i - 28] = packet[i];

            for (int i = 32; i < 38; i++)
                arp_buff[arp_count].TMAC[i - 32] = packet[i];

            for (int i = 38; i < 42; i++)
                arp_buff[arp_count].DIP[i - 38] = packet[i];

            arp_buff[arp_count].id = packet_number;
            arp_buff[arp_count].in_comunication = 0;
            print_ip_mac_port(arp_buff[arp_count].SIP, arp_buff[arp_count].DIP, arp_buff[arp_count].SMAC, arp_buff[arp_count].TMAC);
            printf("IPV4\n");
            arp_count++;
            
        }
        

       

        if (packet[12] == 8 && packet[13] == 0) {       // IPV 4
            
            if (packet[23] == 1) {              //kontrola ICMP protokolu
                printf("\nICMP\n");

                while (strcmp(fgets(icmpwarn, 100, protocols_file), "ICMP\n") != 0)
                    continue;


                while (fscanf(protocols_file, "%d", &icnum) != EOF) {    //kontorla ICMP spravy
                    //if (icnum == packet[70] || icnum == packet[54] || icnum == packet[34] || icnum == packet[0]) {
                      if(icnum == packet[34]){

                        
                          icmp_buff[number_of_icmp].msgid = icnum;
                        
                          fscanf(protocols_file, "%s", icmpwarn);         // nacitam a vypisem ICMP spravu
                        
                          printf("%s", icmpwarn);
                        
                          strcpy(icmpwarn_save, icmpwarn);
                        
                          break;
                    }
                    fgets(icmpwarn, "%s", protocols_file);              // nacitam dalsi riadok zo suboru
                }

                icmp_buff[number_of_icmp].id = packet_number;



                for (i = 26; i < 30; i++)  
                    icmp_buff[number_of_icmp].SIP[i - 26] = packet[i];

                for (i = 30; i < 34; i++)
                    icmp_buff[number_of_icmp].DIP[i - 30] = packet[i];

                strcpy(icmp_buff[number_of_icmp].icmp_messege, icmpwarn_save);


                for (i = 6; i < 12; i++)
                    icmp_buff[number_of_icmp].SMAC[i - 6] = packet[i];

                for (i = 0; i < 6; i++)
                    icmp_buff[number_of_icmp].DMAC[i] = packet[i];
                printf("IPV4\n");
                number_of_icmp++;


                icnum = 0;
                rewind(protocols_file);
            }


            if (packet[23] == 17) {
                printf("\nUDP\n");
                tftp_control = 0;

                if (packet[37] == 69) {                             //keď je č. dest. portu 69 tak vieme, že to je TFTP
                    tftp_coms++;
                    printf("TFTP\n");
                    tftp_control = 1;                                        //označím s boolovskou premennou že som našiel TFTP
                    tftpc[0] = packet[34] * 256 + packet [35];                          //uložím source port do poľa
                }
                else if (packet[36] * 256 + packet[37] == tftpc[0] || packet[34] * 256 + packet[35] == tftpc[0]) {      //ak sa predošlí zdrojový port zhoduje s
                    printf("TFTP\n");                                                       //aktuálnym cielovym tak som našiel TFTP komunikaciu
                    tftp_control = 1;
                }
              
                
                if (tftp_control == 1) {

                    while (strcmp(fgets(icmpwarn, 50, protocols_file), "UDP\n") != 0) 
                        continue;
                    

                    while (fscanf(protocols_file, "%d", &icnum) != EOF) {

                        if (icnum == packet[42] * 256 + packet[43]) {

                            fgets(icmpwarn, 50, protocols_file);

                            strcpy(tftp_buff[number_of_tftp].msg, icmpwarn);

                            
                            tftp_buff[number_of_tftp].type = icnum;
                            
                            printf("%s", icmpwarn);
                            
                            break;
                        }

                        fgets(icmpwarn, 50, protocols_file);
                    }

                    tftp_buff[number_of_tftp].id = packet_number;

                    for (i = 26; i < 30; i++)
                        tftp_buff[number_of_tftp].SIP[i - 26] = packet[i];

                    for (i = 30; i < 34; i++)
                        tftp_buff[number_of_tftp].TIP[i - 30] = packet[i];

                    for (i = 6; i < 12; i++)
                        tftp_buff[number_of_tftp].SMAC[i - 6] = packet[i];

                    for (i = 0; i < 6; i++)
                        tftp_buff[number_of_tftp].DMAC[i] = packet[i];
                    printf("IPV4\n");

                    tftp_buff[number_of_tftp].dport = packet[36] * 256 + packet[37];
                    tftp_buff[number_of_tftp].sport = packet[34] * 256 + packet[35];

                    number_of_tftp++;
                }
                printf("Zdrojovy port: ");

                if (packet[34] > 0)
                    printf("%d\n", packet[34] * 256 + packet[35]);


                else printf("%d\n", packet[35]);

                printf("Cielovy port: ");

                if (packet[36] > 0)
                    printf("%d\n", packet[36] * 256 + packet[37]);

                else printf("%d\n", packet[37]);

                tftp_control = 0;
                icnum = 0;
                rewind(protocols_file);

            }

            // TCP PACKETS AND COMUNICATIONS --------------------------------------------------
            if (packet[23] == 6) {                  // ošetrenie TCP packetov
                icnum = 0;
                rewind(protocols_file);

                printf("\nTCP\n");
                opened_already = 0;
                duplicate = 0;
                tcpsubprotocol_found = 0;
                /*if ((packet[34] * 256 + packet[35]) == 21) {
                    printf("FTP CONTROL\n");
                    strcpy(tcp_buff[number_of_tcp].subprotocol, "FTP CONTROL");
                    tcpsubprotocol_found = 1;
                }
                else if ((packet[34] * 256 + packet[35]) == 20 || (packet[36] * 256 + packet[37]) == 20){
                    printf("FTP DATA\n");
                    strcpy(tcp_buff[number_of_tcp].subprotocol, "FTP DATA");
                    tcpsubprotocol_found = 1;
                }
                else if ((packet[34] * 256 + packet[35]) == 80 || (packet[36] * 256 + packet[37]) == 80) {
                    printf("HTTP\n");
                    strcpy(tcp_buff[number_of_tcp].subprotocol, "HTTP");
                    tcpsubprotocol_found = 1;
                }
                else if ((packet[34] * 256 + packet[35]) == 23 || (packet[36] * 256 + packet[37]) == 23) {
                    printf("TELNET\n");
                    strcpy(tcp_buff[number_of_tcp].subprotocol, "TELNET");
                    tcpsubprotocol_found = 1;
                }
                else if ((packet[34] * 256 + packet[35]) == 443 || (packet[36] * 256 + packet[37]) == 443) {
                    printf("HTTPS\n");
                    strcpy(tcp_buff[number_of_tcp].subprotocol, "HTTPS");
                    tcpsubprotocol_found = 1;
                }
                else if ((packet[34] * 256 + packet[35]) == 20 || (packet[36] * 256 + packet[37]) == 20) {
                    printf("SSH\n");
                    strcpy(tcp_buff[number_of_tcp].subprotocol, "SSH");
                    tcpsubprotocol_found = 1;
                }*/

                tcp_buff[number_of_tcp].id = packet_number;


                for (i = 26; i < 30; i++)
                    tcp_buff[number_of_tcp].SIP[i - 26] = packet[i];

                for (i = 30; i < 34; i++)
                    tcp_buff[number_of_tcp].DIP[i - 30] = packet[i];

                for (i = 6; i < 12; i++)
                    tcp_buff[number_of_tcp].SMAC[i - 6] = packet[i];

                for (i = 0; i < 6; i++)
                    tcp_buff[number_of_tcp].DMAC[i] = packet[i];

                tcp_buff[number_of_tcp].dport = packet[36] * 256 + packet[37];
                tcp_buff[number_of_tcp].sport = packet[34] * 256 + packet[35];

                printf("IPV4\n");

                printf("Zdrojovy port: %d\n", tcp_buff[number_of_tcp].sport);


                printf("Cielovy port: %d\n", tcp_buff[number_of_tcp].dport);

                while (strcmp(fgets(icmpwarn, 100, protocols_file), "TCP\n") != 0)
                    continue;

                while (fscanf(protocols_file, "%d", &icnum) != EOF) {                                  // najdem TCP podprotokol
                    
                    if (tcp_buff[number_of_tcp].dport == icnum || tcp_buff[number_of_tcp].sport == icnum) {
                    
                        tcp_buff[number_of_tcp].has_subprot = icnum;

                        fgets(icmpwarn,50,protocols_file);
                        strcpy(tcp_buff[number_of_tcp].subprotocol, icmpwarn);

                        printf("%s \n", tcp_buff[number_of_tcp].subprotocol);
                        
                        tcpsubprotocol_found = 1;
                        break;
                    }
                    fgets(icmpwarn, 50, protocols_file);
                }

                if (tcpsubprotocol_found == 0)
                    tcp_buff[number_of_tcp].has_subprot = 0;
                        
                        
                    for (int j = 0; j <= number_of_open_TCP_comunications; j++) {    
                        if ((comunication_buff[j].dport == tcp_buff[number_of_tcp].dport && comunication_buff[j].sport == tcp_buff[number_of_tcp].sport) ||
                            (comunication_buff[j].sport == tcp_buff[number_of_tcp].dport && comunication_buff[j].dport == tcp_buff[number_of_tcp].sport)){
                            tcpsubprotocol_found = 1;
                            if (comunication_buff[j].open == 0) {
                                duplicate = 1;

                                if (packet[47] == 2)
                                    comunication_buff[j].syn = 1;

                                else if (packet[47] == 18) {
                                    comunication_buff[j].synack = 1;
                                }

                                else if (packet[47] == 16) {
                                    comunication_buff[j].ack = 1;
                                }
                                if (comunication_buff[j].ack == 1 && comunication_buff[j].syn == 1 && comunication_buff[j].synack == 1) {
                                    comunication_buff[j].open = 1;

                                    if (index_of_first_open_TCP == -1)
                                        index_of_first_open_TCP = j;
                                }
              
                            }
              
                            else if (comunication_buff[j].open == 1) {
                                duplicate = 1;
                                if (comunication_buff[j].complete == 0) {
                                    if (packet[47] == 17) {
                                        comunication_buff[j].finack = 1;
                                        comunication_buff[j].complete = 1;

                                        found_complet_TCP_com = 1;
                                        if (index_of_first_complete_TCP_com == -1)
                                            index_of_first_complete_TCP_com = j;
                                    }
                                    else if (packet[47] == 4) {
                                        comunication_buff[j].rst = 1;
                                        comunication_buff[j].complete = 1;
                                        found_complet_TCP_com = j;
                                        if (index_of_first_complete_TCP_com == -1)
                                            index_of_first_complete_TCP_com = j;
                                    }
                                }
                            }
                                
                            duplicate = 1;
                            break;
                        }
                    }

                    // ulozim novu otvorenu komunikaciu
                    if (duplicate == 0) {  

                        comunication_buff[number_of_open_TCP_comunications].complete = 0;
                        comunication_buff[number_of_open_TCP_comunications].dport = tcp_buff[number_of_tcp].dport;
                        comunication_buff[number_of_open_TCP_comunications].sport = tcp_buff[number_of_tcp].sport;
                        comunication_buff[number_of_open_TCP_comunications].open = 0;

                            if (packet[47] == 2)
                                comunication_buff[number_of_open_TCP_comunications].syn = 1;
                            else if (packet[47] == 16)
                                comunication_buff[number_of_open_TCP_comunications].ack = 1;
                            else if (packet[47] == 18)
                                comunication_buff[number_of_open_TCP_comunications].synack = 1;  
                        number_of_open_TCP_comunications++;
                    }
                    tcpsubprotocol_found = 1;

                // -------------------------------------------------------------------------------------------------- 
                tcpsubprotocol_found = 0;
                opened_already = 0;
                duplicate = 0;
                rewind(protocols_file);
                number_of_tcp++;
            }

        }

        printf("\n");

        for (int j = 0; j < header->len; j++) {          //vypis hexa matrixu                                            
            if (j % 8 == 0)
                if (j % 16 == 0)
                    printf("\n");
                else
                    printf("  ");
            printf("%.2x ", packet[j]);
        }

        printf("\n\n-------------------------------------------------\n\n");
    }

    // ARP KOMUNIKACIE----------------------- ARP KOMUNIKACIE---------------
    pcap_close(descr);
    descr = pcap_open_offline(file, errbuf);


   
    // ARP KOMUNIKACIE----------------------- ARP KOMUNIKACIE---------------

    if (found_complet_TCP_com == 1) {
        printf("\n\n");
        printf("#### PRVA UZATVORENA TCP KOMUNIKACIA ####\n");
        printf("Destination port : %d\n", comunication_buff[index_of_first_complete_TCP_com].dport);
        printf("Source port : %d\n", comunication_buff[index_of_first_complete_TCP_com].sport);
    }


    //printf("\n### Pocet TCP komunikacii: %d ###\n\n", number_of_open_TCP_comunications);
    for (int j = 0; j < number_of_open_TCP_comunications; j++) {
        if (comunication_buff[j].complete == 0 && comunication_buff[j].open == 1) {
            printf("Prva otvorena TCP komunikacia: ");
            printf("Destination port : %d    Source port : %d\n", comunication_buff[j].dport, comunication_buff[j].sport);
            break;
        }
    }




    // ZISTENIE ADRESY NAJVIAC POSIELANYCH PAKETOV
    if (riad > 1) {
        printf("\nIP adresy prijimacich uzlov:\n\n");
        for (int j = 0; j < riad - 1; j++) {
            for (int k = 0; k < 4; k++) {
                printf("%d", uzly[j][k]);

                if (k < 3)
                    printf(".");
            }
            printf("\n");

            if (uzly[j][4] > tcp)
                tcp = uzly[j][4];
        }
    }
    else printf("Nenasli sa tcp uzly\n");

    if (tcp > 0) {
        printf("\n");
        printf("Adresa uzla s najvacsim poctom odosielanych paketov:\n");

        for (int i = 0; i < riad - 1; i++)
            if (uzly[i][4] == tcp)
                for (int k = 0; k < 4; k++) {
                    printf("%d", uzly[i][k]);

                    if (k < 3)
                        printf(".");
                }

        printf("   %d paketov\n", tcp);
    }
    printf("\nPocet paketov: %d\n\n", sum2);

    int choose;
    int print_controller;
    int tcps = 0;
    while (1) {
        tcps = 0;
        printf("\n ZADAJTE CISLO KORESPONDEJUCE K PROTOKOLU :\n ");
        printf("99 - TCP \n");
        printf("391 - HTTPS\n");
        printf("80 - HTTP\n");
        printf("23 - TELNET\n");
        printf("22 - SSH\n");
        printf("20 - FTP - DATA\n");
        printf("21 - FTP - RIADIACI\n");
        printf("############### ---------> -1 - EXIT\n");
        printf(" 1 - ICMP \n");
        printf(" 69 - TFTP \n");
        printf(" 86 - ARP \n");
        scanf("%d", &choose);
        if (choose == -1)
            break;
        else if (choose == 99 || choose == 391 || choose == 80 || choose == 23 || choose == 22 || choose == 20 || choose == 21) {
            for (int i = 0; i < number_of_tcp; i++) {

                 if (tcp_buff[i].has_subprot == choose || choose == 99) {
                     if (tcps > 20)
                         break;
                    printf("Frame number :  %d\n", tcp_buff[i].id);

                    printf("TCP\n");
                    print_ip_mac_port(tcp_buff[i].SIP, tcp_buff[i].DIP, tcp_buff[i].SMAC, tcp_buff[i].DMAC);

                    printf("\nDestination port : %d\nSource port : %d \n", tcp_buff[i].sport, tcp_buff[i].dport);
                    if (tcp_buff[i].has_subprot != 0)
                        printf("%d %s\n", tcp_buff[i].has_subprot, tcp_buff[i].subprotocol);
                    tcps++;

                    printf("\n---------------------------------------\n");
                }
                
            }

            if (number_of_tcp - 10 >= 0) {
                printf("\n***************** POSLEDNYCH 10 PAKETOV *********************\n \n");
                for (int i = number_of_tcp - 10; i < number_of_tcp; i++) {
                    if (tcp_buff[i].has_subprot == choose ||  choose == 99) {
                        printf("Frame number :  %d\n", tcp_buff[i].id);

                        printf("TCP\n");
                        print_ip_mac_port(tcp_buff[i].SIP, tcp_buff[i].DIP, tcp_buff[i].SMAC, tcp_buff[i].DMAC);

                        printf("\nDestination port : %d\nSource port : %d \n", tcp_buff[i].sport, tcp_buff[i].dport);
                        if (tcp_buff[i].has_subprot != 0)
                            printf("%d %s\n", tcp_buff[i].has_subprot, tcp_buff[i].subprotocol);

                        printf("\n---------------------------------------\n");
                    }
                }
            }


             if (found_complet_TCP_com == 1) {
                printf("\n\n");
                printf("#### PRVA UZATVORENA TCP KOMUNIKACIA ####\n");
                printf("Destination port : %d\n", comunication_buff[index_of_first_complete_TCP_com].dport);
                printf("Source port : %d\n", comunication_buff[index_of_first_complete_TCP_com].sport);
            }


            //printf("\n### Pocet TCP komunikacii: %d ###\n\n", number_of_open_TCP_comunications);
            for (int j = 0; j < number_of_open_TCP_comunications; j++) {
                if (comunication_buff[j].complete == 0 && comunication_buff[j].open == 1) {
                    printf("Prva otvorena TCP komunikacia: ");
                    printf("Destination port : %d    Source port : %d\n", comunication_buff[j].dport, comunication_buff[j].sport);
                    break;
                }
            }
        }

        else if ( choose == 1) {
                for (int i = 0; i < number_of_icmp; i++) {
                    if (i > 20)
                        break;
                        printf("Frame number :  %d\n", icmp_buff[i].id);

                        printf("ICMP\n");

                        print_ip_mac_port(icmp_buff[i].SIP, icmp_buff[i].DIP, icmp_buff[i].SMAC, icmp_buff[i].DMAC);

                        printf("\nICMP messege : %s\n", icmp_buff[i].icmp_messege);

                        printf("\n---------------------------------------\n");
                    }
                if (number_of_icmp - 10 >= 0) {
                    printf("\n\nPOSLEDNYCH 10 PAKETOV \n\n");
                    for (int i = number_of_icmp - 10; i < number_of_icmp; i++) {
                        if (i > 20)
                            break;
                        printf("Frame number :  %d\n", icmp_buff[i].id);

                        printf("ICMP\n");

                        print_ip_mac_port(icmp_buff[i].SIP, icmp_buff[i].DIP, icmp_buff[i].SMAC, icmp_buff[i].DMAC);

                        printf("\nICMP messege : %s\n", icmp_buff[i].icmp_messege);

                        printf("\n---------------------------------------\n");
                    }
            
                }
        }

        else if (choose == 69) {
                for (int i = 0; i < number_of_tftp; i++) {
                    if (i > 20)
                        break;
                    printf("Frame number :  %d\n", tftp_buff[i].id);

                    printf("UDP\nTFTP\n");

                    print_ip_mac_port(tftp_buff[i].SIP, tftp_buff[i].TIP, tftp_buff[i].SMAC, tftp_buff[i].DMAC);


                    printf("\nTFTP messege : %s\n", tftp_buff[i].msg);

                    printf("\n---------------------------------------\n");
                }
                if (number_of_tftp - 10 >= 0)
                    printf("\nPOSLEDNYCH 10 PAKETOV \n");
                for (int i = number_of_tftp - 10; i < number_of_tftp; i++) {
                    printf("Frame number :  %d\n", tftp_buff[i].id);

                    printf("UDP\nTFTP\n");

                    print_ip_mac_port(tftp_buff[i].SIP, tftp_buff[i].TIP, tftp_buff[i].SMAC, tftp_buff[i].DMAC);


                    printf("\nTFTP messege : %s\n", tftp_buff[i].msg);

                    printf("\n---------------------------------------\n");

                }

                int k = 1;
                printf("Pocet TFTP komunikacii : %d\n",tftp_coms);
                for (int i = 0; i < number_of_tftp; i++) {
                    if (tftp_buff[i].dport == 69 || tftp_buff[i].sport == 69) {
                        printf("Komunikacia cislo : %d\n", k++);
                        tftp_coms--;
                        printf("PORTY : %d      %d\n", tftp_buff[i + 1].dport, tftp_buff[i+1].sport);

                    }
                }
         }

        else if ( choose == 86) {

            for (int i = 0; i < arp_count; i++) {
                if (i > 20)
                    break;
                printf("Frame number :  %d\n", arp_buff[i].id);
                printf("ARP\n");
                print_ip_mac_port(arp_buff[i].SIP, arp_buff[i].DIP, arp_buff[i].SMAC, arp_buff[i].TMAC);
                printf("\n---------------------------------------\n");
            }

            if (arp_count - 10 >= 0) {
                printf("\n\nPOSLEDNYCH 10 PAKETOV \n\n");
                for (int i = arp_count - 10; i < arp_count; i++) {
                    printf("Frame number :  %d\n", arp_buff[i].id);

                    printf("ARP\n");

                    print_ip_mac_port(arp_buff[i].SIP, arp_buff[i].DIP, arp_buff[i].SMAC, arp_buff[i].TMAC);

                    printf("\n---------------------------------------\n");

                }
            }


            printf("### ARP KOMUNIKACIE ### \n\n");
            if (arp_count == 0)
                printf("Subor neobsahuje ARP pakety");
            else {
                char reply_print_control = 1;
                int arp_communications = 1;

                for (int j = 0; j < arp_count; j++) {
                    if (arp_buff[j].type == 2) {


                        printf("\n");
                        printf("\n");
                        reply_print_control = 1;

                        for (int k = 0; k < arp_count; k++) {

                            if (arp_buff[k].type == 1 && memcmp(arp_buff[k].DIP, arp_buff[j].SIP, sizeof(arp_buff[k].DIP)) == 0 && 
                                memcmp(arp_buff[k].SMAC, arp_buff[j].TMAC, sizeof(arp_buff[k].SMAC)) == 0) {

                                if (reply_print_control == 1) {

                                    printf("\n\n ### ARP KOMUNIKACIA C. %d ###\n", arp_communications);
                                    printf("Cislo packetu: %d \n", arp_buff[j].id);
                                    printf("ARP type : %d (reply) \n", arp_buff[j].type);
                                    print_ip_mac_port(arp_buff[j].SIP, arp_buff[j].DIP, arp_buff[j].SMAC, arp_buff[j].TMAC);


                                    reply_print_control = 0;
                                    arp_communications++;
                                    arp_buff[j].in_comunication = 1;
                                }

                                printf("\n\n");
                                arp_buff[k].in_comunication = 1;
                                printf("Cislo packetu: %d \n", arp_buff[k].id);
                                printf("ARP type : %d (request)\n", arp_buff[k].type);

                                print_ip_mac_port(arp_buff[k].SIP, arp_buff[k].DIP, arp_buff[k].SMAC, arp_buff[k].TMAC);

                                printf("\n");
                                printf("\n");

                            }
                        }
                    }
                }
                printf("\n### ARP REQUESTY BEZ REPLY ALEBO REQUESTY BEZ REPLY ### \n");
                if (arp_count == 0)
                    printf("Subor neobsahuje ARP komunikacie bez repl");
                int alone_arp = 0;
                for (int k = 0; k < arp_count; k++) {
                    if (arp_buff[k].in_comunication == 0) {
                        alone_arp++;
                        printf("\nCislo packetu: %d \n", arp_buff[k].id);
                        printf("ARP type : %d (request)\n", arp_buff[k].type);
                        print_ip_mac_port(arp_buff[k].SIP, arp_buff[k].DIP, arp_buff[k].SMAC, arp_buff[k].TMAC);

                        printf("\n ---------------------------------\n");
                    }
                }
                printf("POCET ARP PAKETOV BEZ REPLY ALEBO REQUEST : %d \n", alone_arp);
                printf("\n\n###################################################\n\n");
            }
        }


        
     }
    return 0;
}
