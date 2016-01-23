/*___________________________________________
 |                                           |
 | SNMP Text Traffic Grapher --- Version 2.0 |
 | Copyright (c) 2005-2009 by Antoni Sawicki |
 | Homepage ---- http://www.tenox.tc/out#ttg |
 | TTG is licensed under terms & cond of BSD |
 |___________________________________________|
 |__________________________________________/
 |
 | Compilation (Unix): cc ttg.c -o ttg -lnetsnmp 
 |
 | Net-SNMP may also require: -lcrypto -lsocket -lnsl 
 |  -liberty -lregex -lws2_32 (Win32) -lkstat (SunOS)
 |
 | For a minimal static snmplib build you may use:
 | ./configure --disable-agent --disable-privacy --without-openssl 
 | --enable-internal-md5 --with-mibs=\"\"
 |
*/

#define VERSION "2.0"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#ifndef UINT32_MAX
#define UINT32_MAX        4294967295U
#endif
#ifndef UINT64_MAX
#define UINT64_MAX        18446744073709551615ULL
#endif

#define OID_ADM 7
#define OID_OPR 8
#define OID_IN 10
#define OID_OUT 16
#define OID_XIN 6
#define OID_XOUT 10


uint64_t S_KB=1000;
uint64_t S_MB;
uint64_t S_GB;
char S_Unit[2];

uint64_t maxin=0, minin=-1, maxout=0, minout=-1;
uint64_t sumin=0, sumout=0;
unsigned int iterations=0, count=-1, interval=1, extended=0, debug=0;
struct snmp_session *ses;

uint64_t getcntr(int dir, oid inst);
int ifstatus(int type, oid inst);
int lsif(char *ifname);
void thr(int ifno);
void kbprint(uint64_t var);
void finish(void);
void perr(struct snmp_pdu *resp);
void usage(void);
void version(void);
void prifalias(oid inst);

int main(int argc, char **argv) {
    int c;
    struct snmp_session init_ses;
    char finame[1024];

    opterr=0;
    while ((c=getopt(argc, argv, "xdvi:k:u:c:")) != -1)
        switch(c) {
            case 'v':
                version();
            case 'x':
                extended=1;
                break;
            case 'd':
                debug=1;
                break;
            case 'c':
                if(isdigit((int)optarg[0]))
                    count=atoi(optarg);
                else
                    usage();
                break;
            case 'i':
                if(isdigit((int)optarg[0]))
                    interval=atoi(optarg);
                else
                    usage();
                break;
            case 'k':
                if(isdigit((int)optarg[0]))
                    S_KB=atoi(optarg);
                else
                    usage();
                break;
            case 'u':
                if(strlen(optarg)==2) {
                    S_Unit[0]=optarg[0];
                    S_Unit[1]=optarg[1];
                }
                else if(strlen(optarg)==1) {
                    S_Unit[0]='n';
                    S_Unit[1]=optarg[0];
                }
                else
                    usage();
                break;
            case '?':
            default:
                usage();
        }

    if(S_KB != 1024 && S_KB !=1000) 
        usage();

    if(interval<1) 
        usage();

    if(count<1)
        usage();

    if((argc-optind)!=3)
        usage();

    if(strcmp(netsnmp_get_version(), PACKAGE_VERSION)!=0) {
        fprintf(stderr,
            "ERROR: Net-SNMP version mismatch!\n"
            "Compiled with headers: %s\n"
            "Executed with library: %s\n",
            PACKAGE_VERSION, netsnmp_get_version());
        exit(1);
    }

    if(UINT32_MAX == UINT64_MAX) {
        fprintf(stderr, "ERROR: UINT32_MAX == UINT64_MAX\n");
        exit(1);
    }

    S_MB=S_KB*S_KB;
    S_GB=S_KB*S_KB*S_KB;

    SOCK_STARTUP;
    init_snmp("ttg");
    snmp_sess_init(&init_ses);
    if(extended)
        init_ses.version=SNMP_VERSION_2c;
    else
        init_ses.version=SNMP_VERSION_1;
    init_ses.peername=argv[optind];
    init_ses.community=(unsigned char*)argv[optind+1];
    init_ses.community_len=strlen((char *)argv[optind+1]);
    snmp_enable_stderrlog(); 

    ses=snmp_open(&init_ses);
    if(!ses) {
        snmp_perror("error");
        exit(1);
    }

    if(strcasecmp(argv[optind+2], "list")==0 || strcasecmp(argv[optind+2], "ls")==0) 
        lsif(NULL);
    else if(isdigit((int)argv[optind+2][0]))
        thr(atoi(argv[optind+2]));
    else if(strlen(argv[optind+2])>=2) {
        if(argv[optind+2][0]=='s' && argv[optind+2][1]=='e') 
            snprintf(finame, sizeof(finame), "Serial%s", argv[optind+2]+2);
        else if(argv[optind+2][0]=='e' && argv[optind+2][1]=='t') 
            snprintf(finame, sizeof(finame), "Ethernet%s", argv[optind+2]+2);
        else if(argv[optind+2][0]=='f' && argv[optind+2][1]=='a') 
            snprintf(finame, sizeof(finame), "FastEthernet%s", argv[optind+2]+2);
        else if(argv[optind+2][0]=='g' && argv[optind+2][1]=='i') 
            snprintf(finame, sizeof(finame), "GigabitEthernet%s", argv[optind+2]+2);
        else if(argv[optind+2][0]=='p' && argv[optind+2][1]=='i') 
            snprintf(finame, sizeof(finame), "PIX Firewall 'inside' interface");
        else if(argv[optind+2][0]=='p' && argv[optind+2][1]=='o') 
            snprintf(finame, sizeof(finame), "PIX Firewall 'outside' interface");
        else if(argv[optind+2][0]=='a' && argv[optind+2][1]=='i') 
            snprintf(finame, sizeof(finame), "Adaptive Security Appliance 'inside' interface");
        else if(argv[optind+2][0]=='a' && argv[optind+2][1]=='o') 
            snprintf(finame, sizeof(finame), "Adaptive Security Appliance 'outside' interface");
        else if(argv[optind+2][0]=='v' && argv[optind+2][1]=='l') 
            snprintf(finame, sizeof(finame), "Vlan%s", argv[optind+2]+2);
        else if(argv[optind+2][0]=='p' && argv[optind+2][1]=='c') 
            snprintf(finame, sizeof(finame), "Port-channel%s", argv[optind+2]+2);
        else if(argv[optind+2][0]=='t' && argv[optind+2][1]=='u') 
            snprintf(finame, sizeof(finame), "Tunnel%s", argv[optind+2]+2);
        else
            thr(lsif(argv[optind+2]));

        thr(lsif(finame));
    }
    else
        usage();

    snmp_close(ses);
    SOCK_CLEANUP;

    return 0;
}


void thr(int ifno) {
    uint64_t in=0, previn=0, out=0, prevout=0, ratein=0, rateout=0;
    time_t t;
    struct tm *ltime;

    signal(SIGINT, (void*)finish);

    while(1) {
        if(iterations>count)
            finish();

        previn=in;
        prevout=out;

        if(extended) {
            in=getcntr(OID_XIN, ifno);
            out=getcntr(OID_XOUT, ifno);
			ratein=(uint64_t)(UINT64_MAX+1-previn+in);
			rateout=(uint64_t)(UINT64_MAX+1-prevout+out);
        }
        else {
            in=getcntr(OID_IN, ifno);
            out=getcntr(OID_OUT, ifno);
			ratein=(uint32_t)(UINT32_MAX+1-previn+in);
			rateout=(uint32_t)(UINT32_MAX+1-prevout+out);
        }

        if(iterations) {
            sumin+=ratein;
            sumout+=rateout;
            if(ratein>maxin) maxin=ratein;
            if(ratein<minin) minin=ratein;
            if(rateout>maxout) maxout=rateout;
            if(rateout<minout) minout=rateout;

            time(&t);
            ltime=localtime(&t);

            printf("[%02d:%02d:%02d] current throughput: in ", ltime->tm_hour, ltime->tm_min, ltime->tm_sec);
            kbprint(ratein/interval);
            printf("  out ");
            kbprint(rateout/interval);
            if (debug) printf("  [RIN: %llu ROUT: %llu] ", in, out);
            putchar('\n');
        }

        iterations++;
#ifndef WIN32
        sleep(interval);
#else
        Sleep(interval*1000);
#endif
    }
}

uint64_t getcntr(int dir, oid inst) {
    struct snmp_pdu *pdu, *resp;
    oid iftable_oid[]  = { 1,3,6,1,2,1,2,2,1,0,0 };    // dir=9 ; inst=10
    oid ifxtable_oid[] = { 1,3,6,1,2,1,31,1,1,1,0,0 }; // dir=10; inst=11
    int stat;
    uint64_t tmp;

    pdu=snmp_pdu_create(SNMP_MSG_GET);
    if(extended) {
        ifxtable_oid[10]=dir;
        ifxtable_oid[11]=inst;
        snmp_add_null_var(pdu, ifxtable_oid, sizeof(ifxtable_oid)/sizeof(oid));
    } else {
        iftable_oid[9]=dir;
        iftable_oid[10]=inst;
        snmp_add_null_var(pdu, iftable_oid, sizeof(iftable_oid)/sizeof(oid));
    }
    
    stat=snmp_synch_response(ses, pdu, &resp);
    if (stat != STAT_SUCCESS || resp->errstat != SNMP_ERR_NOERROR) 
        perr(resp);

    if(extended) {
        if(resp->variables->type != ASN_COUNTER64) {
            fprintf(stderr, "\nunsuported data type (only 64bit counter is supported in extended mode)\n");
            snmp_close(ses);
            SOCK_CLEANUP;
            exit(1);
        }
    } else {
        if(resp->variables->type != ASN_COUNTER) {
            fprintf(stderr, "\nunsuported data type (only 32bit counter is supported in normal mode)\n");
            snmp_close(ses);
            SOCK_CLEANUP;
            exit(1);
        }
    }       

    tmp=resp->variables->val.counter64->high;

    if(extended) {
        tmp<<=32;
        tmp+=resp->variables->val.counter64->low;
    }

    if(resp)
        snmp_free_pdu(resp);

    return tmp;
}

int ifstatus(int type, oid inst) {
    struct snmp_pdu *pdu, *resp;
    oid tmp_oid[] = { 1,3,6,1,2,1,2,2,1,0,0 };
    int stat, tmp;

    tmp_oid[9]=type;
    tmp_oid[10]=inst;
    pdu=snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, tmp_oid, sizeof(tmp_oid)/sizeof(oid));
    stat=snmp_synch_response(ses, pdu, &resp);

    if (stat != STAT_SUCCESS || resp->errstat != SNMP_ERR_NOERROR) 
        perr(resp);

    if((int)resp->variables->val.integer[0] > 2)
        tmp=0;
    else
        tmp=(int)resp->variables->val.integer[0];

    if(resp)
            snmp_free_pdu(resp);

    return tmp;
}

void prifalias(oid inst) {
    struct snmp_pdu *pdu, *resp;
    oid tmp_oid[] = { 1,3,6,1,2,1,31,1,1,1,18,0 };
    int stat;
    char *tmp;

    if(!extended) {
        fprintf(stderr, "prifalias is only available in eXtended mode\n");
        snmp_close(ses);
        SOCK_CLEANUP;
        exit(1);
    }
    
    tmp_oid[11]=inst;
    pdu=snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, tmp_oid, sizeof(tmp_oid)/sizeof(oid));
    stat=snmp_synch_response(ses, pdu, &resp);

    if (stat != STAT_SUCCESS || resp->errstat != SNMP_ERR_NOERROR) 
        perr(resp);

    if(resp->variables->val_len && strlen((char *)resp->variables->val.string)) {
        tmp=malloc((resp->variables->val_len+1) * sizeof(char));
        memcpy(tmp, resp->variables->val.string, resp->variables->val_len);
        tmp[resp->variables->val_len]=0;
        printf("  \"%s\"", tmp);
        free(tmp);
    }
    
    if(resp)
            snmp_free_pdu(resp);

}

int lsif(char *ifname) {
    struct snmp_pdu *pdu, *resp;
    oid tmp_oid[MAX_OID_LEN];
    size_t tmp_oid_len;
    oid ifname_oid[] = { 1,3,6,1,2,1,2,2,1,2 };
    int stat, next;
    char *tmp;
    char *ifstat[3] = { "unkn", "up", "down" };

    memmove(tmp_oid, ifname_oid, sizeof(ifname_oid));
    tmp_oid_len=sizeof(ifname_oid);
    next=1;
    while(next) {
        pdu=snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, tmp_oid, tmp_oid_len/sizeof(oid)); 
        stat=snmp_synch_response(ses, pdu, &resp);
        if(stat == STAT_SUCCESS && resp->errstat == SNMP_ERR_NOERROR) {
            if(memcmp(ifname_oid, resp->variables->name, sizeof(ifname_oid)) == 0) {
                tmp=malloc((resp->variables->val_len+1) * sizeof(char));
                memcpy(tmp, resp->variables->val.string, resp->variables->val_len);
                tmp[resp->variables->val_len]=0;
                if(ifname) {
                    if(strcasecmp(ifname, tmp)==0) {
                        printf("Found \"%s\" at index %lu:\n", tmp, resp->variables->name[resp->variables->name_length-1]);
                        return resp->variables->name[resp->variables->name_length-1];
                    }
                }
                else {
                    printf("%lu : \"%s\" [%s/%s]", 
                        resp->variables->name[resp->variables->name_length-1], 
                        tmp, 
                        ifstat[ifstatus(OID_ADM, resp->variables->name[resp->variables->name_length-1])],
                        ifstat[ifstatus(OID_OPR, resp->variables->name[resp->variables->name_length-1])]
                    );
                    if(extended)
                        prifalias(resp->variables->name[resp->variables->name_length-1]);
                    putchar('\n');
                }
                memmove((char *)tmp_oid, (char *)resp->variables->name, resp->variables->name_length * sizeof(oid));
                tmp_oid_len=resp->variables->name_length * sizeof(oid);
                free(tmp);
                if(resp) snmp_free_pdu(resp);
            }
            else 
                next=0;
        }
        else
            perr(resp);
    }
    if(resp) 
        snmp_free_pdu(resp);
    if(ifname) {
        fprintf(stderr, "Unable to find \"%s\". Use 'list' to display all interfaces.\n", ifname);
        snmp_close(ses);
        SOCK_CLEANUP;
        exit(1);
    }
    return 0;
}

void finish(void) {
    printf( "\n---- ttg statistics ----\n"
        "                       in          out\n"
        "maximum throughput: ");
    kbprint(maxin/interval);
    putchar(' ');
    kbprint(maxout/interval);
    printf( "\n"
        "average throughput: ");
    kbprint((uint64_t)(sumin/(iterations-1)/interval));
    putchar(' ');
    kbprint((uint64_t)(sumout/(iterations-1)/interval));
    printf( "\n"
        "minimum throughput: ");
    kbprint(minin/interval);
    putchar(' ');
    kbprint(minout/interval);
    putchar('\n');
    snmp_close(ses);
    SOCK_CLEANUP;
    exit(0);
}

void kbprint(uint64_t var) {
    float out;
    char unit[2];

    if(     S_Unit[0]=='n' && S_Unit[1]=='B') { out=(float)var;        unit[0]=' '; unit[1]='B'; } /* bytes */
    else if(S_Unit[0]=='n' && S_Unit[1]=='b') { out=(float)var*8;      unit[0]=' '; unit[1]='b'; } /* bits */
    else if(S_Unit[0]=='k' && S_Unit[1]=='B') { out=(float)var/S_KB;   unit[0]='k'; unit[1]='B'; } /* kilobytes */
    else if(S_Unit[0]=='k' && S_Unit[1]=='b') { out=(float)var*8/S_KB; unit[0]='k'; unit[1]='b'; } /* kilobits */
    else if(S_Unit[0]=='M' && S_Unit[1]=='B') { out=(float)var/S_MB;   unit[0]='M'; unit[1]='B'; } /* megabytes */
    else if(S_Unit[0]=='M' && S_Unit[1]=='b') { out=(float)var*8/S_MB; unit[0]='M'; unit[1]='b'; } /* megabits */
    else if(S_Unit[0]=='G' && S_Unit[1]=='B') { out=(float)var/S_GB;   unit[0]='G'; unit[1]='B'; } /* gigabytes */
    else if(S_Unit[0]=='G' && S_Unit[1]=='b') { out=(float)var*8/S_GB; unit[0]='G'; unit[1]='b'; } /* gigabits */
    else if(var >= S_KB && var < S_MB)        { out=(float)var/S_KB;   unit[0]='k'; unit[1]='B'; } /* kilobytes */
    else if(var >= S_MB && var < S_GB)        { out=(float)var/S_MB;   unit[0]='M'; unit[1]='B'; } /* megabytes */
    else if(var >= S_GB              )        { out=(float)var/S_GB;   unit[0]='G'; unit[1]='B'; } /* gigabytes */
    else                                      { out=(float)var;        unit[0]=' '; unit[1]='B'; } /* bytes */

    printf("%6.1f %c%c/s", out, unit[0], unit[1]);
}


void usage(void) {
    fprintf(stderr, 
        "usage:\n"
        "     ttg [-x] [-k 1000|1024] [-i interval] [-c count] [-u b|B|kb|kB|Mb|MB|Gb|GB]\n"
        "         <device> <community> <if_index|if_name|if_abbr>\n"
        "     ttg [-x] <device> <community> list\n"
        "     ttg -v\n\n"
        
        "flags:\n"
        "     -x: extended mode, use SNMPv2c, ifXTable and 64bit counters\n"
        "         for 'list' command also includes interface descriptions\n"
        "     -k: size of kilo, either 1000 or 1024, default %d\n"
        "     -i: interval in seconds; note some agents (eg. Cisco ASA) may require\n"
        "         long, even 10 second interval to return correct values, default 1\n"
        "     -c: maximum iterations, default unlimited\n"
        "     -u: units, b:bits B:bytes kb:kilobits kB:kilobytes etc., default auto\n\n"

        "examples:\n"
        "     ttg router1 public list\n"
        "     ttg -x router1 public ls\n"
        "     ttg router1 public et2\n"
        "     ttg -x router1 public gi3/45\n"
        "     ttg -x -i 10 asafw1 public ao\n"
        "     ttg router1 public \"full interface name from the 'list' command\"\n"
        "     ttg -u MB router1 public 147\n\n"

        "possible abbreviations:\n"
        "     et=ethernet fa=fastethernet gi=gigabitethernet se=serial\n"
        "     pi=pix-inside po=pix-outside ai=asa-inside ao=asa-outside\n"
        "     vl=vlan pc=port-channel tu=tunnel ls=list\n\n", (int)S_KB);
    exit(1);
}

void version(void) {
    fprintf(stdout, 
        "SNMP Text Traffic Grapher\n"
        "Copyright (c) 2005 - 2009 by Antoni Sawicki\n" 
        "Version %s [Build: %s, %s]\n"
        "NET-SNMP Libraries=%s Headers=%s\n"
        "GCC Version %s\n"
        "Kilo=%d (default)\n"
        "Max uint32=%u uint64=%llu\n"
        "Homepage: http://www.tenox.tc/out#ttg\n"
        "Licensed under BSD\n" 
        "Credits:\n"
        "  tenox@tenox.tc\n"
        "  mike@mk.tc\n"
        "  tommy@ntinternals.net\n"
        "  piston@otel.net\n",
        VERSION, __DATE__, __TIME__, netsnmp_get_version(), PACKAGE_VERSION, __VERSION__, 
        (int)S_KB, UINT32_MAX, UINT64_MAX);
    exit(0);
}

void perr(struct snmp_pdu *resp) {
    if(resp) fprintf(stderr, "error: %s\n", snmp_errstring(resp->errstat));
    snmp_perror("error");
    snmp_close(ses);
    SOCK_CLEANUP;
    exit(1);
}
