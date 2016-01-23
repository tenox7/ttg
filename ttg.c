/*___________________________________________
 |                                           |
 | Text Traffic Grapher -------- Version 1.2 |
 | Copyright (c) 2005-2008 by Antoni Sawicki |
 | Homepage --- http://www.tenox.tc/out/#ttg |
 | TTG is licensed under terms & cond of BSD |
 |___________________________________________|
 |__________________________________________/
 |
 | Compilation: cc ttg.c -o ttg -lnetsnmp 
 |
 | Net-SNMP may require: -lcrypto -lsocket -lnsl 
 | -liberty -lregex -lws2_32 (Win32) -lkstat (SunOS)
 |
 | For static snmplib build you may use:
 | ./configure --disable-agent --disable-privacy --without-openssl
 | --enable-internal-md5  --with-mibs=\"\" --disable-snmpv2c 
 | --with-out-mib-modules="snmpv3mibs,mibII/vacm_vars,agent_mibs,agentx,disman/event,disman/schedule"
 |
*/

#define VERSION "1.2"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define OID_ADM 7
#define OID_OPR 8
#define OID_IN 10
#define OID_OUT 16

uint32_t S_KB=1000;
uint32_t S_MB;
uint32_t S_GB;
char S_Unit[2];

uint32_t maxin=0, minin=-1, maxout=0, minout=-1;
uint64_t sumin=0, sumout=0;
unsigned int iterations=0, count=-1, interval=1;
struct snmp_session *ses;

uint32_t getcntr(int dir, oid inst);
int ifstatus(int type, oid inst);
int lsif(char *ifname);
int finish(void);
int perr(struct snmp_pdu *resp);
int kbprint(uint32_t var);
int thr(int ifno);
int usage(void);
int version(void);

int main(int argc, char **argv) {
	int c;
	struct snmp_session init_ses;

	opterr=0;
	while ((c=getopt(argc, argv, "vi:k:u:c:")) != -1)
		switch(c) {
			case 'v':
				version();
			case 'c':
				if(isdigit(optarg[0]))
					count=atoi(optarg);
				else
					usage();
				break;
			case 'i':
				if(isdigit(optarg[0]))
					interval=atoi(optarg);
				else
					usage();
				break;
			case 'k':
				if(isdigit(optarg[0]))
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
			"NET-SNMP version mismatch:\n"
			"Compiled with headers: %s\n"
			"Executed with library: %s\n",
			PACKAGE_VERSION, netsnmp_get_version());
		exit(1);
	}

	S_MB=S_KB*S_KB;
	S_GB=S_KB*S_KB*S_KB;

	SOCK_STARTUP;
	init_snmp("ttg");
	snmp_sess_init(&init_ses);
	init_ses.version=SNMP_VERSION_1;
	init_ses.peername=argv[optind];
	init_ses.community=(unsigned char*)argv[optind+1];
	init_ses.community_len=strlen((char *)argv[optind+1]);
	//snmp_enable_stderrlog(); 

	ses=snmp_open(&init_ses);
	if(!ses) {
		snmp_perror("error");
		exit(1);
	}

	if(strcasecmp(argv[optind+2], "list")==0) 
		lsif(NULL);
	else if(isdigit(argv[optind+2][0]))
		thr(atoi(argv[optind+2]));
	else
		thr(lsif(argv[optind+2]));

	snmp_close(ses);

	return 0;
}


int thr(int ifno) {
	uint32_t in=0, previn=0, out=0, prevout=0, ratein=0, rateout=0;
	time_t t;
	struct tm *ltime;

	signal(SIGINT, (void*)finish);

	while(1) {
		if(iterations>count)
			finish();

		previn=in;
		in=getcntr(OID_IN, ifno);
		if(in>previn)
			ratein=in-previn;
		else
			ratein=0;

		prevout=out;
		out=getcntr(OID_OUT, ifno);
		if(out>prevout)
			rateout=out-prevout;
		else
			rateout=0;

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
			putchar('\n');
		}

		iterations++;
#ifndef WIN32
		sleep(interval);
#else
		Sleep(interval*1000);
#endif
	}
	return 0;
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
						fprintf(stderr, "Found \"%s\" at index %lu\n", tmp, resp->variables->name[resp->variables->name_length-1]);
						return resp->variables->name[resp->variables->name_length-1];
					}
				}
				else {
					printf("%lu: \"%s\" [%s/%s]\n", 
						resp->variables->name[resp->variables->name_length-1], 
						tmp, 
						ifstat[ifstatus(OID_ADM, resp->variables->name[resp->variables->name_length-1])],
						ifstat[ifstatus(OID_OPR, resp->variables->name[resp->variables->name_length-1])]
					);
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
	if(resp) snmp_free_pdu(resp);
	return -1;
}

int finish(void) {
	printf( "\n---- ttg statistics ----\n"
		"                       in          out\n"
		"maximum throughput: ");
	kbprint(maxin/interval);
	putchar(' ');
	kbprint(maxout/interval);
	printf( "\n"
		"average throughput: ");
	kbprint((uint32_t)(sumin/(iterations-1)/interval));
	putchar(' ');
	kbprint((uint32_t)(sumout/(iterations-1)/interval));
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

int kbprint(uint32_t var) {
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

	return 0;
}

uint32_t getcntr(int dir, oid inst) {
	struct snmp_pdu *pdu, *resp;
	oid  tmp_oid[] = { 1,3,6,1,2,1,2,2,1,0,0 };
	int stat;
	uint32_t tmp;

	tmp_oid[9]=dir;
	tmp_oid[10]=inst;
	pdu=snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, tmp_oid, sizeof(tmp_oid)/sizeof(oid));
	stat=snmp_synch_response(ses, pdu, &resp);
	if (stat != STAT_SUCCESS || resp->errstat != SNMP_ERR_NOERROR) 
		perr(resp);

	if(resp->variables->type != ASN_COUNTER) {
		fprintf(stderr, "unsuported data type (only 32bit counter is supported)\n");
		snmp_close(ses);
		SOCK_CLEANUP;
		exit(1);
	}

	tmp=resp->variables->val.counter64->high;

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

        tmp=(int)resp->variables->val.integer[0];

        if(resp)
                snmp_free_pdu(resp);

        return tmp;
}


int usage(void) {
	fprintf(stderr, 
		"usage: ttg [-k 1000|1024] [-i interval] [-c count] [-u b|B|kb|kB|Mb|MB|Gb|GB]\n"
                "        <device> <community> <if_number|if_name>\n"
		"       ttg <device> <community> list\n"
		"       ttg -v\n"
	);
	exit(1);
}

int version(void) {
	fprintf(stdout, 
		"Text Traffic Grapher\n"
		"Copyright (c) 2005 - 2008 by Antoni Sawicki\n" 
		"Version %s [Build: %s, %s] [Generic]\n"
		"NET-SNMP Libraries=%s Headers=%s\n"
		"GCC Version %s\n"
		"Kilobyte equals %d bytes (default)\n"
		"Homepage: http://www.tenox.tc/out/#ttg\n"
		"Licensed under BSD\n" 
		"Credits:\n"
		"  Idea & Coding: Antoni Sawicki <tenox@tenox.tc>\n"
		"  Testing & Cisco expertise: Michal Krzysztofowicz <mike@mk.tc>\n",
		VERSION, __DATE__, __TIME__, netsnmp_get_version(), PACKAGE_VERSION, __VERSION__, (int)S_KB);
	exit(0);
}

int perr(struct snmp_pdu *resp) {
	if(resp) fprintf(stderr, "error: %s\n", snmp_errstring(resp->errstat));
	snmp_perror("error");
	snmp_close(ses);
	SOCK_CLEANUP;
	exit(1);
}
