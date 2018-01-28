#include "protocolswitch.hpp"

string protIdtoName(int id)
{
	/*protoent * tmp;
	 protoent * cpy;
	 tmp = getprotobynumber(id);
	 string prot = string("");

	 if (tmp == NULL)
	 prot = prot.assign("Unknown");
	 else
	 {
	 memcpy(&cpy, &tmp, sizeof(tmp));
	 //protoent * cpy = new protoent(*tmp);
	 prot = prot.assign(cpy->p_name);
	 }
	 tmp = NULL;

	 string p = boost::lexical_cast<string>(id);
	 prot = prot.append(" (");
	 prot = prot.append(p);
	 prot = prot.append(")");
	 string * a = new string(prot);
	 return *a;*/

	string protocollo;
	switch (id)
	{
	case 1:
		protocollo = "ICMP (1)";
		break;

	case 3:
		protocollo = "Gateway-to-Gateway (3)";
		break;

	case 4:
		protocollo = "CMCC Gateway Monitoring Message (4)";
		break;

	case 5:
		protocollo = "ST (5)";
		break;

	case 6:
		protocollo = "TCP (6)";
		break;

	case 7:
		protocollo = "UCL (7)";
		break;

	case 9:
		protocollo = "Secure (9)";
		break;

	case 10:
		protocollo = "BBN RCC Monitoring (10)";
		break;

	case 11:
		protocollo = "NVP (11)";
		break;

	case 12:
		protocollo = "PUP (12)";
		break;

	case 13:
		protocollo = "Pluribus (13)";
		break;

	case 14:
		protocollo = "Telenet (14)";
		break;

	case 15:
		protocollo = "XNET (15)";
		break;

	case 16:
		protocollo = "Chaos (16)";
		break;

	case 17:
		protocollo = "UDP (17)";
		break;

	case 18:
		protocollo = "Multiplexing (18)";
		break;

	case 19:
		protocollo = "DCN (19)";
		break;

	case 20:
		protocollo = "TAC Monitoring (20)";
		break;

	case 64:
		protocollo = "SATNET and Backroom EXPAK (64)";
		break;

	case 65:
		protocollo = "MIT Subnet Support (65)";
		break;

	case 69:
		protocollo = "SATNET Monitoring (69)";
		break;

	case 71:
		protocollo = "Internet Packet Core Utility (71)";
		break;

	case 76:
		protocollo = "SATNET and Backroom EXPAK (76)";
		break;

	case 78:
		protocollo = "SWIDEBAND Monitoring (78)";
		break;

	case 79:
		protocollo = "WIDEBAND EXPAK (79)";
		break;

	case 106:
		protocollo = "QNX (106)";
		break;

	default:
		protocollo = "Unknown";
		break;
	}
	string * a = new string();
	*a = protocollo;
	return *a;
	//ampliare con: http://support.microsoft.com/kb/289892
}

/*
 * Creato con:
 * awk 'BEGIN { FS= " " } ($1!="#") { print $1 " " $2 }' /etc/services | cut -d "/" -f1 | awk '{ print $2 " " $1 } ' |sort -u | sort -n | awk '{ printf "\ncase %s:\nprot = #%s#;\nbreak;\n",$1,$2}' >> portToProtocoll.txt
 */
//TODO per ottimizzare sostituire con array bidimensionale con indice = porta char = nome protocollo (?)
//TODO ampliare con http://it.wikipedia.org/wiki/Lista_di_porte_standard#da_49152_a_65535
//TODO è sbagliato, fare 2 metodi uno per udp e uno per tcp, qui sono tutti mischiati
string portToProtocoll(unsigned int porta)
{
	string prot;
	switch (porta)
	{
	case 1:
		prot = "rtmp Or tcpmux";
		break;

	case 2:
		prot = "compressnet Or nbp";
		break;

	case 3:
		prot = "compressnet";
		break;

	case 4:
		prot = "echo";
		break;

	case 5:
		prot = "rje";
		break;

	case 6:
		prot = "zip";
		break;

	case 7:
		prot = "echo";
		break;

	case 9:
		prot = "discard";
		break;

	case 11:
		prot = "systat";
		break;

	case 13:
		prot = "daytime";
		break;

	case 17:
		prot = "qotd";
		break;

	case 18:
		prot = "msp";
		break;

	case 19:
		prot = "chargen";
		break;

	case 20:
		prot = "ftp-data";
		break;

	case 21:
		prot = "ftp";
		break;

	case 22:
		prot = "ssh";
		break;

	case 23:
		prot = "telnet";
		break;

	case 25:
		prot = "smtp";
		break;

	case 27:
		prot = "nsw-fe";
		break;

	case 29:
		prot = "msg-icp";
		break;

	case 31:
		prot = "msg-auth";
		break;

	case 33:
		prot = "dsp";
		break;

	case 37:
		prot = "time";
		break;

	case 38:
		prot = "rap";
		break;

	case 39:
		prot = "rlp";
		break;

	case 41:
		prot = "graphics";
		break;

	case 42:
		prot = "name";
		break;

	case 43:
		prot = "nicname";
		break;

	case 44:
		prot = "mpm-flags";
		break;

	case 45:
		prot = "mpm";
		break;

	case 46:
		prot = "mpm-snd";
		break;

	case 47:
		prot = "ni-ftp";
		break;

	case 48:
		prot = "auditd";
		break;

	case 49:
		prot = "tacacs";
		break;

	case 50:
		prot = "re-mail-ck";
		break;

	case 51:
		prot = "la-maint";
		break;

	case 52:
		prot = "xns-time";
		break;

	case 53:
		prot = "domain";
		break;

	case 54:
		prot = "xns-ch";
		break;

	case 55:
		prot = "isi-gl";
		break;

	case 56:
		prot = "xns-auth";
		break;

	case 58:
		prot = "xns-mail";
		break;

	case 61:
		prot = "ni-mail";
		break;

	case 62:
		prot = "acas";
		break;

	case 63:
		prot = "whois++";
		break;

	case 64:
		prot = "covia";
		break;

	case 65:
		prot = "tacacs-ds";
		break;

	case 66:
		prot = "sql*net";
		break;

	case 67:
		prot = "bootps";
		break;

	case 68:
		prot = "bootpc";
		break;

	case 69:
		prot = "tftp";
		break;

	case 70:
		prot = "gopher";
		break;

	case 71:
		prot = "netrjs-1";
		break;

	case 72:
		prot = "netrjs-2";
		break;

	case 73:
		prot = "netrjs-3";
		break;

	case 74:
		prot = "netrjs-4";
		break;

	case 76:
		prot = "deos";
		break;

	case 78:
		prot = "vettcp";
		break;

	case 79:
		prot = "finger";
		break;

	case 80:
		prot = "http";
		break;

	case 81:
		prot = "hosts2-ns";
		break;

	case 82:
		prot = "xfer";
		break;

	case 83:
		prot = "mit-ml-dev";
		break;

	case 84:
		prot = "ctf";
		break;

	case 85:
		prot = "mit-ml-dev";
		break;

	case 86:
		prot = "mfcobol";
		break;

	case 88:
		prot = "kerberos";
		break;

	case 89:
		prot = "su-mit-tg";
		break;

	case 90:
		prot = "dnsix";
		break;

	case 91:
		prot = "mit-dov";
		break;

	case 92:
		prot = "npp";
		break;

	case 93:
		prot = "dcp";
		break;

	case 94:
		prot = "objcall";
		break;

	case 95:
		prot = "supdup";
		break;

	case 96:
		prot = "dixie";
		break;

	case 97:
		prot = "swift-rvf";
		break;

	case 98:
		prot = "tacnews";
		break;

	case 99:
		prot = "metagram";
		break;

	case 100:
		prot = "newacct";
		break;

	case 101:
		prot = "hostname";
		break;

	case 102:
		prot = "iso-tsap";
		break;

	case 103:
		prot = "gppitnp";
		break;

	case 104:
		prot = "acr-nema";
		break;

	case 105:
		prot = "csnet-ns Or cso";
		break;

	case 106:
		prot = "3com-tsmux";
		break;

	case 107:
		prot = "rtelnet";
		break;

	case 108:
		prot = "snagas";
		break;

	case 109:
		prot = "pop2";
		break;

	case 110:
		prot = "pop3";
		break;

	case 111:
		prot = "sunrpc";
		break;

	case 112:
		prot = "mcidas";
		break;

	case 113:
		prot = "auth Or ident";
		break;

	case 114:
		prot = "audionews";
		break;

	case 115:
		prot = "sftp";
		break;

	case 116:
		prot = "ansanotify";
		break;

	case 117:
		prot = "uucp-path";
		break;

	case 118:
		prot = "sqlserv";
		break;

	case 119:
		prot = "nntp";
		break;

	case 120:
		prot = "cfdptkt";
		break;

	case 121:
		prot = "erpc";
		break;

	case 122:
		prot = "smakynet";
		break;

	case 123:
		prot = "ntp";
		break;

	case 124:
		prot = "ansatrader";
		break;

	case 125:
		prot = "locus-map";
		break;

	case 126:
		prot = "nxedit";
		break;

	case 127:
		prot = "locus-con";
		break;

	case 128:
		prot = "gss-xlicen";
		break;

	case 129:
		prot = "pwdgen";
		break;

	case 130:
		prot = "cisco-fna";
		break;

	case 131:
		prot = "cisco-tna";
		break;

	case 132:
		prot = "cisco-sys";
		break;

	case 133:
		prot = "statsrv";
		break;

	case 134:
		prot = "ingres-net";
		break;

	case 135:
		prot = "epmap";
		break;

	case 136:
		prot = "profile";
		break;

	case 137:
		prot = "netbios-ns";
		break;

	case 138:
		prot = "netbios-dgm";
		break;

	case 139:
		prot = "netbios-ssn";
		break;

	case 140:
		prot = "emfis-data";
		break;

	case 141:
		prot = "emfis-cntl";
		break;

	case 142:
		prot = "bl-idm";
		break;

	case 143:
		prot = "imap";
		break;

	case 144:
		prot = "uma";
		break;

	case 145:
		prot = "uaac";
		break;

	case 146:
		prot = "iso-tp0";
		break;

	case 147:
		prot = "iso-ip";
		break;

	case 148:
		prot = "jargon";
		break;

	case 149:
		prot = "aed-512";
		break;

	case 150:
		prot = "sql-net";
		break;

	case 151:
		prot = "hems";
		break;

	case 152:
		prot = "bftp";
		break;

	case 153:
		prot = "sgmp";
		break;

	case 154:
		prot = "netsc-prod";
		break;

	case 155:
		prot = "netsc-dev";
		break;

	case 156:
		prot = "sqlsrv";
		break;

	case 157:
		prot = "knet-cmp";
		break;

	case 158:
		prot = "pcmail-srv";
		break;

	case 159:
		prot = "nss-routing";
		break;

	case 160:
		prot = "sgmp-traps";
		break;

	case 161:
		prot = "snmp";
		break;

	case 162:
		prot = "snmptrap";
		break;

	case 163:
		prot = "cmip-man";
		break;

	case 164:
		prot = "cmip-agent";
		break;

	case 165:
		prot = "xns-courier";
		break;

	case 166:
		prot = "s-net";
		break;

	case 167:
		prot = "namp";
		break;

	case 168:
		prot = "rsvd";
		break;

	case 169:
		prot = "send";
		break;

	case 170:
		prot = "print-srv";
		break;

	case 171:
		prot = "multiplex";
		break;

	case 173:
		prot = "xyplex-mux";
		break;

	case 174:
		prot = "mailq";
		break;

	case 175:
		prot = "vmnet";
		break;

	case 176:
		prot = "genrad-mux";
		break;

	case 177:
		prot = "xdmcp";
		break;

	case 178:
		prot = "nextstep";
		break;

	case 179:
		prot = "bgp";
		break;

	case 180:
		prot = "ris";
		break;

	case 181:
		prot = "unify";
		break;

	case 182:
		prot = "audit";
		break;

	case 183:
		prot = "ocbinder";
		break;

	case 184:
		prot = "ocserver";
		break;

	case 185:
		prot = "remote-kis";
		break;

	case 186:
		prot = "kis";
		break;

	case 187:
		prot = "aci";
		break;

	case 188:
		prot = "mumps";
		break;

	case 189:
		prot = "qft";
		break;

	case 190:
		prot = "gacp";
		break;

	case 191:
		prot = "prospero";
		break;

	case 192:
		prot = "osu-nms";
		break;

	case 193:
		prot = "srmp";
		break;

	case 194:
		prot = "irc";
		break;

	case 195:
		prot = "dn6-nlm-aud";
		break;

	case 196:
		prot = "dn6-smm-red";
		break;

	case 197:
		prot = "dls";
		break;

	case 198:
		prot = "dls-mon";
		break;

	case 199:
		prot = "smux";
		break;

	case 200:
		prot = "src";
		break;

	case 201:
		prot = "at-rtmp";
		break;

	case 202:
		prot = "at-nbp";
		break;

	case 203:
		prot = "at-3";
		break;

	case 204:
		prot = "at-echo";
		break;

	case 205:
		prot = "at-5";
		break;

	case 206:
		prot = "at-zis";
		break;

	case 207:
		prot = "at-7";
		break;

	case 208:
		prot = "at-8";
		break;

	case 209:
		prot = "qmtp";
		break;

	case 210:
		prot = "z39.50";
		break;

	case 212:
		prot = "anet";
		break;

	case 213:
		prot = "ipx";
		break;

	case 214:
		prot = "vmpwscs";
		break;

	case 215:
		prot = "softpc";
		break;

	case 216:
		prot = "CAIlic";
		break;

	case 217:
		prot = "dbase";
		break;

	case 218:
		prot = "mpp";
		break;

	case 219:
		prot = "uarps";
		break;

	case 220:
		prot = "imap3";
		break;

	case 221:
		prot = "fln-spx";
		break;

	case 222:
		prot = "rsh-spx";
		break;

	case 223:
		prot = "cdc";
		break;

	case 224:
		prot = "masqdialer";
		break;

	case 242:
		prot = "direct";
		break;

	case 243:
		prot = "sur-meas";
		break;

	case 244:
		prot = "inbusiness";
		break;

	case 245:
		prot = "link";
		break;

	case 246:
		prot = "dsp3270";
		break;

	case 247:
		prot = "subntbcst_tftp";
		break;

	case 248:
		prot = "bhfhs";
		break;

	case 256:
		prot = "rap";
		break;

	case 257:
		prot = "set";
		break;

	case 258:
		prot = "yak-chat";
		break;

	case 259:
		prot = "esro-gen";
		break;

	case 260:
		prot = "openport";
		break;

	case 261:
		prot = "nsiiops";
		break;

	case 262:
		prot = "arcisdms";
		break;

	case 263:
		prot = "hdap";
		break;

	case 264:
		prot = "bgmp";
		break;

	case 265:
		prot = "x-bone-ctl";
		break;

	case 266:
		prot = "sst";
		break;

	case 267:
		prot = "td-service";
		break;

	case 268:
		prot = "td-replica";
		break;

	case 280:
		prot = "http-mgmt";
		break;

	case 281:
		prot = "personal-link";
		break;

	case 282:
		prot = "cableport-ax";
		break;

	case 283:
		prot = "rescap";
		break;

	case 284:
		prot = "corerjd";
		break;

	case 286:
		prot = "fxp-1";
		break;

	case 287:
		prot = "k-block";
		break;

	case 308:
		prot = "novastorbakcup";
		break;

	case 309:
		prot = "entrusttime";
		break;

	case 310:
		prot = "bhmds";
		break;

	case 311:
		prot = "asip-webadmin";
		break;

	case 312:
		prot = "vslmp";
		break;

	case 313:
		prot = "magenta-logic";
		break;

	case 314:
		prot = "opalis-robot";
		break;

	case 315:
		prot = "dpsi";
		break;

	case 316:
		prot = "decauth";
		break;

	case 317:
		prot = "zannet";
		break;

	case 318:
		prot = "pkix-timestamp";
		break;

	case 319:
		prot = "ptp-event";
		break;

	case 320:
		prot = "ptp-general";
		break;

	case 321:
		prot = "pip";
		break;

	case 322:
		prot = "rtsps";
		break;

	case 333:
		prot = "texar";
		break;

	case 344:
		prot = "pdap";
		break;

	case 345:
		prot = "pawserv";
		break;

	case 346:
		prot = "zserv";
		break;

	case 347:
		prot = "fatserv";
		break;

	case 348:
		prot = "csi-sgwp";
		break;

	case 349:
		prot = "mftp";
		break;

	case 350:
		prot = "matip-type-a";
		break;

	case 351:
		prot = "bhoetty Or matip-type-b";
		break;

	case 352:
		prot = "bhoedap4 Or dtag-ste-sb";
		break;

	case 353:
		prot = "ndsauth";
		break;

	case 354:
		prot = "bh611";
		break;

	case 355:
		prot = "datex-asn";
		break;

	case 356:
		prot = "cloanto-net-1";
		break;

	case 357:
		prot = "bhevent";
		break;

	case 358:
		prot = "shrinkwrap";
		break;

	case 359:
		prot = "nsrmp";
		break;

	case 360:
		prot = "scoi2odialog";
		break;

	case 361:
		prot = "semantix";
		break;

	case 362:
		prot = "srssend";
		break;

	case 363:
		prot = "rsvp_tunnel";
		break;

	case 364:
		prot = "aurora-cmgr";
		break;

	case 365:
		prot = "dtk";
		break;

	case 366:
		prot = "odmr";
		break;

	case 367:
		prot = "mortgageware";
		break;

	case 368:
		prot = "qbikgdp";
		break;

	case 369:
		prot = "rpc2portmap";
		break;

	case 370:
		prot = "codaauth2";
		break;

	case 371:
		prot = "clearcase";
		break;

	case 372:
		prot = "ulistproc";
		break;

	case 373:
		prot = "legent-1";
		break;

	case 374:
		prot = "legent-2";
		break;

	case 375:
		prot = "hassle";
		break;

	case 376:
		prot = "nip";
		break;

	case 377:
		prot = "tnETOS";
		break;

	case 378:
		prot = "dsETOS";
		break;

	case 379:
		prot = "is99c";
		break;

	case 380:
		prot = "is99s";
		break;

	case 381:
		prot = "hp-collector";
		break;

	case 382:
		prot = "hp-managed-node";
		break;

	case 383:
		prot = "hp-alarm-mgr";
		break;

	case 384:
		prot = "arns";
		break;

	case 385:
		prot = "ibm-app";
		break;

	case 386:
		prot = "asa";
		break;

	case 387:
		prot = "aurp";
		break;

	case 388:
		prot = "unidata-ldm";
		break;

	case 389:
		prot = "ldap";
		break;

	case 390:
		prot = "uis";
		break;

	case 391:
		prot = "synotics-relay";
		break;

	case 392:
		prot = "synotics-broker";
		break;

	case 393:
		prot = "meta5";
		break;

	case 394:
		prot = "embl-ndt";
		break;

	case 395:
		prot = "netcp";
		break;

	case 396:
		prot = "netware-ip";
		break;

	case 397:
		prot = "mptn";
		break;

	case 398:
		prot = "kryptolan";
		break;

	case 399:
		prot = "iso-tsap-c2";
		break;

	case 400:
		prot = "work-sol";
		break;

	case 401:
		prot = "ups";
		break;

	case 402:
		prot = "genie";
		break;

	case 403:
		prot = "decap";
		break;

	case 404:
		prot = "nced";
		break;

	case 405:
		prot = "ncld";
		break;

	case 406:
		prot = "imsp";
		break;

	case 407:
		prot = "timbuktu";
		break;

	case 408:
		prot = "prm-sm";
		break;

	case 409:
		prot = "prm-nm";
		break;

	case 410:
		prot = "decladebug";
		break;

	case 411:
		prot = "rmt";
		break;

	case 412:
		prot = "synoptics-trap";
		break;

	case 413:
		prot = "smsp";
		break;

	case 414:
		prot = "infoseek";
		break;

	case 415:
		prot = "bnet";
		break;

	case 416:
		prot = "silverplatter";
		break;

	case 417:
		prot = "onmux";
		break;

	case 418:
		prot = "hyper-g";
		break;

	case 419:
		prot = "ariel1";
		break;

	case 420:
		prot = "smpte";
		break;

	case 421:
		prot = "ariel2";
		break;

	case 422:
		prot = "ariel3";
		break;

	case 423:
		prot = "opc-job-start";
		break;

	case 424:
		prot = "opc-job-track";
		break;

	case 425:
		prot = "icad-el";
		break;

	case 426:
		prot = "smartsdp";
		break;

	case 427:
		prot = "svrloc";
		break;

	case 428:
		prot = "ocs_cmu";
		break;

	case 429:
		prot = "ocs_amu";
		break;

	case 430:
		prot = "utmpsd";
		break;

	case 431:
		prot = "utmpcd";
		break;

	case 432:
		prot = "iasd";
		break;

	case 433:
		prot = "nnsp";
		break;

	case 434:
		prot = "mobileip-agent";
		break;

	case 435:
		prot = "mobilip-mn";
		break;

	case 436:
		prot = "dna-cml";
		break;

	case 437:
		prot = "comscm";
		break;

	case 438:
		prot = "dsfgw";
		break;

	case 439:
		prot = "dasp";
		break;

	case 440:
		prot = "sgcp";
		break;

	case 441:
		prot = "decvms-sysmgt";
		break;

	case 442:
		prot = "cvc_hostd";
		break;

	case 443:
		prot = "https";
		break;

	case 444:
		prot = "snpp";
		break;

	case 445:
		prot = "microsoft-ds";
		break;

	case 446:
		prot = "ddm-rdb";
		break;

	case 447:
		prot = "ddm-dfm";
		break;

	case 448:
		prot = "ddm-ssl";
		break;

	case 449:
		prot = "as-servermap";
		break;

	case 450:
		prot = "tserver";
		break;

	case 451:
		prot = "sfs-smp-net";
		break;

	case 452:
		prot = "sfs-config";
		break;

	case 453:
		prot = "creativeserver";
		break;

	case 454:
		prot = "contentserver";
		break;

	case 455:
		prot = "creativepartnr";
		break;

	case 456:
		prot = "macon";
		break;

	case 457:
		prot = "scohelp";
		break;

	case 458:
		prot = "appleqtc";
		break;

	case 459:
		prot = "ampr-rcmd";
		break;

	case 460:
		prot = "skronk";
		break;

	case 461:
		prot = "datasurfsrv";
		break;

	case 462:
		prot = "datasurfsrvsec";
		break;

	case 463:
		prot = "alpes";
		break;

	case 464:
		prot = "kpasswd";
		break;

	case 465:
		prot = "igmpv3lite Or urd";
		break;

	case 466:
		prot = "digital-vrc";
		break;

	case 467:
		prot = "mylex-mapd";
		break;

	case 468:
		prot = "photuris";
		break;

	case 469:
		prot = "rcp";
		break;

	case 470:
		prot = "scx-proxy";
		break;

	case 471:
		prot = "mondex";
		break;

	case 472:
		prot = "ljk-login";
		break;

	case 473:
		prot = "hybrid-pop";
		break;

	case 474:
		prot = "tn-tl-w1";
		break;

	case 475:
		prot = "tcpnethaspsrv";
		break;

	case 476:
		prot = "tn-tl-fd1";
		break;

	case 477:
		prot = "ss7ns";
		break;

	case 478:
		prot = "spsc";
		break;

	case 479:
		prot = "iafserver";
		break;

	case 480:
		prot = "iafdbase";
		break;

	case 481:
		prot = "ph";
		break;

	case 482:
		prot = "bgs-nsi";
		break;

	case 483:
		prot = "ulpnet";
		break;

	case 484:
		prot = "integra-sme";
		break;

	case 485:
		prot = "powerburst";
		break;

	case 486:
		prot = "avian";
		break;

	case 487:
		prot = "saft";
		break;

	case 488:
		prot = "gss-http";
		break;

	case 489:
		prot = "nest-protocol";
		break;

	case 490:
		prot = "micom-pfs";
		break;

	case 491:
		prot = "go-login";
		break;

	case 492:
		prot = "ticf-1";
		break;

	case 493:
		prot = "ticf-2";
		break;

	case 494:
		prot = "pov-ray";
		break;

	case 495:
		prot = "intecourier";
		break;

	case 496:
		prot = "pim-rp-disc";
		break;

	case 497:
		prot = "dantz";
		break;

	case 498:
		prot = "siam";
		break;

	case 499:
		prot = "iso-ill";
		break;

	case 500:
		prot = "isakmp";
		break;

	case 501:
		prot = "stmf";
		break;

	case 502:
		prot = "asa-appl-proto";
		break;

	case 503:
		prot = "intrinsa";
		break;

	case 504:
		prot = "citadel";
		break;

	case 505:
		prot = "mailbox-lm";
		break;

	case 506:
		prot = "ohimsrv";
		break;

	case 507:
		prot = "crs";
		break;

	case 508:
		prot = "xvttp";
		break;

	case 509:
		prot = "snare";
		break;

	case 510:
		prot = "fcp";
		break;

	case 511:
		prot = "passgo";
		break;

	case 512:
		prot = "comsat Or exec";
		break;

	case 513:
		prot = "login Or who";
		break;

	case 514:
		prot = "shell Or syslog";
		break;

	case 515:
		prot = "printer";
		break;

	case 516:
		prot = "videotex";
		break;

	case 517:
		prot = "talk";
		break;

	case 518:
		prot = "ntalk";
		break;

	case 519:
		prot = "utime";
		break;

	case 520:
		prot = "efs Or router";
		break;

	case 521:
		prot = "ripng";
		break;

	case 522:
		prot = "ulp";
		break;

	case 523:
		prot = "ibm-db2";
		break;

	case 524:
		prot = "ncp";
		break;

	case 525:
		prot = "timed";
		break;

	case 526:
		prot = "tempo";
		break;

	case 527:
		prot = "stx";
		break;

	case 528:
		prot = "custix";
		break;

	case 529:
		prot = "irc-serv";
		break;

	case 530:
		prot = "courier";
		break;

	case 531:
		prot = "conference";
		break;

	case 532:
		prot = "netnews";
		break;

	case 533:
		prot = "netwall";
		break;

	case 534:
		prot = "mm-admin";
		break;

	case 535:
		prot = "iiop";
		break;

	case 536:
		prot = "opalis-rdv";
		break;

	case 537:
		prot = "nmsp";
		break;

	case 538:
		prot = "gdomap";
		break;

	case 539:
		prot = "apertus-ldp";
		break;

	case 540:
		prot = "uucp";
		break;

	case 541:
		prot = "uucp-rlogin";
		break;

	case 542:
		prot = "commerce";
		break;

	case 543:
		prot = "klogin";
		break;

	case 544:
		prot = "kshell";
		break;

	case 545:
		prot = "appleqtcsrvr";
		break;

	case 546:
		prot = "dhcpv6-client";
		break;

	case 547:
		prot = "dhcpv6-server";
		break;

	case 548:
		prot = "afpovertcp";
		break;

	case 549:
		prot = "idfp";
		break;

	case 550:
		prot = "new-rwho";
		break;

	case 551:
		prot = "cybercash";
		break;

	case 552:
		prot = "devshr-nts";
		break;

	case 553:
		prot = "pirp";
		break;

	case 554:
		prot = "rtsp - real time streaming";
		break;

	case 555:
		prot = "dsf";
		break;

	case 556:
		prot = "remotefs";
		break;

	case 557:
		prot = "openvms-sysipc";
		break;

	case 558:
		prot = "sdnskmp";
		break;

	case 559:
		prot = "teedtap";
		break;

	case 560:
		prot = "rmonitor";
		break;

	case 561:
		prot = "monitor";
		break;

	case 562:
		prot = "chshell";
		break;

	case 563:
		prot = "nntps";
		break;

	case 564:
		prot = "9pfs";
		break;

	case 565:
		prot = "whoami";
		break;

	case 566:
		prot = "streettalk";
		break;

	case 567:
		prot = "banyan-rpc";
		break;

	case 568:
		prot = "ms-shuttle";
		break;

	case 569:
		prot = "ms-rome";
		break;

	case 570:
		prot = "meter";
		break;

	case 571:
		prot = "meter";
		break;

	case 572:
		prot = "sonar";
		break;

	case 573:
		prot = "banyan-vip";
		break;

	case 574:
		prot = "ftp-agent";
		break;

	case 575:
		prot = "vemmi";
		break;

	case 576:
		prot = "ipcd";
		break;

	case 577:
		prot = "vnas";
		break;

	case 578:
		prot = "ipdd";
		break;

	case 579:
		prot = "decbsrv";
		break;

	case 580:
		prot = "sntp-heartbeat";
		break;

	case 581:
		prot = "bdp";
		break;

	case 582:
		prot = "scc-security";
		break;

	case 583:
		prot = "philips-vc";
		break;

	case 584:
		prot = "keyserver";
		break;

	case 585:
		prot = "imap4-ssl";
		break;

	case 586:
		prot = "password-chg";
		break;

	case 587:
		prot = "submission";
		break;

	case 588:
		prot = "cal";
		break;

	case 589:
		prot = "eyelink";
		break;

	case 590:
		prot = "tns-cml";
		break;

	case 591:
		prot = "http-alt";
		break;

	case 592:
		prot = "eudora-set";
		break;

	case 593:
		prot = "http-rpc-epmap";
		break;

	case 594:
		prot = "tpip";
		break;

	case 595:
		prot = "cab-protocol";
		break;

	case 596:
		prot = "smsd";
		break;

	case 597:
		prot = "ptcnameservice";
		break;

	case 598:
		prot = "sco-websrvrmg3";
		break;

	case 599:
		prot = "acp";
		break;

	case 600:
		prot = "ipcserver";
		break;

	case 601:
		prot = "syslog-conn";
		break;

	case 602:
		prot = "xmlrpc-beep";
		break;

	case 603:
		prot = "idxp";
		break;

	case 604:
		prot = "tunnel";
		break;

	case 605:
		prot = "soap-beep";
		break;

	case 606:
		prot = "urm";
		break;

	case 607:
		prot = "nqs";
		break;

	case 608:
		prot = "sift-uft";
		break;

	case 609:
		prot = "npmp-trap";
		break;

	case 610:
		prot = "npmp-local";
		break;

	case 611:
		prot = "npmp-gui";
		break;

	case 612:
		prot = "hmmp-ind";
		break;

	case 613:
		prot = "hmmp-op";
		break;

	case 614:
		prot = "sshell";
		break;

	case 615:
		prot = "sco-inetmgr";
		break;

	case 616:
		prot = "sco-sysmgr";
		break;

	case 617:
		prot = "sco-dtmgr";
		break;

	case 618:
		prot = "dei-icda";
		break;

	case 619:
		prot = "compaq-evm";
		break;

	case 620:
		prot = "sco-websrvrmgr";
		break;

	case 621:
		prot = "escp-ip";
		break;

	case 622:
		prot = "collaborator";
		break;

	case 623:
		prot = "asf-rmcp";
		break;

	case 624:
		prot = "cryptoadmin";
		break;

	case 625:
		prot = "dec_dlm";
		break;

	case 626:
		prot = "asia";
		break;

	case 627:
		prot = "passgo-tivoli";
		break;

	case 628:
		prot = "qmqp";
		break;

	case 629:
		prot = "3com-amp3";
		break;

	case 630:
		prot = "rda";
		break;

	case 631:
		prot = "ipp/CUPS";
		break;

	case 632:
		prot = "bmpp";
		break;

	case 633:
		prot = "servstat";
		break;

	case 634:
		prot = "ginad";
		break;

	case 635:
		prot = "rlzdbase";
		break;

	case 636:
		prot = "ldaps";
		break;

	case 637:
		prot = "lanserver";
		break;

	case 638:
		prot = "mcns-sec";
		break;

	case 639:
		prot = "msdp";
		break;

	case 640:
		prot = "entrust-sps";
		break;

	case 641:
		prot = "repcmd";
		break;

	case 642:
		prot = "esro-emsdp";
		break;

	case 643:
		prot = "sanity";
		break;

	case 644:
		prot = "dwr";
		break;

	case 645:
		prot = "pssc";
		break;

	case 646:
		prot = "ldp";
		break;

	case 647:
		prot = "dhcp-failover";
		break;

	case 648:
		prot = "rrp";
		break;

	case 649:
		prot = "cadview-3d";
		break;

	case 650:
		prot = "obex";
		break;

	case 651:
		prot = "ieee-mms";
		break;

	case 652:
		prot = "hello-port";
		break;

	case 653:
		prot = "repscmd";
		break;

	case 654:
		prot = "aodv";
		break;

	case 655:
		prot = "tinc";
		break;

	case 656:
		prot = "spmp";
		break;

	case 657:
		prot = "rmc";
		break;

	case 658:
		prot = "tenfold";
		break;

	case 660:
		prot = "mac-srvr-admin";
		break;

	case 661:
		prot = "hap";
		break;

	case 662:
		prot = "pftp";
		break;

	case 663:
		prot = "purenoise";
		break;

	case 664:
		prot = "asf-secure-rmcp";
		break;

	case 665:
		prot = "sun-dr";
		break;

	case 666:
		prot = "mdqs";
		break;

	case 667:
		prot = "disclose";
		break;

	case 668:
		prot = "mecomm";
		break;

	case 669:
		prot = "meregister";
		break;

	case 670:
		prot = "vacdsm-sws";
		break;

	case 671:
		prot = "vacdsm-app";
		break;

	case 672:
		prot = "vpps-qua";
		break;

	case 673:
		prot = "cimplex";
		break;

	case 674:
		prot = "acap";
		break;

	case 675:
		prot = "dctp";
		break;

	case 676:
		prot = "vpps-via";
		break;

	case 677:
		prot = "vpp";
		break;

	case 678:
		prot = "ggf-ncp";
		break;

	case 679:
		prot = "mrm";
		break;

	case 680:
		prot = "entrust-aaas";
		break;

	case 681:
		prot = "entrust-aams";
		break;

	case 682:
		prot = "xfr";
		break;

	case 683:
		prot = "corba-iiop";
		break;

	case 684:
		prot = "corba-iiop-ssl";
		break;

	case 685:
		prot = "mdc-portmapper";
		break;

	case 686:
		prot = "hcp-wismar";
		break;

	case 687:
		prot = "asipregistry";
		break;

	case 688:
		prot = "realm-rusd";
		break;

	case 689:
		prot = "nmap";
		break;

	case 690:
		prot = "vatp";
		break;

	case 691:
		prot = "msexch-routing";
		break;

	case 692:
		prot = "hyperwave-isp";
		break;

	case 693:
		prot = "connendp";
		break;

	case 694:
		prot = "ha-cluster";
		break;

	case 695:
		prot = "ieee-mms-ssl";
		break;

	case 696:
		prot = "rushd";
		break;

	case 697:
		prot = "uuidgen";
		break;

	case 698:
		prot = "olsr";
		break;

	case 699:
		prot = "accessnetwork";
		break;

	case 700:
		prot = "epp";
		break;

	case 701:
		prot = "lmp";
		break;

	case 702:
		prot = "iris-beep";
		break;

	case 704:
		prot = "elcsd";
		break;

	case 705:
		prot = "agentx";
		break;

	case 706:
		prot = "silc";
		break;

	case 707:
		prot = "borland-dsj";
		break;

	case 709:
		prot = "entrust-kmsh";
		break;

	case 710:
		prot = "entrust-ash";
		break;

	case 711:
		prot = "cisco-tdp";
		break;

	case 712:
		prot = "tbrpf";
		break;

	case 729:
		prot = "netviewdm1";
		break;

	case 730:
		prot = "netviewdm2";
		break;

	case 731:
		prot = "netviewdm3";
		break;

	case 741:
		prot = "netgw";
		break;

	case 742:
		prot = "netrcs";
		break;

	case 744:
		prot = "flexlm";
		break;

	case 747:
		prot = "fujitsu-dev";
		break;

	case 748:
		prot = "ris-cm";
		break;

	case 749:
		prot = "kerberos-adm";
		break;

	case 750:
		prot = "loadav Or rfile";
		break;

	case 751:
		prot = "pump";
		break;

	case 752:
		prot = "qrh";
		break;

	case 753:
		prot = "rrh";
		break;

	case 754:
		prot = "tell";
		break;

	case 758:
		prot = "nlogin";
		break;

	case 759:
		prot = "con";
		break;

	case 760:
		prot = "ns";
		break;

	case 761:
		prot = "rxe";
		break;

	case 762:
		prot = "quotad";
		break;

	case 763:
		prot = "cycleserv";
		break;

	case 764:
		prot = "omserv";
		break;

	case 765:
		prot = "webster";
		break;

	case 767:
		prot = "phonebook";
		break;

	case 769:
		prot = "vid";
		break;

	case 770:
		prot = "cadlock";
		break;

	case 771:
		prot = "rtip";
		break;

	case 772:
		prot = "cycleserv2";
		break;

	case 773:
		prot = "notify Or submit";
		break;

	case 774:
		prot = "acmaint_dbd Or rpasswd";
		break;

	case 775:
		prot = "acmaint_transd Or entomb";
		break;

	case 776:
		prot = "wpages";
		break;

	case 777:
		prot = "multiling-http";
		break;

	case 780:
		prot = "wpgs";
		break;

	case 800:
		prot = "mdbs_daemon";
		break;

	case 801:
		prot = "device";
		break;

	case 810:
		prot = "fcp-udp";
		break;

	case 828:
		prot = "itm-mcell-s";
		break;

	case 829:
		prot = "pkix-3-ca-ra";
		break;

	case 830:
		prot = "netconf-ssh";
		break;

	case 831:
		prot = "netconf-beep";
		break;

	case 832:
		prot = "netconfsoaphttp";
		break;

	case 833:
		prot = "netconfsoapbeep";
		break;

	case 847:
		prot = "dhcp-failover2";
		break;

	case 848:
		prot = "gdoi";
		break;

	case 860:
		prot = "iscsi";
		break;

	case 861:
		prot = "owamp-control";
		break;

	case 873:
		prot = "rsync";
		break;

	case 886:
		prot = "iclcnet-locate";
		break;

	case 887:
		prot = "iclcnet_svinfo";
		break;

	case 888:
		prot = "accessbuilder Or cddbp";
		break;

	case 900:
		prot = "omginitialrefs";
		break;

	case 901:
		prot = "smpnameres";
		break;

	case 902:
		prot = "ideafarm-chat";
		break;

	case 903:
		prot = "ideafarm-catch";
		break;

	case 910:
		prot = "kink";
		break;

	case 911:
		prot = "xact-backup";
		break;

	case 912:
		prot = "apex-mesh";
		break;

	case 913:
		prot = "apex-edge";
		break;

	case 989:
		prot = "ftps-data";
		break;

	case 990:
		prot = "ftps";
		break;

	case 991:
		prot = "nas";
		break;

	case 992:
		prot = "telnets";
		break;

	case 993:
		prot = "imaps";
		break;

	case 994:
		prot = "ircs";
		break;

	case 995:
		prot = "pop3s";
		break;

	case 996:
		prot = "vsinet";
		break;

	case 997:
		prot = "maitrd";
		break;

	case 998:
		prot = "busboy Or puparp";
		break;

	case 999:
		prot = "applix Or garcon";
		break;

	case 1000:
		prot = "cadlock2";
		break;

	case 1010:
		prot = "surf";
		break;

	case 1021:
		prot = "exp1";
		break;

	case 1022:
		prot = "exp2";
		break;

	case 1025:
		prot = "blackjack";
		break;

	case 1026:
		prot = "cap";
		break;

	case 1027:
		prot = "exosee";
		break;

	case 1029:
		prot = "solid-mux";
		break;

	case 1030:
		prot = "iad1";
		break;

	case 1031:
		prot = "iad2";
		break;

	case 1032:
		prot = "iad3";
		break;

	case 1033:
		prot = "netinfo-local";
		break;

	case 1034:
		prot = "activesync";
		break;

	case 1035:
		prot = "mxxrlogin";
		break;

	case 1036:
		prot = "pcg-radar";
		break;

	case 1037:
		prot = "ams";
		break;

	case 1038:
		prot = "mtqp";
		break;

	case 1039:
		prot = "sbl";
		break;

	case 1040:
		prot = "netarx";
		break;

	case 1041:
		prot = "danf-ak2";
		break;

	case 1042:
		prot = "afrog";
		break;

	case 1043:
		prot = "boinc-client";
		break;

	case 1044:
		prot = "dcutility";
		break;

	case 1045:
		prot = "fpitp";
		break;

	case 1046:
		prot = "wfremotertm";
		break;

	case 1047:
		prot = "neod1";
		break;

	case 1048:
		prot = "neod2";
		break;

	case 1049:
		prot = "td-postman";
		break;

	case 1050:
		prot = "cma";
		break;

	case 1051:
		prot = "optima-vnet";
		break;

	case 1052:
		prot = "ddt";
		break;

	case 1053:
		prot = "remote-as";
		break;

	case 1054:
		prot = "brvread";
		break;

	case 1055:
		prot = "ansyslmd";
		break;

	case 1056:
		prot = "vfo";
		break;

	case 1057:
		prot = "startron";
		break;

	case 1058:
		prot = "nim";
		break;

	case 1059:
		prot = "nimreg";
		break;

	case 1060:
		prot = "polestar";
		break;

	case 1061:
		prot = "kiosk";
		break;

	case 1062:
		prot = "veracity";
		break;

	case 1063:
		prot = "kyoceranetdev";
		break;

	case 1064:
		prot = "jstel";
		break;

	case 1065:
		prot = "syscomlan";
		break;

	case 1066:
		prot = "fpo-fns";
		break;

	case 1067:
		prot = "instl_boots";
		break;

	case 1068:
		prot = "instl_bootc";
		break;

	case 1069:
		prot = "cognex-insight";
		break;

	case 1070:
		prot = "gmrupdateserv";
		break;

	case 1071:
		prot = "bsquare-voip";
		break;

	case 1072:
		prot = "cardax";
		break;

	case 1073:
		prot = "bridgecontrol";
		break;

	case 1074:
		prot = "fastechnologlm";
		break;

	case 1075:
		prot = "rdrmshc";
		break;

	case 1076:
		prot = "dab-sti-c";
		break;

	case 1077:
		prot = "imgames";
		break;

	case 1078:
		prot = "avocent-proxy";
		break;

	case 1079:
		prot = "asprovatalk";
		break;

	case 1080:
		prot = "socks";
		break;

	case 1081:
		prot = "pvuniwien";
		break;

	case 1082:
		prot = "amt-esd-prot";
		break;

	case 1083:
		prot = "ansoft-lm-1";
		break;

	case 1084:
		prot = "ansoft-lm-2";
		break;

	case 1085:
		prot = "webobjects";
		break;

	case 1086:
		prot = "cplscrambler-lg";
		break;

	case 1087:
		prot = "cplscrambler-in";
		break;

	case 1088:
		prot = "cplscrambler-al";
		break;

	case 1089:
		prot = "ff-annunc";
		break;

	case 1090:
		prot = "ff-fms";
		break;

	case 1091:
		prot = "ff-sm";
		break;

	case 1092:
		prot = "obrpd";
		break;

	case 1093:
		prot = "proofd";
		break;

	case 1094:
		prot = "rootd";
		break;

	case 1095:
		prot = "nicelink";
		break;

	case 1096:
		prot = "cnrprotocol";
		break;

	case 1097:
		prot = "sunclustermgr";
		break;

	case 1098:
		prot = "rmiactivation";
		break;

	case 1099:
		prot = "rmiregistry";
		break;

	case 1100:
		prot = "mctp";
		break;

	case 1101:
		prot = "pt2-discover";
		break;

	case 1102:
		prot = "adobeserver-1";
		break;

	case 1103:
		prot = "adobeserver-2";
		break;

	case 1104:
		prot = "xrl";
		break;

	case 1105:
		prot = "ftranhc";
		break;

	case 1106:
		prot = "isoipsigport-1";
		break;

	case 1107:
		prot = "isoipsigport-2";
		break;

	case 1108:
		prot = "ratio-adp";
		break;

	case 1110:
		prot = "nfsd-keepalive Or nfsd-status";
		break;

	case 1111:
		prot = "lmsocialserver";
		break;

	case 1112:
		prot = "icp";
		break;

	case 1113:
		prot = "ltp-deepspace";
		break;

	case 1114:
		prot = "mini-sql";
		break;

	case 1115:
		prot = "ardus-trns";
		break;

	case 1116:
		prot = "ardus-cntl";
		break;

	case 1117:
		prot = "ardus-mtrns";
		break;

	case 1118:
		prot = "sacred";
		break;

	case 1119:
		prot = "bnetgame";
		break;

	case 1120:
		prot = "bnetfile";
		break;

	case 1121:
		prot = "rmpp";
		break;

	case 1122:
		prot = "availant-mgr";
		break;

	case 1123:
		prot = "murray";
		break;

	case 1124:
		prot = "hpvmmcontrol";
		break;

	case 1125:
		prot = "hpvmmagent";
		break;

	case 1126:
		prot = "hpvmmdata";
		break;

	case 1127:
		prot = "kwdb-commn";
		break;

	case 1128:
		prot = "saphostctrl";
		break;

	case 1129:
		prot = "saphostctrls";
		break;

	case 1130:
		prot = "casp";
		break;

	case 1131:
		prot = "caspssl";
		break;

	case 1132:
		prot = "kvm-via-ip";
		break;

	case 1133:
		prot = "dfn";
		break;

	case 1134:
		prot = "aplx";
		break;

	case 1135:
		prot = "omnivision";
		break;

	case 1136:
		prot = "hhb-gateway";
		break;

	case 1137:
		prot = "trim";
		break;

	case 1140:
		prot = "autonoc";
		break;

	case 1141:
		prot = "mxomss";
		break;

	case 1142:
		prot = "edtools";
		break;

	case 1143:
		prot = "imyx";
		break;

	case 1144:
		prot = "fuscript";
		break;

	case 1145:
		prot = "x9-icue";
		break;

	case 1146:
		prot = "audit-transfer";
		break;

	case 1147:
		prot = "capioverlan";
		break;

	case 1148:
		prot = "elfiq-repl";
		break;

	case 1149:
		prot = "bvtsonar";
		break;

	case 1150:
		prot = "blaze";
		break;

	case 1151:
		prot = "unizensus";
		break;

	case 1152:
		prot = "winpoplanmess";
		break;

	case 1153:
		prot = "c1222-acse";
		break;

	case 1154:
		prot = "resacommunity";
		break;

	case 1155:
		prot = "nfa";
		break;

	case 1156:
		prot = "iascontrol-oms";
		break;

	case 1157:
		prot = "iascontrol";
		break;

	case 1158:
		prot = "dbcontrol-oms";
		break;

	case 1159:
		prot = "oracle-oms";
		break;

	case 1160:
		prot = "olsv";
		break;

	case 1161:
		prot = "health-polling";
		break;

	case 1162:
		prot = "health-trap";
		break;

	case 1163:
		prot = "sddp";
		break;

	case 1164:
		prot = "qsm-proxy";
		break;

	case 1165:
		prot = "qsm-gui";
		break;

	case 1166:
		prot = "qsm-remote";
		break;

	case 1167:
		prot = "cisco-ipsla";
		break;

	case 1168:
		prot = "vchat";
		break;

	case 1169:
		prot = "tripwire";
		break;

	case 1170:
		prot = "atc-lm";
		break;

	case 1171:
		prot = "atc-appserver";
		break;

	case 1172:
		prot = "dnap";
		break;

	case 1173:
		prot = "d-cinema-rrp";
		break;

	case 1174:
		prot = "fnet-remote-ui";
		break;

	case 1175:
		prot = "dossier";
		break;

	case 1176:
		prot = "indigo-server";
		break;

	case 1177:
		prot = "dkmessenger";
		break;

	case 1178:
		prot = "sgi-storman";
		break;

	case 1179:
		prot = "b2n";
		break;

	case 1180:
		prot = "mc-client";
		break;

	case 1181:
		prot = "3comnetman";
		break;

	case 1182:
		prot = "accelenet";
		break;

	case 1183:
		prot = "llsurfup-http";
		break;

	case 1184:
		prot = "llsurfup-https";
		break;

	case 1185:
		prot = "catchpole";
		break;

	case 1186:
		prot = "mysql-cluster";
		break;

	case 1187:
		prot = "alias";
		break;

	case 1188:
		prot = "hp-webadmin";
		break;

	case 1189:
		prot = "unet";
		break;

	case 1190:
		prot = "commlinx-avl";
		break;

	case 1191:
		prot = "gpfs";
		break;

	case 1192:
		prot = "caids-sensor";
		break;

	case 1193:
		prot = "fiveacross";
		break;

	case 1194:
		prot = "openvpn";
		break;

	case 1195:
		prot = "rsf-1";
		break;

	case 1196:
		prot = "netmagic";
		break;

	case 1197:
		prot = "carrius-rshell";
		break;

	case 1198:
		prot = "cajo-discovery";
		break;

	case 1199:
		prot = "dmidi";
		break;

	case 1200:
		prot = "scol";
		break;

	case 1201:
		prot = "nucleus-sand";
		break;

	case 1202:
		prot = "caiccipc";
		break;

	case 1203:
		prot = "ssslic-mgr";
		break;

	case 1204:
		prot = "ssslog-mgr";
		break;

	case 1205:
		prot = "accord-mgc";
		break;

	case 1206:
		prot = "anthony-data";
		break;

	case 1207:
		prot = "metasage";
		break;

	case 1208:
		prot = "seagull-ais";
		break;

	case 1209:
		prot = "ipcd3";
		break;

	case 1210:
		prot = "eoss";
		break;

	case 1211:
		prot = "groove-dpp";
		break;

	case 1212:
		prot = "lupa";
		break;

	case 1213:
		prot = "mpc-lifenet";
		break;

	case 1214:
		prot = "kazaa";
		break;

	case 1215:
		prot = "scanstat-1";
		break;

	case 1216:
		prot = "etebac5";
		break;

	case 1217:
		prot = "hpss-ndapi";
		break;

	case 1218:
		prot = "aeroflight-ads";
		break;

	case 1219:
		prot = "aeroflight-ret";
		break;

	case 1220:
		prot = "qt-serveradmin";
		break;

	case 1221:
		prot = "sweetware-apps";
		break;

	case 1222:
		prot = "nerv";
		break;

	case 1223:
		prot = "tgp";
		break;

	case 1224:
		prot = "vpnz";
		break;

	case 1225:
		prot = "slinkysearch";
		break;

	case 1226:
		prot = "stgxfws";
		break;

	case 1227:
		prot = "dns2go";
		break;

	case 1228:
		prot = "florence";
		break;

	case 1229:
		prot = "novell-zfs";
		break;

	case 1230:
		prot = "periscope";
		break;

	case 1231:
		prot = "menandmice-lpm";
		break;

	case 1233:
		prot = "univ-appserver";
		break;

	case 1234:
		prot = "search-agent";
		break;

	case 1235:
		prot = "mosaicsyssvc1";
		break;

	case 1236:
		prot = "bvcontrol";
		break;

	case 1237:
		prot = "tsdos390";
		break;

	case 1238:
		prot = "hacl-qs";
		break;

	case 1239:
		prot = "nmsd";
		break;

	case 1240:
		prot = "instantia";
		break;

	case 1241:
		prot = "nessus";
		break;

	case 1242:
		prot = "nmasoverip";
		break;

	case 1243:
		prot = "serialgateway";
		break;

	case 1244:
		prot = "isbconference1";
		break;

	case 1245:
		prot = "isbconference2";
		break;

	case 1246:
		prot = "payrouter";
		break;

	case 1247:
		prot = "visionpyramid";
		break;

	case 1248:
		prot = "hermes";
		break;

	case 1249:
		prot = "mesavistaco";
		break;

	case 1250:
		prot = "swldy-sias";
		break;

	case 1251:
		prot = "servergraph";
		break;

	case 1252:
		prot = "bspne-pcc";
		break;

	case 1253:
		prot = "q55-pcc";
		break;

	case 1254:
		prot = "de-noc";
		break;

	case 1255:
		prot = "de-cache-query";
		break;

	case 1256:
		prot = "de-server";
		break;

	case 1257:
		prot = "shockwave2";
		break;

	case 1258:
		prot = "opennl";
		break;

	case 1259:
		prot = "opennl-voice";
		break;

	case 1260:
		prot = "ibm-ssd";
		break;

	case 1261:
		prot = "mpshrsv";
		break;

	case 1262:
		prot = "qnts-orb";
		break;

	case 1263:
		prot = "dka";
		break;

	case 1264:
		prot = "prat";
		break;

	case 1265:
		prot = "dssiapi";
		break;

	case 1266:
		prot = "dellpwrappks";
		break;

	case 1267:
		prot = "epc";
		break;

	case 1268:
		prot = "propel-msgsys";
		break;

	case 1269:
		prot = "watilapp";
		break;

	case 1270:
		prot = "opsmgr";
		break;

	case 1271:
		prot = "dabew";
		break;

	case 1272:
		prot = "cspmlockmgr";
		break;

	case 1273:
		prot = "emc-gateway";
		break;

	case 1274:
		prot = "t1distproc";
		break;

	case 1275:
		prot = "ivcollector";
		break;

	case 1276:
		prot = "ivmanager";
		break;

	case 1277:
		prot = "miva-mqs";
		break;

	case 1278:
		prot = "dellwebadmin-1";
		break;

	case 1279:
		prot = "dellwebadmin-2";
		break;

	case 1280:
		prot = "pictrography";
		break;

	case 1281:
		prot = "healthd";
		break;

	case 1282:
		prot = "emperion";
		break;

	case 1283:
		prot = "productinfo";
		break;

	case 1284:
		prot = "iee-qfx";
		break;

	case 1285:
		prot = "neoiface";
		break;

	case 1286:
		prot = "netuitive";
		break;

	case 1287:
		prot = "routematch";
		break;

	case 1288:
		prot = "navbuddy";
		break;

	case 1289:
		prot = "jwalkserver";
		break;

	case 1290:
		prot = "winjaserver";
		break;

	case 1291:
		prot = "seagulllms";
		break;

	case 1292:
		prot = "dsdn";
		break;

	case 1293:
		prot = "pkt-krb-ipsec";
		break;

	case 1294:
		prot = "cmmdriver";
		break;

	case 1295:
		prot = "ehtp";
		break;

	case 1296:
		prot = "dproxy";
		break;

	case 1297:
		prot = "sdproxy";
		break;

	case 1298:
		prot = "lpcp";
		break;

	case 1299:
		prot = "hp-sci";
		break;

	case 1300:
		prot = "h323hostcallsc";
		break;

	case 1301:
		prot = "ci3-software-1";
		break;

	case 1302:
		prot = "ci3-software-2";
		break;

	case 1303:
		prot = "sftsrv";
		break;

	case 1304:
		prot = "boomerang";
		break;

	case 1305:
		prot = "pe-mike";
		break;

	case 1306:
		prot = "re-conn-proto";
		break;

	case 1307:
		prot = "pacmand";
		break;

	case 1308:
		prot = "odsi";
		break;

	case 1309:
		prot = "jtag-server";
		break;

	case 1310:
		prot = "husky";
		break;

	case 1311:
		prot = "rxmon";
		break;

	case 1312:
		prot = "sti-envision";
		break;

	case 1313:
		prot = "bmc_patroldb";
		break;

	case 1314:
		prot = "pdps";
		break;

	case 1315:
		prot = "els";
		break;

	case 1316:
		prot = "exbit-escp";
		break;

	case 1317:
		prot = "vrts-ipcserver";
		break;

	case 1318:
		prot = "krb5gatekeeper";
		break;

	case 1319:
		prot = "panja-icsp";
		break;

	case 1320:
		prot = "panja-axbnet";
		break;

	case 1321:
		prot = "pip";
		break;

	case 1322:
		prot = "novation";
		break;

	case 1323:
		prot = "brcd";
		break;

	case 1324:
		prot = "delta-mcp";
		break;

	case 1325:
		prot = "dx-instrument";
		break;

	case 1326:
		prot = "wimsic";
		break;

	case 1327:
		prot = "ultrex";
		break;

	case 1328:
		prot = "ewall";
		break;

	case 1329:
		prot = "netdb-export";
		break;

	case 1330:
		prot = "streetperfect";
		break;

	case 1331:
		prot = "intersan";
		break;

	case 1332:
		prot = "pcia-rxp-b";
		break;

	case 1333:
		prot = "passwrd-policy";
		break;

	case 1334:
		prot = "writesrv";
		break;

	case 1335:
		prot = "digital-notary";
		break;

	case 1336:
		prot = "ischat";
		break;

	case 1337:
		prot = "menandmice-dns";
		break;

	case 1338:
		prot = "wmc-log-svc";
		break;

	case 1339:
		prot = "kjtsiteserver";
		break;

	case 1340:
		prot = "naap";
		break;

	case 1341:
		prot = "qubes";
		break;

	case 1342:
		prot = "esbroker";
		break;

	case 1343:
		prot = "re101";
		break;

	case 1344:
		prot = "icap";
		break;

	case 1345:
		prot = "vpjp";
		break;

	case 1346:
		prot = "alta-ana-lm";
		break;

	case 1347:
		prot = "bbn-mmc";
		break;

	case 1348:
		prot = "bbn-mmx";
		break;

	case 1349:
		prot = "sbook";
		break;

	case 1350:
		prot = "editbench";
		break;

	case 1351:
		prot = "equationbuilder";
		break;

	case 1352:
		prot = "lotusnote";
		break;

	case 1353:
		prot = "relief";
		break;

	case 1354:
		prot = "rightbrain";
		break;

	case 1355:
		prot = "intuitive-edge";
		break;

	case 1356:
		prot = "cuillamartin";
		break;

	case 1357:
		prot = "pegboard";
		break;

	case 1358:
		prot = "connlcli";
		break;

	case 1359:
		prot = "ftsrv";
		break;

	case 1360:
		prot = "mimer";
		break;

	case 1361:
		prot = "linx";
		break;

	case 1362:
		prot = "timeflies";
		break;

	case 1363:
		prot = "ndm-requester";
		break;

	case 1364:
		prot = "ndm-server";
		break;

	case 1365:
		prot = "adapt-sna";
		break;

	case 1366:
		prot = "netware-csp";
		break;

	case 1367:
		prot = "dcs";
		break;

	case 1368:
		prot = "screencast";
		break;

	case 1369:
		prot = "gv-us";
		break;

	case 1370:
		prot = "us-gv";
		break;

	case 1371:
		prot = "fc-cli";
		break;

	case 1372:
		prot = "fc-ser";
		break;

	case 1373:
		prot = "chromagrafx";
		break;

	case 1374:
		prot = "molly";
		break;

	case 1375:
		prot = "bytex";
		break;

	case 1376:
		prot = "ibm-pps";
		break;

	case 1377:
		prot = "cichlid";
		break;

	case 1378:
		prot = "elan";
		break;

	case 1379:
		prot = "dbreporter";
		break;

	case 1380:
		prot = "telesis-licman";
		break;

	case 1381:
		prot = "apple-licman";
		break;

	case 1382:
		prot = "udt_os";
		break;

	case 1383:
		prot = "gwha";
		break;

	case 1384:
		prot = "os-licman";
		break;

	case 1385:
		prot = "atex_elmd";
		break;

	case 1386:
		prot = "checksum";
		break;

	case 1387:
		prot = "cadsi-lm";
		break;

	case 1388:
		prot = "objective-dbc";
		break;

	case 1389:
		prot = "iclpv-dm";
		break;

	case 1390:
		prot = "iclpv-sc";
		break;

	case 1391:
		prot = "iclpv-sas";
		break;

	case 1392:
		prot = "iclpv-pm";
		break;

	case 1393:
		prot = "iclpv-nls";
		break;

	case 1394:
		prot = "iclpv-nlc";
		break;

	case 1395:
		prot = "iclpv-wsm";
		break;

	case 1396:
		prot = "dvl-activemail";
		break;

	case 1397:
		prot = "audio-activmail";
		break;

	case 1398:
		prot = "video-activmail";
		break;

	case 1399:
		prot = "cadkey-licman";
		break;

	case 1400:
		prot = "cadkey-tablet";
		break;

	case 1401:
		prot = "goldleaf-licman";
		break;

	case 1402:
		prot = "prm-sm-np";
		break;

	case 1403:
		prot = "prm-nm-np";
		break;

	case 1404:
		prot = "igi-lm";
		break;

	case 1405:
		prot = "ibm-res";
		break;

	case 1406:
		prot = "netlabs-lm";
		break;

	case 1407:
		prot = "dbsa-lm";
		break;

	case 1408:
		prot = "sophia-lm";
		break;

	case 1409:
		prot = "here-lm";
		break;

	case 1410:
		prot = "hiq";
		break;

	case 1411:
		prot = "af";
		break;

	case 1412:
		prot = "innosys";
		break;

	case 1413:
		prot = "innosys-acl";
		break;

	case 1414:
		prot = "ibm-mqseries";
		break;

	case 1415:
		prot = "dbstar";
		break;

	case 1416:
		prot = "novell-lu6.2";
		break;

	case 1417:
		prot = "timbuktu-srv1";
		break;

	case 1418:
		prot = "timbuktu-srv2";
		break;

	case 1419:
		prot = "timbuktu-srv3";
		break;

	case 1420:
		prot = "timbuktu-srv4";
		break;

	case 1421:
		prot = "gandalf-lm";
		break;

	case 1422:
		prot = "autodesk-lm";
		break;

	case 1423:
		prot = "essbase";
		break;

	case 1424:
		prot = "hybrid";
		break;

	case 1425:
		prot = "zion-lm";
		break;

	case 1426:
		prot = "sais";
		break;

	case 1427:
		prot = "mloadd";
		break;

	case 1428:
		prot = "informatik-lm";
		break;

	case 1429:
		prot = "nms";
		break;

	case 1430:
		prot = "tpdu";
		break;

	case 1431:
		prot = "rgtp";
		break;

	case 1432:
		prot = "blueberry-lm";
		break;

	case 1433:
		prot = "ms-sql-s";
		break;

	case 1434:
		prot = "ms-sql-m";
		break;

	case 1435:
		prot = "ibm-cics";
		break;

	case 1436:
		prot = "saism";
		break;

	case 1437:
		prot = "tabula";
		break;

	case 1438:
		prot = "eicon-server";
		break;

	case 1439:
		prot = "eicon-x25";
		break;

	case 1440:
		prot = "eicon-slp";
		break;

	case 1441:
		prot = "cadis-1";
		break;

	case 1442:
		prot = "cadis-2";
		break;

	case 1443:
		prot = "ies-lm";
		break;

	case 1444:
		prot = "marcam-lm";
		break;

	case 1445:
		prot = "proxima-lm";
		break;

	case 1446:
		prot = "ora-lm";
		break;

	case 1447:
		prot = "apri-lm";
		break;

	case 1448:
		prot = "oc-lm";
		break;

	case 1449:
		prot = "peport";
		break;

	case 1450:
		prot = "dwf";
		break;

	case 1451:
		prot = "infoman";
		break;

	case 1452:
		prot = "gtegsc-lm";
		break;

	case 1453:
		prot = "genie-lm";
		break;

	case 1454:
		prot = "interhdl_elmd";
		break;

	case 1455:
		prot = "esl-lm";
		break;

	case 1456:
		prot = "dca";
		break;

	case 1457:
		prot = "valisys-lm";
		break;

	case 1458:
		prot = "nrcabq-lm";
		break;

	case 1459:
		prot = "proshare1";
		break;

	case 1460:
		prot = "proshare2";
		break;

	case 1461:
		prot = "ibm_wrless_lan";
		break;

	case 1462:
		prot = "world-lm";
		break;

	case 1463:
		prot = "nucleus";
		break;

	case 1464:
		prot = "msl_lmd";
		break;

	case 1465:
		prot = "pipes";
		break;

	case 1466:
		prot = "oceansoft-lm";
		break;

	case 1467:
		prot = "csdmbase";
		break;

	case 1468:
		prot = "csdm";
		break;

	case 1469:
		prot = "aal-lm";
		break;

	case 1470:
		prot = "uaiact";
		break;

	case 1471:
		prot = "csdmbase";
		break;

	case 1472:
		prot = "csdm";
		break;

	case 1473:
		prot = "openmath";
		break;

	case 1474:
		prot = "telefinder";
		break;

	case 1475:
		prot = "taligent-lm";
		break;

	case 1476:
		prot = "clvm-cfg";
		break;

	case 1477:
		prot = "ms-sna-server";
		break;

	case 1478:
		prot = "ms-sna-base";
		break;

	case 1479:
		prot = "dberegister";
		break;

	case 1480:
		prot = "pacerforum";
		break;

	case 1481:
		prot = "airs";
		break;

	case 1482:
		prot = "miteksys-lm";
		break;

	case 1483:
		prot = "afs";
		break;

	case 1484:
		prot = "confluent";
		break;

	case 1485:
		prot = "lansource";
		break;

	case 1486:
		prot = "nms_topo_serv";
		break;

	case 1487:
		prot = "localinfosrvr";
		break;

	case 1488:
		prot = "docstor";
		break;

	case 1489:
		prot = "dmdocbroker";
		break;

	case 1490:
		prot = "insitu-conf";
		break;

	case 1491:
		prot = "anynetgateway";
		break;

	case 1492:
		prot = "stone-design-1";
		break;

	case 1493:
		prot = "netmap_lm";
		break;

	case 1494:
		prot = "ica";
		break;

	case 1495:
		prot = "cvc";
		break;

	case 1496:
		prot = "liberty-lm";
		break;

	case 1497:
		prot = "rfx-lm";
		break;

	case 1498:
		prot = "sybase-sqlany";
		break;

	case 1499:
		prot = "fhc";
		break;

	case 1500:
		prot = "vlsi-lm";
		break;

	case 1501:
		prot = "saiscm";
		break;

	case 1502:
		prot = "shivadiscovery";
		break;

	case 1503:
		prot = "imtc-mcs";
		break;

	case 1504:
		prot = "evb-elm";
		break;

	case 1505:
		prot = "funkproxy";
		break;

	case 1506:
		prot = "utcd";
		break;

	case 1507:
		prot = "symplex";
		break;

	case 1508:
		prot = "diagmond";
		break;

	case 1509:
		prot = "robcad-lm";
		break;

	case 1510:
		prot = "mvx-lm";
		break;

	case 1511:
		prot = "3l-l1";
		break;

	case 1512:
		prot = "wins";
		break;

	case 1513:
		prot = "fujitsu-dtc";
		break;

	case 1514:
		prot = "fujitsu-dtcns";
		break;

	case 1515:
		prot = "ifor-protocol";
		break;

	case 1516:
		prot = "vpad";
		break;

	case 1517:
		prot = "vpac";
		break;

	case 1518:
		prot = "vpvd";
		break;

	case 1519:
		prot = "vpvc";
		break;

	case 1520:
		prot = "atm-zip-office";
		break;

	case 1521:
		prot = "ncube-lm";
		break;

	case 1522:
		prot = "ricardo-lm";
		break;

	case 1523:
		prot = "cichild-lm";
		break;

	case 1524:
		prot = "ingreslock";
		break;

	case 1525:
		prot = "orasrv";
		break;

	case 1526:
		prot = "pdap-np";
		break;

	case 1527:
		prot = "tlisrv";
		break;

	case 1528:
		prot = "mciautoreg";
		break;

	case 1529:
		prot = "coauthor";
		break;

	case 1530:
		prot = "rap-service";
		break;

	case 1531:
		prot = "rap-listen";
		break;

	case 1532:
		prot = "miroconnect";
		break;

	case 1533:
		prot = "virtual-places";
		break;

	case 1534:
		prot = "micromuse-lm";
		break;

	case 1535:
		prot = "ampr-info";
		break;

	case 1536:
		prot = "ampr-inter";
		break;

	case 1537:
		prot = "sdsc-lm";
		break;

	case 1538:
		prot = "3ds-lm";
		break;

	case 1539:
		prot = "intellistor-lm";
		break;

	case 1540:
		prot = "rds";
		break;

	case 1541:
		prot = "rds2";
		break;

	case 1542:
		prot = "gridgen-elmd";
		break;

	case 1543:
		prot = "simba-cs";
		break;

	case 1544:
		prot = "aspeclmd";
		break;

	case 1545:
		prot = "vistium-share";
		break;

	case 1546:
		prot = "abbaccuray";
		break;

	case 1547:
		prot = "laplink";
		break;

	case 1548:
		prot = "axon-lm";
		break;

	case 1549:
		prot = "shivahose Or shivasound";
		break;

	case 1550:
		prot = "3m-image-lm";
		break;

	case 1551:
		prot = "hecmtl-db";
		break;

	case 1552:
		prot = "pciarray";
		break;

	case 1553:
		prot = "sna-cs";
		break;

	case 1554:
		prot = "caci-lm";
		break;

	case 1555:
		prot = "livelan";
		break;

	case 1556:
		prot = "ashwin";
		break;

	case 1557:
		prot = "arbortext-lm";
		break;

	case 1558:
		prot = "xingmpeg";
		break;

	case 1559:
		prot = "web2host";
		break;

	case 1560:
		prot = "asci-val";
		break;

	case 1561:
		prot = "facilityview";
		break;

	case 1562:
		prot = "pconnectmgr";
		break;

	case 1563:
		prot = "cadabra-lm";
		break;

	case 1564:
		prot = "pay-per-view";
		break;

	case 1565:
		prot = "winddlb";
		break;

	case 1566:
		prot = "corelvideo";
		break;

	case 1567:
		prot = "jlicelmd";
		break;

	case 1568:
		prot = "tsspmap";
		break;

	case 1569:
		prot = "ets";
		break;

	case 1570:
		prot = "orbixd";
		break;

	case 1571:
		prot = "rdb-dbs-disp";
		break;

	case 1572:
		prot = "chip-lm";
		break;

	case 1573:
		prot = "itscomm-ns";
		break;

	case 1574:
		prot = "mvel-lm";
		break;

	case 1575:
		prot = "oraclenames";
		break;

	case 1576:
		prot = "moldflow-lm";
		break;

	case 1577:
		prot = "hypercube-lm";
		break;

	case 1578:
		prot = "jacobus-lm";
		break;

	case 1579:
		prot = "ioc-sea-lm";
		break;

	case 1580:
		prot = "tn-tl-r";
		break;

	case 1581:
		prot = "mil-2045-47001";
		break;

	case 1582:
		prot = "msims";
		break;

	case 1583:
		prot = "simbaexpress";
		break;

	case 1584:
		prot = "tn-tl-fd2";
		break;

	case 1585:
		prot = "intv";
		break;

	case 1586:
		prot = "ibm-abtact";
		break;

	case 1587:
		prot = "pra_elmd";
		break;

	case 1588:
		prot = "triquest-lm";
		break;

	case 1589:
		prot = "vqp";
		break;

	case 1590:
		prot = "gemini-lm";
		break;

	case 1591:
		prot = "ncpm-pm";
		break;

	case 1592:
		prot = "commonspace";
		break;

	case 1593:
		prot = "mainsoft-lm";
		break;

	case 1594:
		prot = "sixtrak";
		break;

	case 1595:
		prot = "radio";
		break;

	case 1596:
		prot = "radio-bc Or radio-sm";
		break;

	case 1597:
		prot = "orbplus-iiop";
		break;

	case 1598:
		prot = "picknfs";
		break;

	case 1599:
		prot = "simbaservices";
		break;

	case 1600:
		prot = "issd";
		break;

	case 1601:
		prot = "aas";
		break;

	case 1602:
		prot = "inspect";
		break;

	case 1603:
		prot = "picodbc";
		break;

	case 1604:
		prot = "icabrowser";
		break;

	case 1605:
		prot = "slp";
		break;

	case 1606:
		prot = "slm-api";
		break;

	case 1607:
		prot = "stt";
		break;

	case 1608:
		prot = "smart-lm";
		break;

	case 1609:
		prot = "isysg-lm";
		break;

	case 1610:
		prot = "taurus-wh";
		break;

	case 1611:
		prot = "ill";
		break;

	case 1612:
		prot = "netbill-trans";
		break;

	case 1613:
		prot = "netbill-keyrep";
		break;

	case 1614:
		prot = "netbill-cred";
		break;

	case 1615:
		prot = "netbill-auth";
		break;

	case 1616:
		prot = "netbill-prod";
		break;

	case 1617:
		prot = "nimrod-agent";
		break;

	case 1618:
		prot = "skytelnet";
		break;

	case 1619:
		prot = "xs-openstorage";
		break;

	case 1620:
		prot = "faxportwinport";
		break;

	case 1621:
		prot = "softdataphone";
		break;

	case 1622:
		prot = "ontime";
		break;

	case 1623:
		prot = "jaleosnd";
		break;

	case 1624:
		prot = "udp-sr-port";
		break;

	case 1625:
		prot = "svs-omagent";
		break;

	case 1626:
		prot = "shockwave";
		break;

	case 1627:
		prot = "t128-gateway";
		break;

	case 1628:
		prot = "lontalk-norm";
		break;

	case 1629:
		prot = "lontalk-urgnt";
		break;

	case 1630:
		prot = "oraclenet8cman";
		break;

	case 1631:
		prot = "visitview";
		break;

	case 1632:
		prot = "pammratc";
		break;

	case 1633:
		prot = "pammrpc";
		break;

	case 1634:
		prot = "loaprobe";
		break;

	case 1635:
		prot = "edb-server1";
		break;

	case 1636:
		prot = "cncp";
		break;

	case 1637:
		prot = "cnap";
		break;

	case 1638:
		prot = "cnip";
		break;

	case 1639:
		prot = "cert-initiator";
		break;

	case 1640:
		prot = "cert-responder";
		break;

	case 1641:
		prot = "invision";
		break;

	case 1642:
		prot = "isis-am";
		break;

	case 1643:
		prot = "isis-ambc";
		break;

	case 1644:
		prot = "saiseh";
		break;

	case 1645:
		prot = "sightline";
		break;

	case 1646:
		prot = "sa-msg-port";
		break;

	case 1647:
		prot = "rsap";
		break;

	case 1648:
		prot = "concurrent-lm";
		break;

	case 1649:
		prot = "kermit";
		break;

	case 1650:
		prot = "nkd";
		break;

	case 1651:
		prot = "shiva_confsrvr";
		break;

	case 1652:
		prot = "xnmp";
		break;

	case 1653:
		prot = "alphatech-lm";
		break;

	case 1654:
		prot = "stargatealerts";
		break;

	case 1655:
		prot = "dec-mbadmin";
		break;

	case 1656:
		prot = "dec-mbadmin-h";
		break;

	case 1657:
		prot = "fujitsu-mmpdc";
		break;

	case 1658:
		prot = "sixnetudr";
		break;

	case 1659:
		prot = "sg-lm";
		break;

	case 1660:
		prot = "skip-mc-gikreq";
		break;

	case 1661:
		prot = "netview-aix-1";
		break;

	case 1662:
		prot = "netview-aix-2";
		break;

	case 1663:
		prot = "netview-aix-3";
		break;

	case 1664:
		prot = "netview-aix-4";
		break;

	case 1665:
		prot = "netview-aix-5";
		break;

	case 1666:
		prot = "netview-aix-6";
		break;

	case 1667:
		prot = "netview-aix-7";
		break;

	case 1668:
		prot = "netview-aix-8";
		break;

	case 1669:
		prot = "netview-aix-9";
		break;

	case 1670:
		prot = "netview-aix-10";
		break;

	case 1671:
		prot = "netview-aix-11";
		break;

	case 1672:
		prot = "netview-aix-12";
		break;

	case 1673:
		prot = "proshare-mc-1";
		break;

	case 1674:
		prot = "proshare-mc-2";
		break;

	case 1675:
		prot = "pdp";
		break;

	case 1676:
		prot = "netcomm";
		break;

	case 1677:
		prot = "groupwise";
		break;

	case 1678:
		prot = "prolink";
		break;

	case 1679:
		prot = "darcorp-lm";
		break;

	case 1680:
		prot = "microcom-sbp";
		break;

	case 1681:
		prot = "sd-elmd";
		break;

	case 1682:
		prot = "lanyon-lantern";
		break;

	case 1683:
		prot = "ncpm-hip";
		break;

	case 1684:
		prot = "snaresecure";
		break;

	case 1685:
		prot = "n2nremote";
		break;

	case 1686:
		prot = "cvmon";
		break;

	case 1687:
		prot = "nsjtp-ctrl";
		break;

	case 1688:
		prot = "nsjtp-data";
		break;

	case 1689:
		prot = "firefox";
		break;

	case 1690:
		prot = "ng-umds";
		break;

	case 1691:
		prot = "empire-empuma";
		break;

	case 1692:
		prot = "sstsys-lm";
		break;

	case 1693:
		prot = "rrirtr";
		break;

	case 1694:
		prot = "rrimwm";
		break;

	case 1695:
		prot = "rrilwm";
		break;

	case 1696:
		prot = "rrifmm";
		break;

	case 1697:
		prot = "rrisat";
		break;

	case 1698:
		prot = "rsvp-encap-1";
		break;

	case 1699:
		prot = "rsvp-encap-2";
		break;

	case 1700:
		prot = "mps-raft";
		break;

	case 1701:
		prot = "l2f";
		break;

	case 1702:
		prot = "deskshare";
		break;

	case 1703:
		prot = "hb-engine";
		break;

	case 1704:
		prot = "bcs-broker";
		break;

	case 1705:
		prot = "slingshot";
		break;

	case 1706:
		prot = "jetform";
		break;

	case 1707:
		prot = "vdmplay";
		break;

	case 1708:
		prot = "gat-lmd";
		break;

	case 1709:
		prot = "centra";
		break;

	case 1710:
		prot = "impera";
		break;

	case 1711:
		prot = "pptconference";
		break;

	case 1712:
		prot = "registrar";
		break;

	case 1713:
		prot = "conferencetalk";
		break;

	case 1714:
		prot = "sesi-lm";
		break;

	case 1715:
		prot = "houdini-lm";
		break;

	case 1716:
		prot = "xmsg";
		break;

	case 1717:
		prot = "fj-hdnet";
		break;

	case 1718:
		prot = "h323gatedisc";
		break;

	case 1719:
		prot = "h323gatestat";
		break;

	case 1720:
		prot = "h323hostcall";
		break;

	case 1721:
		prot = "caicci";
		break;

	case 1722:
		prot = "hks-lm";
		break;

	case 1723:
		prot = "pptp";
		break;

	case 1724:
		prot = "csbphonemaster";
		break;

	case 1725:
		prot = "iden-ralp";
		break;

	case 1726:
		prot = "iberiagames";
		break;

	case 1727:
		prot = "winddx";
		break;

	case 1728:
		prot = "telindus";
		break;

	case 1729:
		prot = "citynl";
		break;

	case 1730:
		prot = "roketz";
		break;

	case 1731:
		prot = "msiccp";
		break;

	case 1732:
		prot = "proxim";
		break;

	case 1733:
		prot = "siipat";
		break;

	case 1734:
		prot = "cambertx-lm";
		break;

	case 1735:
		prot = "privatechat";
		break;

	case 1736:
		prot = "street-stream";
		break;

	case 1737:
		prot = "ultimad";
		break;

	case 1738:
		prot = "gamegen1";
		break;

	case 1739:
		prot = "webaccess";
		break;

	case 1740:
		prot = "encore";
		break;

	case 1741:
		prot = "cisco-net-mgmt";
		break;

	case 1742:
		prot = "3Com-nsd";
		break;

	case 1743:
		prot = "cinegrfx-lm";
		break;

	case 1744:
		prot = "ncpm-ft";
		break;

	case 1745:
		prot = "remote-winsock";
		break;

	case 1746:
		prot = "ftrapid-1";
		break;

	case 1747:
		prot = "ftrapid-2";
		break;

	case 1748:
		prot = "oracle-em1";
		break;

	case 1749:
		prot = "aspen-services";
		break;

	case 1750:
		prot = "sslp";
		break;

	case 1751:
		prot = "swiftnet";
		break;

	case 1752:
		prot = "lofr-lm";
		break;

	case 1753:
		prot = "translogic-lm";
		break;

	case 1754:
		prot = "oracle-em2";
		break;

	case 1755:
		prot = "ms-streaming";
		break;

	case 1756:
		prot = "capfast-lmd";
		break;

	case 1757:
		prot = "cnhrp";
		break;

	case 1758:
		prot = "tftp-mcast";
		break;

	case 1759:
		prot = "spss-lm";
		break;

	case 1760:
		prot = "www-ldap-gw";
		break;

	case 1761:
		prot = "cft-0";
		break;

	case 1762:
		prot = "cft-1";
		break;

	case 1763:
		prot = "cft-2";
		break;

	case 1764:
		prot = "cft-3";
		break;

	case 1765:
		prot = "cft-4";
		break;

	case 1766:
		prot = "cft-5";
		break;

	case 1767:
		prot = "cft-6";
		break;

	case 1768:
		prot = "cft-7";
		break;

	case 1769:
		prot = "bmc-net-adm";
		break;

	case 1770:
		prot = "bmc-net-svc";
		break;

	case 1771:
		prot = "vaultbase";
		break;

	case 1772:
		prot = "essweb-gw";
		break;

	case 1773:
		prot = "kmscontrol";
		break;

	case 1774:
		prot = "global-dtserv";
		break;

	case 1775:
		prot = "MMS - video streaming";
		break;

	case 1776:
		prot = "femis";
		break;

	case 1777:
		prot = "powerguardian";
		break;

	case 1778:
		prot = "prodigy-intrnet";
		break;

	case 1779:
		prot = "pharmasoft";
		break;

	case 1780:
		prot = "dpkeyserv";
		break;

	case 1781:
		prot = "answersoft-lm";
		break;

	case 1782:
		prot = "hp-hcip";
		break;

	case 1784:
		prot = "finle-lm";
		break;

	case 1785:
		prot = "windlm";
		break;

	case 1786:
		prot = "funk-logger";
		break;

	case 1787:
		prot = "funk-license";
		break;

	case 1788:
		prot = "psmond";
		break;

	case 1789:
		prot = "hello";
		break;

	case 1790:
		prot = "nmsp";
		break;

	case 1791:
		prot = "ea1";
		break;

	case 1792:
		prot = "ibm-dt-2";
		break;

	case 1793:
		prot = "rsc-robot";
		break;

	case 1794:
		prot = "cera-bcm";
		break;

	case 1795:
		prot = "dpi-proxy";
		break;

	case 1796:
		prot = "vocaltec-admin";
		break;

	case 1797:
		prot = "uma";
		break;

	case 1798:
		prot = "etp";
		break;

	case 1799:
		prot = "netrisk";
		break;

	case 1800:
		prot = "ansys-lm";
		break;

	case 1801:
		prot = "msmq";
		break;

	case 1802:
		prot = "concomp1";
		break;

	case 1803:
		prot = "hp-hcip-gwy";
		break;

	case 1804:
		prot = "enl";
		break;

	case 1805:
		prot = "enl-name";
		break;

	case 1806:
		prot = "musiconline";
		break;

	case 1807:
		prot = "fhsp";
		break;

	case 1808:
		prot = "oracle-vp2";
		break;

	case 1809:
		prot = "oracle-vp1";
		break;

	case 1810:
		prot = "jerand-lm";
		break;

	case 1811:
		prot = "scientia-sdb";
		break;

	case 1812:
		prot = "radius";
		break;

	case 1813:
		prot = "radius-acct";
		break;

	case 1814:
		prot = "tdp-suite";
		break;

	case 1815:
		prot = "mmpft";
		break;

	case 1816:
		prot = "harp";
		break;

	case 1817:
		prot = "rkb-oscs";
		break;

	case 1818:
		prot = "etftp";
		break;

	case 1819:
		prot = "plato-lm";
		break;

	case 1820:
		prot = "mcagent";
		break;

	case 1821:
		prot = "donnyworld";
		break;

	case 1822:
		prot = "es-elmd";
		break;

	case 1823:
		prot = "unisys-lm";
		break;

	case 1824:
		prot = "metrics-pas";
		break;

	case 1825:
		prot = "direcpc-video";
		break;

	case 1826:
		prot = "ardt";
		break;

	case 1827:
		prot = "asi";
		break;

	case 1828:
		prot = "itm-mcell-u";
		break;

	case 1829:
		prot = "optika-emedia";
		break;

	case 1830:
		prot = "net8-cman";
		break;

	case 1831:
		prot = "myrtle";
		break;

	case 1832:
		prot = "tht-treasure";
		break;

	case 1833:
		prot = "udpradio";
		break;

	case 1834:
		prot = "ardusuni";
		break;

	case 1835:
		prot = "ardusmul";
		break;

	case 1836:
		prot = "ste-smsc";
		break;

	case 1837:
		prot = "csoft1";
		break;

	case 1838:
		prot = "talnet";
		break;

	case 1839:
		prot = "netopia-vo1";
		break;

	case 1840:
		prot = "netopia-vo2";
		break;

	case 1841:
		prot = "netopia-vo3";
		break;

	case 1842:
		prot = "netopia-vo4";
		break;

	case 1843:
		prot = "netopia-vo5";
		break;

	case 1844:
		prot = "direcpc-dll";
		break;

	case 1845:
		prot = "altalink";
		break;

	case 1846:
		prot = "tunstall-pnc";
		break;

	case 1847:
		prot = "slp-notify";
		break;

	case 1848:
		prot = "fjdocdist";
		break;

	case 1849:
		prot = "alpha-sms";
		break;

	case 1850:
		prot = "gsi";
		break;

	case 1851:
		prot = "ctcd";
		break;

	case 1852:
		prot = "virtual-time";
		break;

	case 1853:
		prot = "vids-avtp";
		break;

	case 1854:
		prot = "buddy-draw";
		break;

	case 1855:
		prot = "fiorano-rtrsvc";
		break;

	case 1856:
		prot = "fiorano-msgsvc";
		break;

	case 1857:
		prot = "datacaptor";
		break;

	case 1858:
		prot = "privateark";
		break;

	case 1859:
		prot = "gammafetchsvr";
		break;

	case 1860:
		prot = "sunscalar-svc";
		break;

	case 1861:
		prot = "lecroy-vicp";
		break;

	case 1862:
		prot = "techra-server";
		break;

	case 1863:
		prot = "msnp";
		break;

	case 1864:
		prot = "paradym-31port";
		break;

	case 1865:
		prot = "entp";
		break;

	case 1866:
		prot = "swrmi";
		break;

	case 1867:
		prot = "udrive";
		break;

	case 1868:
		prot = "viziblebrowser";
		break;

	case 1869:
		prot = "yestrader";
		break;

	case 1870:
		prot = "sunscalar-dns";
		break;

	case 1871:
		prot = "canocentral0";
		break;

	case 1872:
		prot = "canocentral1";
		break;

	case 1873:
		prot = "fjmpjps";
		break;

	case 1874:
		prot = "fjswapsnp";
		break;

	case 1875:
		prot = "westell-stats";
		break;

	case 1876:
		prot = "ewcappsrv";
		break;

	case 1877:
		prot = "hp-webqosdb";
		break;

	case 1878:
		prot = "drmsmc";
		break;

	case 1879:
		prot = "nettgain-nms";
		break;

	case 1880:
		prot = "vsat-control";
		break;

	case 1881:
		prot = "ibm-mqseries2";
		break;

	case 1882:
		prot = "ecsqdmn";
		break;

	case 1883:
		prot = "ibm-mqisdp";
		break;

	case 1884:
		prot = "idmaps";
		break;

	case 1885:
		prot = "vrtstrapserver";
		break;

	case 1886:
		prot = "leoip";
		break;

	case 1887:
		prot = "filex-lport";
		break;

	case 1888:
		prot = "ncconfig";
		break;

	case 1889:
		prot = "unify-adapter";
		break;

	case 1890:
		prot = "wilkenlistener";
		break;

	case 1891:
		prot = "childkey-notif";
		break;

	case 1892:
		prot = "childkey-ctrl";
		break;

	case 1893:
		prot = "elad";
		break;

	case 1894:
		prot = "o2server-port";
		break;

	case 1896:
		prot = "b-novative-ls";
		break;

	case 1897:
		prot = "metaagent";
		break;

	case 1898:
		prot = "cymtec-port";
		break;

	case 1899:
		prot = "mc2studios";
		break;

	case 1900:
		prot = "ssdp";
		break;

	case 1901:
		prot = "fjicl-tep-a";
		break;

	case 1902:
		prot = "fjicl-tep-b";
		break;

	case 1903:
		prot = "linkname";
		break;

	case 1904:
		prot = "fjicl-tep-c";
		break;

	case 1905:
		prot = "sugp";
		break;

	case 1906:
		prot = "tpmd";
		break;

	case 1907:
		prot = "intrastar";
		break;

	case 1908:
		prot = "dawn";
		break;

	case 1909:
		prot = "global-wlink";
		break;

	case 1910:
		prot = "ultrabac";
		break;

	case 1911:
		prot = "mtp";
		break;

	case 1912:
		prot = "rhp-iibp";
		break;

	case 1913:
		prot = "armadp";
		break;

	case 1914:
		prot = "elm-momentum";
		break;

	case 1915:
		prot = "facelink";
		break;

	case 1916:
		prot = "persona";
		break;

	case 1917:
		prot = "noagent";
		break;

	case 1918:
		prot = "can-nds";
		break;

	case 1919:
		prot = "can-dch";
		break;

	case 1920:
		prot = "can-ferret";
		break;

	case 1921:
		prot = "noadmin";
		break;

	case 1922:
		prot = "tapestry";
		break;

	case 1923:
		prot = "spice";
		break;

	case 1924:
		prot = "xiip";
		break;

	case 1925:
		prot = "discovery-port";
		break;

	case 1926:
		prot = "egs";
		break;

	case 1927:
		prot = "videte-cipc";
		break;

	case 1928:
		prot = "emsd-port";
		break;

	case 1929:
		prot = "bandwiz-system";
		break;

	case 1930:
		prot = "driveappserver";
		break;

	case 1931:
		prot = "amdsched";
		break;

	case 1932:
		prot = "ctt-broker";
		break;

	case 1933:
		prot = "xmapi";
		break;

	case 1934:
		prot = "xaapi";
		break;

	case 1935:
		prot = "macromedia-fcs";
		break;

	case 1936:
		prot = "jetcmeserver";
		break;

	case 1937:
		prot = "jwserver";
		break;

	case 1938:
		prot = "jwclient";
		break;

	case 1939:
		prot = "jvserver";
		break;

	case 1940:
		prot = "jvclient";
		break;

	case 1941:
		prot = "dic-aida";
		break;

	case 1942:
		prot = "res";
		break;

	case 1943:
		prot = "beeyond-media";
		break;

	case 1944:
		prot = "close-combat";
		break;

	case 1945:
		prot = "dialogic-elmd";
		break;

	case 1946:
		prot = "tekpls";
		break;

	case 1947:
		prot = "hlserver";
		break;

	case 1948:
		prot = "eye2eye";
		break;

	case 1949:
		prot = "ismaeasdaqlive";
		break;

	case 1950:
		prot = "ismaeasdaqtest";
		break;

	case 1951:
		prot = "bcs-lmserver";
		break;

	case 1952:
		prot = "mpnjsc";
		break;

	case 1953:
		prot = "rapidbase";
		break;

	case 1954:
		prot = "abr-basic";
		break;

	case 1955:
		prot = "abr-secure";
		break;

	case 1956:
		prot = "vrtl-vmf-ds";
		break;

	case 1957:
		prot = "unix-status";
		break;

	case 1958:
		prot = "dxadmind";
		break;

	case 1959:
		prot = "simp-all";
		break;

	case 1960:
		prot = "nasmanager";
		break;

	case 1961:
		prot = "bts-appserver";
		break;

	case 1962:
		prot = "biap-mp";
		break;

	case 1963:
		prot = "webmachine";
		break;

	case 1964:
		prot = "solid-e-engine";
		break;

	case 1965:
		prot = "tivoli-npm";
		break;

	case 1966:
		prot = "slush";
		break;

	case 1967:
		prot = "sns-quote";
		break;

	case 1968:
		prot = "lipsinc";
		break;

	case 1969:
		prot = "lipsinc1";
		break;

	case 1970:
		prot = "netop-rc";
		break;

	case 1971:
		prot = "netop-school";
		break;

	case 1972:
		prot = "intersys-cache";
		break;

	case 1973:
		prot = "dlsrap";
		break;

	case 1974:
		prot = "drp";
		break;

	case 1975:
		prot = "tcoflashagent";
		break;

	case 1976:
		prot = "tcoregagent";
		break;

	case 1977:
		prot = "tcoaddressbook";
		break;

	case 1978:
		prot = "unisql";
		break;

	case 1979:
		prot = "unisql-java";
		break;

	case 1980:
		prot = "pearldoc-xact";
		break;

	case 1981:
		prot = "p2pq";
		break;

	case 1982:
		prot = "estamp";
		break;

	case 1983:
		prot = "lhtp";
		break;

	case 1984:
		prot = "bb";
		break;

	case 1985:
		prot = "hsrp";
		break;

	case 1986:
		prot = "licensedaemon";
		break;

	case 1987:
		prot = "tr-rsrb-p1";
		break;

	case 1988:
		prot = "tr-rsrb-p2";
		break;

	case 1989:
		prot = "mshnet Or tr-rsrb-p3";
		break;

	case 1990:
		prot = "stun-p1";
		break;

	case 1991:
		prot = "stun-p2";
		break;

	case 1992:
		prot = "ipsendmsg Or stun-p3";
		break;

	case 1993:
		prot = "snmp-tcp-port";
		break;

	case 1994:
		prot = "stun-port";
		break;

	case 1995:
		prot = "perf-port";
		break;

	case 1996:
		prot = "tr-rsrb-port";
		break;

	case 1997:
		prot = "gdp-port";
		break;

	case 1998:
		prot = "x25-svc-port";
		break;

	case 1999:
		prot = "tcp-id-port";
		break;

	case 2000:
		prot = "callbook";
		break;

	case 2001:
		prot = "dc Or wizard";
		break;

	case 2002:
		prot = "globe";
		break;

	case 2004:
		prot = "emce Or mailbox";
		break;

	case 2005:
		prot = "berknet Or oracle";
		break;

	case 2006:
		prot = "invokator Or raid-cc";
		break;

	case 2007:
		prot = "dectalk Or raid-am";
		break;

	case 2008:
		prot = "conf Or terminaldb";
		break;

	case 2009:
		prot = "news Or whosockami";
		break;

	case 2010:
		prot = "pipe_server Or search";
		break;

	case 2011:
		prot = "raid-cc Or servserv";
		break;

	case 2012:
		prot = "raid-ac Or ttyinfo";
		break;

	case 2013:
		prot = "raid-am Or raid-cd";
		break;

	case 2014:
		prot = "raid-sf Or troff";
		break;

	case 2015:
		prot = "cypress Or raid-cs";
		break;

	case 2016:
		prot = "bootserver";
		break;

	case 2017:
		prot = "bootclient Or cypress-stat";
		break;

	case 2018:
		prot = "rellpack Or terminaldb";
		break;

	case 2019:
		prot = "about Or whosockami";
		break;

	case 2020:
		prot = "xinupageserver";
		break;

	case 2021:
		prot = "servexec Or xinuexpansion1";
		break;

	case 2022:
		prot = "down Or xinuexpansion2";
		break;

	case 2023:
		prot = "xinuexpansion3";
		break;

	case 2024:
		prot = "xinuexpansion4";
		break;

	case 2025:
		prot = "ellpack Or xribs";
		break;

	case 2026:
		prot = "scrabble";
		break;

	case 2027:
		prot = "shadowserver";
		break;

	case 2028:
		prot = "submitserver";
		break;

	case 2029:
		prot = "hsrpv6";
		break;

	case 2030:
		prot = "device2";
		break;

	case 2031:
		prot = "mobrien-chat";
		break;

	case 2032:
		prot = "blackboard";
		break;

	case 2033:
		prot = "glogger";
		break;

	case 2034:
		prot = "scoremgr";
		break;

	case 2035:
		prot = "imsldoc";
		break;

	case 2036:
		prot = "e-dpnet";
		break;

	case 2037:
		prot = "p2plus";
		break;

	case 2038:
		prot = "objectmanager";
		break;

	case 2039:
		prot = "prizma";
		break;

	case 2040:
		prot = "lam";
		break;

	case 2041:
		prot = "interbase";
		break;

	case 2042:
		prot = "isis";
		break;

	case 2043:
		prot = "isis-bcast";
		break;

	case 2044:
		prot = "rimsl";
		break;

	case 2045:
		prot = "cdfunc";
		break;

	case 2046:
		prot = "sdfunc";
		break;

	case 2047:
		prot = "dls";
		break;

	case 2048:
		prot = "dls-monitor";
		break;

	case 2049:
		prot = "shilp Or nfsd";
		break;

	case 2050:
		prot = "av-emb-config";
		break;

	case 2051:
		prot = "epnsdp";
		break;

	case 2052:
		prot = "clearvisn";
		break;

	case 2053:
		prot = "lot105-ds-upd";
		break;

	case 2054:
		prot = "weblogin";
		break;

	case 2055:
		prot = "iop";
		break;

	case 2056:
		prot = "omnisky";
		break;

	case 2057:
		prot = "rich-cp";
		break;

	case 2058:
		prot = "newwavesearch";
		break;

	case 2059:
		prot = "bmc-messaging";
		break;

	case 2060:
		prot = "teleniumdaemon";
		break;

	case 2061:
		prot = "netmount";
		break;

	case 2062:
		prot = "icg-swp";
		break;

	case 2063:
		prot = "icg-bridge";
		break;

	case 2064:
		prot = "icg-iprelay";
		break;

	case 2065:
		prot = "dlsrpn";
		break;

	case 2066:
		prot = "aura";
		break;

	case 2067:
		prot = "dlswpn";
		break;

	case 2068:
		prot = "avauthsrvprtcl";
		break;

	case 2069:
		prot = "event-port";
		break;

	case 2070:
		prot = "ah-esp-encap";
		break;

	case 2071:
		prot = "acp-port";
		break;

	case 2072:
		prot = "msync";
		break;

	case 2073:
		prot = "gxs-data-port";
		break;

	case 2074:
		prot = "vrtl-vmf-sa";
		break;

	case 2075:
		prot = "newlixengine";
		break;

	case 2076:
		prot = "newlixconfig";
		break;

	case 2077:
		prot = "trellisagt";
		break;

	case 2078:
		prot = "trellissvr";
		break;

	case 2079:
		prot = "idware-router";
		break;

	case 2080:
		prot = "autodesk-nlm";
		break;

	case 2081:
		prot = "kme-trap-port";
		break;

	case 2082:
		prot = "infowave";
		break;

	case 2083:
		prot = "radsec";
		break;

	case 2084:
		prot = "sunclustergeo";
		break;

	case 2085:
		prot = "ada-cip";
		break;

	case 2086:
		prot = "gnunet";
		break;

	case 2087:
		prot = "eli";
		break;

	case 2088:
		prot = "ip-blf";
		break;

	case 2089:
		prot = "sep";
		break;

	case 2090:
		prot = "lrp";
		break;

	case 2091:
		prot = "prp";
		break;

	case 2092:
		prot = "descent3";
		break;

	case 2093:
		prot = "nbx-cc";
		break;

	case 2094:
		prot = "nbx-au";
		break;

	case 2095:
		prot = "nbx-ser";
		break;

	case 2096:
		prot = "nbx-dir";
		break;

	case 2097:
		prot = "jetformpreview";
		break;

	case 2098:
		prot = "dialog-port";
		break;

	case 2099:
		prot = "h2250-annex-g";
		break;

	case 2100:
		prot = "amiganetfs";
		break;

	case 2101:
		prot = "rtcm-sc104";
		break;

	case 2102:
		prot = "zephyr-srv";
		break;

	case 2103:
		prot = "zephyr-clt";
		break;

	case 2104:
		prot = "zephyr-hm";
		break;

	case 2105:
		prot = "minipay";
		break;

	case 2106:
		prot = "mzap";
		break;

	case 2107:
		prot = "bintec-admin";
		break;

	case 2108:
		prot = "comcam";
		break;

	case 2109:
		prot = "ergolight";
		break;

	case 2110:
		prot = "umsp";
		break;

	case 2111:
		prot = "dsatp";
		break;

	case 2112:
		prot = "idonix-metanet";
		break;

	case 2113:
		prot = "hsl-storm";
		break;

	case 2114:
		prot = "newheights";
		break;

	case 2115:
		prot = "kdm";
		break;

	case 2116:
		prot = "ccowcmr";
		break;

	case 2117:
		prot = "mentaclient";
		break;

	case 2118:
		prot = "mentaserver";
		break;

	case 2119:
		prot = "gsigatekeeper";
		break;

	case 2120:
		prot = "qencp";
		break;

	case 2121:
		prot = "scientia-ssdb";
		break;

	case 2122:
		prot = "caupc-remote";
		break;

	case 2123:
		prot = "gtp-control";
		break;

	case 2124:
		prot = "elatelink";
		break;

	case 2125:
		prot = "lockstep";
		break;

	case 2126:
		prot = "pktcable-cops";
		break;

	case 2127:
		prot = "index-pc-wb";
		break;

	case 2128:
		prot = "net-steward";
		break;

	case 2129:
		prot = "cs-live";
		break;

	case 2130:
		prot = "swc-xds";
		break;

	case 2131:
		prot = "avantageb2b";
		break;

	case 2132:
		prot = "avail-epmap";
		break;

	case 2133:
		prot = "zymed-zpp";
		break;

	case 2134:
		prot = "avenue";
		break;

	case 2135:
		prot = "gris";
		break;

	case 2136:
		prot = "appworxsrv";
		break;

	case 2137:
		prot = "connect";
		break;

	case 2138:
		prot = "unbind-cluster";
		break;

	case 2139:
		prot = "ias-auth";
		break;

	case 2140:
		prot = "ias-reg";
		break;

	case 2141:
		prot = "ias-admind";
		break;

	case 2142:
		prot = "tdm-over-ip";
		break;

	case 2143:
		prot = "lv-jc";
		break;

	case 2144:
		prot = "lv-ffx";
		break;

	case 2145:
		prot = "lv-pici";
		break;

	case 2146:
		prot = "lv-not";
		break;

	case 2147:
		prot = "lv-auth";
		break;

	case 2148:
		prot = "veritas-ucl";
		break;

	case 2149:
		prot = "acptsys";
		break;

	case 2150:
		prot = "dynamic3d";
		break;

	case 2151:
		prot = "docent";
		break;

	case 2152:
		prot = "gtp-user";
		break;

	case 2159:
		prot = "gdbremote";
		break;

	case 2160:
		prot = "apc-2160";
		break;

	case 2161:
		prot = "apc-2161";
		break;

	case 2162:
		prot = "navisphere";
		break;

	case 2163:
		prot = "navisphere-sec";
		break;

	case 2164:
		prot = "ddns-v3";
		break;

	case 2165:
		prot = "x-bone-api";
		break;

	case 2166:
		prot = "iwserver";
		break;

	case 2167:
		prot = "raw-serial";
		break;

	case 2168:
		prot = "easy-soft-mux";
		break;

	case 2169:
		prot = "brain";
		break;

	case 2170:
		prot = "eyetv";
		break;

	case 2171:
		prot = "msfw-storage";
		break;

	case 2172:
		prot = "msfw-s-storage";
		break;

	case 2173:
		prot = "msfw-replica";
		break;

	case 2174:
		prot = "msfw-array";
		break;

	case 2175:
		prot = "airsync";
		break;

	case 2176:
		prot = "rapi";
		break;

	case 2177:
		prot = "qwave";
		break;

	case 2178:
		prot = "bitspeer";
		break;

	case 2180:
		prot = "mc-gt-srv";
		break;

	case 2181:
		prot = "eforward";
		break;

	case 2182:
		prot = "cgn-stat";
		break;

	case 2183:
		prot = "cgn-config";
		break;

	case 2184:
		prot = "nvd";
		break;

	case 2185:
		prot = "onbase-dds";
		break;

	case 2190:
		prot = "tivoconnect";
		break;

	case 2191:
		prot = "tvbus";
		break;

	case 2192:
		prot = "asdis";
		break;

	case 2197:
		prot = "mnp-exchange";
		break;

	case 2198:
		prot = "onehome-remote";
		break;

	case 2199:
		prot = "onehome-help";
		break;

	case 2200:
		prot = "ici";
		break;

	case 2201:
		prot = "ats";
		break;

	case 2202:
		prot = "imtc-map";
		break;

	case 2203:
		prot = "b2-runtime";
		break;

	case 2204:
		prot = "b2-license";
		break;

	case 2205:
		prot = "jps";
		break;

	case 2206:
		prot = "hpocbus";
		break;

	case 2207:
		prot = "hpssd";
		break;

	case 2208:
		prot = "hpiod";
		break;

	case 2213:
		prot = "kali";
		break;

	case 2214:
		prot = "rpi";
		break;

	case 2215:
		prot = "ipcore";
		break;

	case 2216:
		prot = "vtu-comms";
		break;

	case 2217:
		prot = "gotodevice";
		break;

	case 2218:
		prot = "bounzza";
		break;

	case 2219:
		prot = "netiq-ncap";
		break;

	case 2220:
		prot = "netiq";
		break;

	case 2221:
		prot = "rockwell-csp1";
		break;

	case 2222:
		prot = "rockwell-csp2";
		break;

	case 2223:
		prot = "rockwell-csp3";
		break;

	case 2224:
		prot = "efi-mg";
		break;

	case 2225:
		prot = "rcip-itu";
		break;

	case 2226:
		prot = "di-drm";
		break;

	case 2227:
		prot = "di-msg";
		break;

	case 2228:
		prot = "ehome-ms";
		break;

	case 2229:
		prot = "datalens";
		break;

	case 2230:
		prot = "queueadm";
		break;

	case 2231:
		prot = "wimaxasncp";
		break;

	case 2232:
		prot = "ivs-video";
		break;

	case 2233:
		prot = "infocrypt";
		break;

	case 2234:
		prot = "directplay";
		break;

	case 2235:
		prot = "sercomm-wlink";
		break;

	case 2236:
		prot = "nani";
		break;

	case 2237:
		prot = "optech-port1-lm";
		break;

	case 2238:
		prot = "aviva-sna";
		break;

	case 2239:
		prot = "imagequery";
		break;

	case 2240:
		prot = "recipe";
		break;

	case 2241:
		prot = "ivsd";
		break;

	case 2242:
		prot = "foliocorp";
		break;

	case 2243:
		prot = "magicom";
		break;

	case 2244:
		prot = "nmsserver";
		break;

	case 2245:
		prot = "hao";
		break;

	case 2246:
		prot = "pc-mta-addrmap";
		break;

	case 2247:
		prot = "antidotemgrsvr";
		break;

	case 2248:
		prot = "ums";
		break;

	case 2249:
		prot = "rfmp";
		break;

	case 2250:
		prot = "remote-collab";
		break;

	case 2251:
		prot = "dif-port";
		break;

	case 2252:
		prot = "njenet-ssl";
		break;

	case 2253:
		prot = "dtv-chan-req";
		break;

	case 2254:
		prot = "seispoc";
		break;

	case 2255:
		prot = "vrtp";
		break;

	case 2256:
		prot = "pcc-mfp";
		break;

	case 2257:
		prot = "simple-tx-rx";
		break;

	case 2258:
		prot = "rcts";
		break;

	case 2259:
		prot = "acd-pm";
		break;

	case 2260:
		prot = "apc-2260";
		break;

	case 2261:
		prot = "comotionmaster";
		break;

	case 2262:
		prot = "comotionback";
		break;

	case 2263:
		prot = "ecwcfg";
		break;

	case 2264:
		prot = "apx500api-1";
		break;

	case 2265:
		prot = "apx500api-2";
		break;

	case 2266:
		prot = "mfserver";
		break;

	case 2267:
		prot = "ontobroker";
		break;

	case 2268:
		prot = "amt";
		break;

	case 2269:
		prot = "mikey";
		break;

	case 2270:
		prot = "starschool";
		break;

	case 2271:
		prot = "mmcals";
		break;

	case 2272:
		prot = "mmcal";
		break;

	case 2273:
		prot = "mysql-im";
		break;

	case 2274:
		prot = "pcttunnell";
		break;

	case 2275:
		prot = "ibridge-data";
		break;

	case 2276:
		prot = "ibridge-mgmt";
		break;

	case 2277:
		prot = "bluectrlproxy";
		break;

	case 2278:
		prot = "s3db";
		break;

	case 2279:
		prot = "xmquery";
		break;

	case 2280:
		prot = "lnvpoller";
		break;

	case 2281:
		prot = "lnvconsole";
		break;

	case 2282:
		prot = "lnvalarm";
		break;

	case 2283:
		prot = "lnvstatus";
		break;

	case 2284:
		prot = "lnvmaps";
		break;

	case 2285:
		prot = "lnvmailmon";
		break;

	case 2286:
		prot = "nas-metering";
		break;

	case 2287:
		prot = "dna";
		break;

	case 2288:
		prot = "netml";
		break;

	case 2289:
		prot = "dict-lookup";
		break;

	case 2290:
		prot = "sonus-logging";
		break;

	case 2291:
		prot = "eapsp";
		break;

	case 2292:
		prot = "mib-streaming";
		break;

	case 2293:
		prot = "npdbgmngr";
		break;

	case 2294:
		prot = "konshus-lm";
		break;

	case 2295:
		prot = "advant-lm";
		break;

	case 2296:
		prot = "theta-lm";
		break;

	case 2297:
		prot = "d2k-datamover1";
		break;

	case 2298:
		prot = "d2k-datamover2";
		break;

	case 2299:
		prot = "pc-telecommute";
		break;

	case 2300:
		prot = "cvmmon";
		break;

	case 2301:
		prot = "cpq-wbem";
		break;

	case 2302:
		prot = "binderysupport";
		break;

	case 2303:
		prot = "proxy-gateway";
		break;

	case 2304:
		prot = "attachmate-uts";
		break;

	case 2305:
		prot = "mt-scaleserver";
		break;

	case 2306:
		prot = "tappi-boxnet";
		break;

	case 2307:
		prot = "pehelp";
		break;

	case 2308:
		prot = "sdhelp";
		break;

	case 2309:
		prot = "sdserver";
		break;

	case 2310:
		prot = "sdclient";
		break;

	case 2311:
		prot = "messageservice";
		break;

	case 2312:
		prot = "wanscaler";
		break;

	case 2313:
		prot = "iapp";
		break;

	case 2314:
		prot = "cr-websystems";
		break;

	case 2315:
		prot = "precise-sft";
		break;

	case 2316:
		prot = "sent-lm";
		break;

	case 2317:
		prot = "attachmate-g32";
		break;

	case 2318:
		prot = "cadencecontrol";
		break;

	case 2319:
		prot = "infolibria";
		break;

	case 2320:
		prot = "siebel-ns";
		break;

	case 2321:
		prot = "rdlap";
		break;

	case 2322:
		prot = "ofsd";
		break;

	case 2323:
		prot = "3d-nfsd";
		break;

	case 2324:
		prot = "cosmocall";
		break;

	case 2325:
		prot = "designspace-lm";
		break;

	case 2326:
		prot = "idcp";
		break;

	case 2327:
		prot = "xingcsm";
		break;

	case 2328:
		prot = "netrix-sftm";
		break;

	case 2329:
		prot = "nvd";
		break;

	case 2330:
		prot = "tscchat";
		break;

	case 2331:
		prot = "agentview";
		break;

	case 2332:
		prot = "rcc-host";
		break;

	case 2333:
		prot = "snapp";
		break;

	case 2334:
		prot = "ace-client";
		break;

	case 2335:
		prot = "ace-proxy";
		break;

	case 2336:
		prot = "appleugcontrol";
		break;

	case 2337:
		prot = "ideesrv";
		break;

	case 2338:
		prot = "norton-lambert";
		break;

	case 2339:
		prot = "3com-webview";
		break;

	case 2340:
		prot = "wrs_registry";
		break;

	case 2341:
		prot = "xiostatus";
		break;

	case 2342:
		prot = "manage-exec";
		break;

	case 2343:
		prot = "nati-logos";
		break;

	case 2344:
		prot = "fcmsys";
		break;

	case 2345:
		prot = "dbm";
		break;

	case 2346:
		prot = "redstorm_join";
		break;

	case 2347:
		prot = "redstorm_find";
		break;

	case 2348:
		prot = "redstorm_info";
		break;

	case 2349:
		prot = "redstorm_diag";
		break;

	case 2350:
		prot = "psbserver";
		break;

	case 2351:
		prot = "psrserver";
		break;

	case 2352:
		prot = "pslserver";
		break;

	case 2353:
		prot = "pspserver";
		break;

	case 2354:
		prot = "psprserver";
		break;

	case 2355:
		prot = "psdbserver";
		break;

	case 2356:
		prot = "gxtelmd";
		break;

	case 2357:
		prot = "unihub-server";
		break;

	case 2358:
		prot = "futrix";
		break;

	case 2359:
		prot = "flukeserver";
		break;

	case 2360:
		prot = "nexstorindltd";
		break;

	case 2361:
		prot = "tl1";
		break;

	case 2362:
		prot = "digiman";
		break;

	case 2363:
		prot = "mediacntrlnfsd";
		break;

	case 2364:
		prot = "oi-2000";
		break;

	case 2365:
		prot = "dbref";
		break;

	case 2366:
		prot = "qip-login";
		break;

	case 2367:
		prot = "service-ctrl";
		break;

	case 2368:
		prot = "opentable";
		break;

	case 2369:
		prot = "acs2000-dsp";
		break;

	case 2370:
		prot = "l3-hbmon";
		break;

	case 2371:
		prot = "worldwire";
		break;

	case 2381:
		prot = "compaq-https";
		break;

	case 2382:
		prot = "ms-olap3";
		break;

	case 2383:
		prot = "ms-olap4";
		break;

	case 2384:
		prot = "sd-capacity Or sd-request";
		break;

	case 2385:
		prot = "sd-data";
		break;

	case 2386:
		prot = "virtualtape";
		break;

	case 2387:
		prot = "vsamredirector";
		break;

	case 2388:
		prot = "mynahautostart";
		break;

	case 2389:
		prot = "ovsessionmgr";
		break;

	case 2390:
		prot = "rsmtp";
		break;

	case 2391:
		prot = "3com-net-mgmt";
		break;

	case 2392:
		prot = "tacticalauth";
		break;

	case 2393:
		prot = "ms-olap1";
		break;

	case 2394:
		prot = "ms-olap2";
		break;

	case 2395:
		prot = "lan900_remote";
		break;

	case 2396:
		prot = "wusage";
		break;

	case 2397:
		prot = "ncl";
		break;

	case 2398:
		prot = "orbiter";
		break;

	case 2399:
		prot = "fmpro-fdal";
		break;

	case 2400:
		prot = "opequus-server";
		break;

	case 2401:
		prot = "cvspserver";
		break;

	case 2402:
		prot = "taskmaster2000";
		break;

	case 2403:
		prot = "taskmaster2000";
		break;

	case 2404:
		prot = "iec-104";
		break;

	case 2405:
		prot = "trc-netpoll";
		break;

	case 2406:
		prot = "jediserver";
		break;

	case 2407:
		prot = "orion";
		break;

	case 2408:
		prot = "optimanet";
		break;

	case 2409:
		prot = "sns-protocol";
		break;

	case 2410:
		prot = "vrts-registry";
		break;

	case 2411:
		prot = "netwave-ap-mgmt";
		break;

	case 2412:
		prot = "cdn";
		break;

	case 2413:
		prot = "orion-rmi-reg";
		break;

	case 2414:
		prot = "beeyond";
		break;

	case 2415:
		prot = "codima-rtp";
		break;

	case 2416:
		prot = "rmtserver";
		break;

	case 2417:
		prot = "composit-server";
		break;

	case 2418:
		prot = "cas";
		break;

	case 2419:
		prot = "attachmate-s2s";
		break;

	case 2420:
		prot = "dslremote-mgmt";
		break;

	case 2421:
		prot = "g-talk";
		break;

	case 2422:
		prot = "crmsbits";
		break;

	case 2423:
		prot = "rnrp";
		break;

	case 2424:
		prot = "kofax-svr";
		break;

	case 2425:
		prot = "fjitsuappmgr";
		break;

	case 2427:
		prot = "mgcp-gateway";
		break;

	case 2428:
		prot = "ott";
		break;

	case 2429:
		prot = "ft-role";
		break;

	case 2430:
		prot = "venus";
		break;

	case 2431:
		prot = "venus-se";
		break;

	case 2432:
		prot = "codasrv";
		break;

	case 2433:
		prot = "codasrv-se";
		break;

	case 2434:
		prot = "pxc-epmap";
		break;

	case 2435:
		prot = "optilogic";
		break;

	case 2436:
		prot = "topx";
		break;

	case 2437:
		prot = "unicontrol";
		break;

	case 2438:
		prot = "msp";
		break;

	case 2439:
		prot = "sybasedbsynch";
		break;

	case 2440:
		prot = "spearway";
		break;

	case 2441:
		prot = "pvsw-inet";
		break;

	case 2442:
		prot = "netangel";
		break;

	case 2443:
		prot = "powerclientcsf";
		break;

	case 2444:
		prot = "btpp2sectrans";
		break;

	case 2445:
		prot = "dtn1";
		break;

	case 2446:
		prot = "bues_service";
		break;

	case 2447:
		prot = "ovwdb";
		break;

	case 2448:
		prot = "hpppssvr";
		break;

	case 2449:
		prot = "ratl";
		break;

	case 2450:
		prot = "netadmin";
		break;

	case 2451:
		prot = "netchat";
		break;

	case 2452:
		prot = "snifferclient";
		break;

	case 2453:
		prot = "madge-om";
		break;

	case 2454:
		prot = "indx-dds";
		break;

	case 2455:
		prot = "wago-io-system";
		break;

	case 2456:
		prot = "altav-remmgt";
		break;

	case 2457:
		prot = "rapido-ip";
		break;

	case 2458:
		prot = "griffin";
		break;

	case 2459:
		prot = "community";
		break;

	case 2460:
		prot = "ms-theater";
		break;

	case 2461:
		prot = "qadmifoper";
		break;

	case 2462:
		prot = "qadmifevent";
		break;

	case 2463:
		prot = "symbios-raid";
		break;

	case 2464:
		prot = "direcpc-si";
		break;

	case 2465:
		prot = "lbm";
		break;

	case 2466:
		prot = "lbf";
		break;

	case 2467:
		prot = "high-criteria";
		break;

	case 2468:
		prot = "qip-msgd";
		break;

	case 2469:
		prot = "mti-tcs-comm";
		break;

	case 2470:
		prot = "taskman-port";
		break;

	case 2471:
		prot = "seaodbc";
		break;

	case 2472:
		prot = "c3";
		break;

	case 2473:
		prot = "aker-cdp";
		break;

	case 2474:
		prot = "vitalanalysis";
		break;

	case 2475:
		prot = "ace-server";
		break;

	case 2476:
		prot = "ace-svr-prop";
		break;

	case 2477:
		prot = "ssm-cvs";
		break;

	case 2478:
		prot = "ssm-cssps";
		break;

	case 2479:
		prot = "ssm-els";
		break;

	case 2480:
		prot = "lingwood";
		break;

	case 2481:
		prot = "giop";
		break;

	case 2482:
		prot = "giop-ssl";
		break;

	case 2483:
		prot = "ttc";
		break;

	case 2484:
		prot = "ttc-ssl";
		break;

	case 2485:
		prot = "netobjects1";
		break;

	case 2486:
		prot = "netobjects2";
		break;

	case 2487:
		prot = "pns";
		break;

	case 2488:
		prot = "moy-corp";
		break;

	case 2489:
		prot = "tsilb";
		break;

	case 2490:
		prot = "qip-qdhcp";
		break;

	case 2491:
		prot = "conclave-cpp";
		break;

	case 2492:
		prot = "groove";
		break;

	case 2493:
		prot = "talarian-mqs";
		break;

	case 2494:
		prot = "bmc-ar";
		break;

	case 2495:
		prot = "fast-rem-serv";
		break;

	case 2496:
		prot = "dirgis";
		break;

	case 2497:
		prot = "quaddb";
		break;

	case 2498:
		prot = "odn-castraq";
		break;

	case 2499:
		prot = "unicontrol";
		break;

	case 2500:
		prot = "rtsserv";
		break;

	case 2501:
		prot = "rtsclient";
		break;

	case 2502:
		prot = "kentrox-prot";
		break;

	case 2503:
		prot = "nms-dpnss";
		break;

	case 2504:
		prot = "wlbs";
		break;

	case 2505:
		prot = "ppcontrol";
		break;

	case 2506:
		prot = "jbroker";
		break;

	case 2507:
		prot = "spock";
		break;

	case 2508:
		prot = "jdatastore";
		break;

	case 2509:
		prot = "fjmpss";
		break;

	case 2510:
		prot = "fjappmgrbulk";
		break;

	case 2511:
		prot = "metastorm";
		break;

	case 2512:
		prot = "citrixima";
		break;

	case 2513:
		prot = "citrixadmin";
		break;

	case 2514:
		prot = "facsys-ntp";
		break;

	case 2515:
		prot = "facsys-router";
		break;

	case 2516:
		prot = "maincontrol";
		break;

	case 2517:
		prot = "call-sig-trans";
		break;

	case 2518:
		prot = "willy";
		break;

	case 2519:
		prot = "globmsgsvc";
		break;

	case 2520:
		prot = "pvsw";
		break;

	case 2521:
		prot = "adaptecmgr";
		break;

	case 2522:
		prot = "windb";
		break;

	case 2523:
		prot = "qke-llc-v3";
		break;

	case 2524:
		prot = "optiwave-lm";
		break;

	case 2525:
		prot = "ms-v-worlds";
		break;

	case 2526:
		prot = "ema-sent-lm";
		break;

	case 2527:
		prot = "iqserver";
		break;

	case 2528:
		prot = "ncr_ccl";
		break;

	case 2529:
		prot = "utsftp";
		break;

	case 2530:
		prot = "vrcommerce";
		break;

	case 2531:
		prot = "ito-e-gui";
		break;

	case 2532:
		prot = "ovtopmd";
		break;

	case 2533:
		prot = "snifferserver";
		break;

	case 2534:
		prot = "combox-web-acc";
		break;

	case 2535:
		prot = "madcap";
		break;

	case 2536:
		prot = "btpp2audctr1";
		break;

	case 2537:
		prot = "upgrade";
		break;

	case 2538:
		prot = "vnwk-prapi";
		break;

	case 2539:
		prot = "vsiadmin";
		break;

	case 2540:
		prot = "lonworks";
		break;

	case 2541:
		prot = "lonworks2";
		break;

	case 2542:
		prot = "davinci";
		break;

	case 2543:
		prot = "reftek";
		break;

	case 2544:
		prot = "novell-zen";
		break;

	case 2545:
		prot = "sis-emt";
		break;

	case 2546:
		prot = "vytalvaultbrtp";
		break;

	case 2547:
		prot = "vytalvaultvsmp";
		break;

	case 2548:
		prot = "vytalvaultpipe";
		break;

	case 2549:
		prot = "ipass";
		break;

	case 2550:
		prot = "ads";
		break;

	case 2551:
		prot = "isg-uda-server";
		break;

	case 2552:
		prot = "call-logging";
		break;

	case 2553:
		prot = "efidiningport";
		break;

	case 2554:
		prot = "vcnet-link-v10";
		break;

	case 2555:
		prot = "compaq-wcp";
		break;

	case 2556:
		prot = "nicetec-nmsvc";
		break;

	case 2557:
		prot = "nicetec-mgmt";
		break;

	case 2558:
		prot = "pclemultimedia";
		break;

	case 2559:
		prot = "lstp";
		break;

	case 2560:
		prot = "labrat";
		break;

	case 2561:
		prot = "mosaixcc";
		break;

	case 2562:
		prot = "delibo";
		break;

	case 2563:
		prot = "cti-redwood";
		break;

	case 2564:
		prot = "hp-3000-telnet";
		break;

	case 2565:
		prot = "coord-svr";
		break;

	case 2566:
		prot = "pcs-pcw";
		break;

	case 2567:
		prot = "clp";
		break;

	case 2568:
		prot = "spamtrap";
		break;

	case 2569:
		prot = "sonuscallsig";
		break;

	case 2570:
		prot = "hs-port";
		break;

	case 2571:
		prot = "cecsvc";
		break;

	case 2572:
		prot = "ibp";
		break;

	case 2573:
		prot = "trustestablish";
		break;

	case 2574:
		prot = "blockade-bpsp";
		break;

	case 2575:
		prot = "hl7";
		break;

	case 2576:
		prot = "tclprodebugger";
		break;

	case 2577:
		prot = "scipticslsrvr";
		break;

	case 2578:
		prot = "rvs-isdn-dcp";
		break;

	case 2579:
		prot = "mpfoncl";
		break;

	case 2580:
		prot = "tributary";
		break;

	case 2581:
		prot = "argis-te";
		break;

	case 2582:
		prot = "argis-ds";
		break;

	case 2583:
		prot = "mon";
		break;

	case 2584:
		prot = "cyaserv";
		break;

	case 2585:
		prot = "netx-server";
		break;

	case 2586:
		prot = "netx-agent";
		break;

	case 2587:
		prot = "masc";
		break;

	case 2588:
		prot = "privilege";
		break;

	case 2589:
		prot = "quartus-tcl";
		break;

	case 2590:
		prot = "idotdist";
		break;

	case 2591:
		prot = "maytagshuffle";
		break;

	case 2592:
		prot = "netrek";
		break;

	case 2593:
		prot = "mns-mail";
		break;

	case 2594:
		prot = "dts";
		break;

	case 2595:
		prot = "worldfusion1";
		break;

	case 2596:
		prot = "worldfusion2";
		break;

	case 2597:
		prot = "homesteadglory";
		break;

	case 2598:
		prot = "citriximaclient";
		break;

	case 2599:
		prot = "snapd";
		break;

	case 2600:
		prot = "hpstgmgr";
		break;

	case 2601:
		prot = "discp-client";
		break;

	case 2602:
		prot = "discp-server";
		break;

	case 2603:
		prot = "servicemeter";
		break;

	case 2604:
		prot = "nsc-ccs";
		break;

	case 2605:
		prot = "nsc-posa";
		break;

	case 2606:
		prot = "netmon";
		break;

	case 2607:
		prot = "connection";
		break;

	case 2608:
		prot = "wag-service";
		break;

	case 2609:
		prot = "system-monitor";
		break;

	case 2610:
		prot = "versa-tek";
		break;

	case 2611:
		prot = "lionhead";
		break;

	case 2612:
		prot = "qpasa-agent";
		break;

	case 2613:
		prot = "smntubootstrap";
		break;

	case 2614:
		prot = "neveroffline";
		break;

	case 2615:
		prot = "firepower";
		break;

	case 2616:
		prot = "appswitch-emp";
		break;

	case 2617:
		prot = "cmadmin";
		break;

	case 2618:
		prot = "priority-e-com";
		break;

	case 2619:
		prot = "bruce";
		break;

	case 2620:
		prot = "lpsrecommender";
		break;

	case 2621:
		prot = "miles-apart";
		break;

	case 2622:
		prot = "metricadbc";
		break;

	case 2623:
		prot = "lmdp";
		break;

	case 2624:
		prot = "aria";
		break;

	case 2625:
		prot = "blwnkl-port";
		break;

	case 2626:
		prot = "gbjd816";
		break;

	case 2627:
		prot = "moshebeeri";
		break;

	case 2628:
		prot = "dict";
		break;

	case 2629:
		prot = "sitaraserver";
		break;

	case 2630:
		prot = "sitaramgmt";
		break;

	case 2631:
		prot = "sitaradir";
		break;

	case 2632:
		prot = "irdg-post";
		break;

	case 2633:
		prot = "interintelli";
		break;

	case 2634:
		prot = "pk-electronics";
		break;

	case 2635:
		prot = "backburner";
		break;

	case 2636:
		prot = "solve";
		break;

	case 2637:
		prot = "imdocsvc";
		break;

	case 2638:
		prot = "sybaseanywhere";
		break;

	case 2639:
		prot = "aminet";
		break;

	case 2640:
		prot = "sai_sentlm";
		break;

	case 2641:
		prot = "hdl-srv";
		break;

	case 2642:
		prot = "tragic";
		break;

	case 2643:
		prot = "gte-samp";
		break;

	case 2644:
		prot = "travsoft-ipx-t";
		break;

	case 2645:
		prot = "novell-ipx-cmd";
		break;

	case 2646:
		prot = "and-lm";
		break;

	case 2647:
		prot = "syncserver";
		break;

	case 2648:
		prot = "upsnotifyprot";
		break;

	case 2649:
		prot = "vpsipport";
		break;

	case 2650:
		prot = "eristwoguns";
		break;

	case 2651:
		prot = "ebinsite";
		break;

	case 2652:
		prot = "interpathpanel";
		break;

	case 2653:
		prot = "sonus";
		break;

	case 2654:
		prot = "corel_vncadmin";
		break;

	case 2655:
		prot = "unglue";
		break;

	case 2656:
		prot = "kana";
		break;

	case 2657:
		prot = "sns-dispatcher";
		break;

	case 2658:
		prot = "sns-admin";
		break;

	case 2659:
		prot = "sns-query";
		break;

	case 2660:
		prot = "gcmonitor";
		break;

	case 2661:
		prot = "olhost";
		break;

	case 2662:
		prot = "bintec-capi";
		break;

	case 2663:
		prot = "bintec-tapi";
		break;

	case 2664:
		prot = "patrol-mq-gm";
		break;

	case 2665:
		prot = "patrol-mq-nm";
		break;

	case 2666:
		prot = "extensis";
		break;

	case 2667:
		prot = "alarm-clock-s";
		break;

	case 2668:
		prot = "alarm-clock-c";
		break;

	case 2669:
		prot = "toad";
		break;

	case 2670:
		prot = "tve-announce";
		break;

	case 2671:
		prot = "newlixreg";
		break;

	case 2672:
		prot = "nhserver";
		break;

	case 2673:
		prot = "firstcall42";
		break;

	case 2674:
		prot = "ewnn";
		break;

	case 2675:
		prot = "ttc-etap";
		break;

	case 2676:
		prot = "simslink";
		break;

	case 2677:
		prot = "gadgetgate1way";
		break;

	case 2678:
		prot = "gadgetgate2way";
		break;

	case 2679:
		prot = "syncserverssl";
		break;

	case 2680:
		prot = "pxc-sapxom";
		break;

	case 2681:
		prot = "mpnjsomb";
		break;

	case 2683:
		prot = "ncdloadbalance";
		break;

	case 2684:
		prot = "mpnjsosv";
		break;

	case 2685:
		prot = "mpnjsocl";
		break;

	case 2686:
		prot = "mpnjsomg";
		break;

	case 2687:
		prot = "pq-lic-mgmt";
		break;

	case 2688:
		prot = "md-cg-http";
		break;

	case 2689:
		prot = "fastlynx";
		break;

	case 2690:
		prot = "hp-nnm-data";
		break;

	case 2691:
		prot = "itinternet";
		break;

	case 2692:
		prot = "admins-lms";
		break;

	case 2693:
		prot = "belarc-http";
		break;

	case 2694:
		prot = "pwrsevent";
		break;

	case 2695:
		prot = "vspread";
		break;

	case 2696:
		prot = "unifyadmin";
		break;

	case 2697:
		prot = "oce-snmp-trap";
		break;

	case 2698:
		prot = "mck-ivpip";
		break;

	case 2699:
		prot = "csoft-plusclnt";
		break;

	case 2700:
		prot = "tqdata";
		break;

	case 2701:
		prot = "sms-rcinfo";
		break;

	case 2702:
		prot = "sms-xfer";
		break;

	case 2703:
		prot = "sms-chat";
		break;

	case 2704:
		prot = "sms-remctrl";
		break;

	case 2705:
		prot = "sds-admin";
		break;

	case 2706:
		prot = "ncdmirroring";
		break;

	case 2707:
		prot = "emcsymapiport";
		break;

	case 2708:
		prot = "banyan-net";
		break;

	case 2709:
		prot = "supermon";
		break;

	case 2710:
		prot = "sso-service";
		break;

	case 2711:
		prot = "sso-control";
		break;

	case 2712:
		prot = "aocp";
		break;

	case 2713:
		prot = "raven1";
		break;

	case 2714:
		prot = "raven2";
		break;

	case 2715:
		prot = "hpstgmgr2";
		break;

	case 2716:
		prot = "inova-ip-disco";
		break;

	case 2717:
		prot = "pn-requester";
		break;

	case 2718:
		prot = "pn-requester2";
		break;

	case 2719:
		prot = "scan-change";
		break;

	case 2720:
		prot = "wkars";
		break;

	case 2721:
		prot = "smart-diagnose";
		break;

	case 2722:
		prot = "proactivesrvr";
		break;

	case 2723:
		prot = "watchdognt";
		break;

	case 2724:
		prot = "qotps";
		break;

	case 2725:
		prot = "msolap-ptp2";
		break;

	case 2726:
		prot = "tams";
		break;

	case 2727:
		prot = "mgcp-callagent";
		break;

	case 2728:
		prot = "sqdr";
		break;

	case 2729:
		prot = "tcim-control";
		break;

	case 2730:
		prot = "nec-raidplus";
		break;

	case 2731:
		prot = "fyre-messanger";
		break;

	case 2732:
		prot = "g5m";
		break;

	case 2733:
		prot = "signet-ctf";
		break;

	case 2734:
		prot = "ccs-software";
		break;

	case 2735:
		prot = "netiq-mc";
		break;

	case 2736:
		prot = "radwiz-nms-srv";
		break;

	case 2737:
		prot = "srp-feedback";
		break;

	case 2738:
		prot = "ndl-tcp-ois-gw";
		break;

	case 2739:
		prot = "tn-timing";
		break;

	case 2740:
		prot = "alarm";
		break;

	case 2741:
		prot = "tsb";
		break;

	case 2742:
		prot = "tsb2";
		break;

	case 2743:
		prot = "murx";
		break;

	case 2744:
		prot = "honyaku";
		break;

	case 2745:
		prot = "urbisnet";
		break;

	case 2746:
		prot = "cpudpencap";
		break;

	case 2747:
		prot = "fjippol-swrly";
		break;

	case 2748:
		prot = "fjippol-polsvr";
		break;

	case 2749:
		prot = "fjippol-cnsl";
		break;

	case 2750:
		prot = "fjippol-port1";
		break;

	case 2751:
		prot = "fjippol-port2";
		break;

	case 2752:
		prot = "rsisysaccess";
		break;

	case 2753:
		prot = "de-spot";
		break;

	case 2754:
		prot = "apollo-cc";
		break;

	case 2755:
		prot = "expresspay";
		break;

	case 2756:
		prot = "simplement-tie";
		break;

	case 2757:
		prot = "cnrp";
		break;

	case 2758:
		prot = "apollo-status";
		break;

	case 2759:
		prot = "apollo-gms";
		break;

	case 2760:
		prot = "sabams";
		break;

	case 2761:
		prot = "dicom-iscl";
		break;

	case 2762:
		prot = "dicom-tls";
		break;

	case 2763:
		prot = "desktop-dna";
		break;

	case 2764:
		prot = "data-insurance";
		break;

	case 2765:
		prot = "qip-audup";
		break;

	case 2766:
		prot = "compaq-scp";
		break;

	case 2767:
		prot = "uadtc";
		break;

	case 2768:
		prot = "uacs";
		break;

	case 2769:
		prot = "singlept-mvs";
		break;

	case 2770:
		prot = "veronica";
		break;

	case 2771:
		prot = "vergencecm";
		break;

	case 2772:
		prot = "auris";
		break;

	case 2773:
		prot = "rbakcup1";
		break;

	case 2774:
		prot = "rbakcup2";
		break;

	case 2775:
		prot = "smpp";
		break;

	case 2776:
		prot = "ridgeway1";
		break;

	case 2777:
		prot = "ridgeway2";
		break;

	case 2778:
		prot = "gwen-sonya";
		break;

	case 2779:
		prot = "lbc-sync";
		break;

	case 2780:
		prot = "lbc-control";
		break;

	case 2781:
		prot = "whosells";
		break;

	case 2782:
		prot = "everydayrc";
		break;

	case 2783:
		prot = "aises";
		break;

	case 2784:
		prot = "www-dev";
		break;

	case 2785:
		prot = "aic-np";
		break;

	case 2786:
		prot = "aic-oncrpc";
		break;

	case 2787:
		prot = "piccolo";
		break;

	case 2788:
		prot = "fryeserv";
		break;

	case 2789:
		prot = "media-agent";
		break;

	case 2790:
		prot = "plgproxy";
		break;

	case 2791:
		prot = "mtport-regist";
		break;

	case 2792:
		prot = "f5-globalsite";
		break;

	case 2793:
		prot = "initlsmsad";
		break;

	case 2794:
		prot = "aaftp";
		break;

	case 2795:
		prot = "livestats";
		break;

	case 2796:
		prot = "ac-tech";
		break;

	case 2797:
		prot = "esp-encap";
		break;

	case 2798:
		prot = "tmesis-upshot";
		break;

	case 2799:
		prot = "icon-discover";
		break;

	case 2800:
		prot = "acc-raid";
		break;

	case 2801:
		prot = "igcp";
		break;

	case 2802:
		prot = "veritas";
		break;

	case 2803:
		prot = "btprjctrl";
		break;

	case 2804:
		prot = "telexis-vtu";
		break;

	case 2805:
		prot = "wta-wsp-s";
		break;

	case 2806:
		prot = "cspuni";
		break;

	case 2807:
		prot = "cspmulti";
		break;

	case 2808:
		prot = "j-lan-p";
		break;

	case 2809:
		prot = "corbaloc";
		break;

	case 2810:
		prot = "netsteward";
		break;

	case 2811:
		prot = "gsiftp";
		break;

	case 2812:
		prot = "atmtcp";
		break;

	case 2813:
		prot = "llm-pass";
		break;

	case 2814:
		prot = "llm-csv";
		break;

	case 2815:
		prot = "lbc-measure";
		break;

	case 2816:
		prot = "lbc-watchdog";
		break;

	case 2817:
		prot = "nmsigport";
		break;

	case 2818:
		prot = "rmlnk";
		break;

	case 2819:
		prot = "fc-faultnotify";
		break;

	case 2820:
		prot = "univision";
		break;

	case 2821:
		prot = "vrts-at-port";
		break;

	case 2822:
		prot = "ka0wuc";
		break;

	case 2823:
		prot = "cqg-netlan";
		break;

	case 2824:
		prot = "cqg-netlan-1";
		break;

	case 2826:
		prot = "slc-systemlog";
		break;

	case 2827:
		prot = "slc-ctrlrloops";
		break;

	case 2828:
		prot = "itm-lm";
		break;

	case 2829:
		prot = "silkp1";
		break;

	case 2830:
		prot = "silkp2";
		break;

	case 2831:
		prot = "silkp3";
		break;

	case 2832:
		prot = "silkp4";
		break;

	case 2833:
		prot = "glishd";
		break;

	case 2834:
		prot = "evtp";
		break;

	case 2835:
		prot = "evtp-data";
		break;

	case 2836:
		prot = "catalyst";
		break;

	case 2837:
		prot = "repliweb";
		break;

	case 2838:
		prot = "starbot";
		break;

	case 2839:
		prot = "nmsigport";
		break;

	case 2840:
		prot = "l3-exprt";
		break;

	case 2841:
		prot = "l3-ranger";
		break;

	case 2842:
		prot = "l3-hawk";
		break;

	case 2843:
		prot = "pdnet";
		break;

	case 2844:
		prot = "bpcp-poll";
		break;

	case 2845:
		prot = "bpcp-trap";
		break;

	case 2846:
		prot = "aimpp-hello";
		break;

	case 2847:
		prot = "aimpp-port-req";
		break;

	case 2848:
		prot = "amt-blc-port";
		break;

	case 2849:
		prot = "fxp";
		break;

	case 2850:
		prot = "metaconsole";
		break;

	case 2851:
		prot = "webemshttp";
		break;

	case 2852:
		prot = "bears-01";
		break;

	case 2853:
		prot = "ispipes";
		break;

	case 2854:
		prot = "infomover";
		break;

	case 2856:
		prot = "cesdinv";
		break;

	case 2857:
		prot = "simctlp";
		break;

	case 2858:
		prot = "ecnp";
		break;

	case 2859:
		prot = "activememory";
		break;

	case 2860:
		prot = "dialpad-voice1";
		break;

	case 2861:
		prot = "dialpad-voice2";
		break;

	case 2862:
		prot = "ttg-protocol";
		break;

	case 2863:
		prot = "sonardata";
		break;

	case 2864:
		prot = "astromed-main";
		break;

	case 2865:
		prot = "pit-vpn";
		break;

	case 2866:
		prot = "iwlistener";
		break;

	case 2867:
		prot = "esps-portal";
		break;

	case 2868:
		prot = "npep-messaging";
		break;

	case 2869:
		prot = "icslap";
		break;

	case 2870:
		prot = "daishi";
		break;

	case 2871:
		prot = "msi-selectplay";
		break;

	case 2872:
		prot = "radix";
		break;

	case 2873:
		prot = "paspar2-zoomin";
		break;

	case 2874:
		prot = "dxmessagebase1";
		break;

	case 2875:
		prot = "dxmessagebase2";
		break;

	case 2876:
		prot = "sps-tunnel";
		break;

	case 2877:
		prot = "bluelance";
		break;

	case 2878:
		prot = "aap";
		break;

	case 2879:
		prot = "ucentric-ds";
		break;

	case 2880:
		prot = "synapse";
		break;

	case 2881:
		prot = "ndsp";
		break;

	case 2882:
		prot = "ndtp";
		break;

	case 2883:
		prot = "ndnp";
		break;

	case 2884:
		prot = "flashmsg";
		break;

	case 2885:
		prot = "topflow";
		break;

	case 2886:
		prot = "responselogic";
		break;

	case 2887:
		prot = "aironetddp";
		break;

	case 2888:
		prot = "spcsdlobby";
		break;

	case 2889:
		prot = "rsom";
		break;

	case 2890:
		prot = "cspclmulti";
		break;

	case 2891:
		prot = "cinegrfx-elmd";
		break;

	case 2892:
		prot = "snifferdata";
		break;

	case 2893:
		prot = "vseconnector";
		break;

	case 2894:
		prot = "abacus-remote";
		break;

	case 2895:
		prot = "natuslink";
		break;

	case 2896:
		prot = "ecovisiong6-1";
		break;

	case 2897:
		prot = "citrix-rtmp";
		break;

	case 2898:
		prot = "appliance-cfg";
		break;

	case 2899:
		prot = "powergemplus";
		break;

	case 2900:
		prot = "quicksuite";
		break;

	case 2901:
		prot = "allstorcns";
		break;

	case 2902:
		prot = "netaspi";
		break;

	case 2903:
		prot = "suitcase";
		break;

	case 2904:
		prot = "m2ua";
		break;

	case 2905:
		prot = "m3ua";
		break;

	case 2906:
		prot = "caller9";
		break;

	case 2907:
		prot = "webmethods-b2b";
		break;

	case 2908:
		prot = "mao";
		break;

	case 2909:
		prot = "funk-dialout";
		break;

	case 2910:
		prot = "tdaccess";
		break;

	case 2911:
		prot = "blockade";
		break;

	case 2912:
		prot = "epicon";
		break;

	case 2913:
		prot = "boosterware";
		break;

	case 2914:
		prot = "gamelobby";
		break;

	case 2915:
		prot = "tksocket";
		break;

	case 2916:
		prot = "elvin_server";
		break;

	case 2917:
		prot = "elvin_client";
		break;

	case 2918:
		prot = "kastenchasepad";
		break;

	case 2919:
		prot = "roboer";
		break;

	case 2920:
		prot = "roboeda";
		break;

	case 2921:
		prot = "cesdcdman";
		break;

	case 2922:
		prot = "cesdcdtrn";
		break;

	case 2923:
		prot = "wta-wsp-wtp-s";
		break;

	case 2924:
		prot = "precise-vip";
		break;

	case 2926:
		prot = "mobile-file-dl";
		break;

	case 2927:
		prot = "unimobilectrl";
		break;

	case 2928:
		prot = "redstone-cpss";
		break;

	case 2929:
		prot = "amx-webadmin";
		break;

	case 2930:
		prot = "amx-weblinx";
		break;

	case 2931:
		prot = "circle-x";
		break;

	case 2932:
		prot = "incp";
		break;

	case 2933:
		prot = "4-tieropmgw";
		break;

	case 2934:
		prot = "4-tieropmcli";
		break;

	case 2935:
		prot = "qtp";
		break;

	case 2936:
		prot = "otpatch";
		break;

	case 2937:
		prot = "pnaconsult-lm";
		break;

	case 2938:
		prot = "sm-pas-1";
		break;

	case 2939:
		prot = "sm-pas-2";
		break;

	case 2940:
		prot = "sm-pas-3";
		break;

	case 2941:
		prot = "sm-pas-4";
		break;

	case 2942:
		prot = "sm-pas-5";
		break;

	case 2943:
		prot = "ttnrepository";
		break;

	case 2944:
		prot = "megaco-h248";
		break;

	case 2945:
		prot = "h248-binary";
		break;

	case 2946:
		prot = "fjsvmpor";
		break;

	case 2947:
		prot = "gpsd";
		break;

	case 2948:
		prot = "wap-push";
		break;

	case 2949:
		prot = "wap-pushsecure";
		break;

	case 2950:
		prot = "esip";
		break;

	case 2951:
		prot = "ottp";
		break;

	case 2952:
		prot = "mpfwsas";
		break;

	case 2953:
		prot = "ovalarmsrv";
		break;

	case 2954:
		prot = "ovalarmsrv-cmd";
		break;

	case 2955:
		prot = "csnotify";
		break;

	case 2956:
		prot = "ovrimosdbman";
		break;

	case 2957:
		prot = "jmact5";
		break;

	case 2958:
		prot = "jmact6";
		break;

	case 2959:
		prot = "rmopagt";
		break;

	case 2960:
		prot = "dfoxserver";
		break;

	case 2961:
		prot = "boldsoft-lm";
		break;

	case 2962:
		prot = "iph-policy-cli";
		break;

	case 2963:
		prot = "iph-policy-adm";
		break;

	case 2964:
		prot = "bullant-srap";
		break;

	case 2965:
		prot = "bullant-rap";
		break;

	case 2966:
		prot = "idp-infotrieve";
		break;

	case 2967:
		prot = "ssc-agent";
		break;

	case 2968:
		prot = "enpp";
		break;

	case 2969:
		prot = "essp";
		break;

	case 2970:
		prot = "index-net";
		break;

	case 2971:
		prot = "netclip";
		break;

	case 2972:
		prot = "pmsm-webrctl";
		break;

	case 2973:
		prot = "svnetworks";
		break;

	case 2974:
		prot = "signal";
		break;

	case 2975:
		prot = "fjmpcm";
		break;

	case 2976:
		prot = "cns-srv-port";
		break;

	case 2977:
		prot = "ttc-etap-ns";
		break;

	case 2978:
		prot = "ttc-etap-ds";
		break;

	case 2979:
		prot = "h263-video";
		break;

	case 2980:
		prot = "wimd";
		break;

	case 2981:
		prot = "mylxamport";
		break;

	case 2982:
		prot = "iwb-whiteboard";
		break;

	case 2983:
		prot = "netplan";
		break;

	case 2984:
		prot = "hpidsadmin";
		break;

	case 2985:
		prot = "hpidsagent";
		break;

	case 2986:
		prot = "stonefalls";
		break;

	case 2987:
		prot = "identify";
		break;

	case 2988:
		prot = "hippad";
		break;

	case 2989:
		prot = "zarkov";
		break;

	case 2990:
		prot = "boscap";
		break;

	case 2991:
		prot = "wkstn-mon";
		break;

	case 2992:
		prot = "itb301";
		break;

	case 2993:
		prot = "veritas-vis1";
		break;

	case 2994:
		prot = "veritas-vis2";
		break;

	case 2995:
		prot = "idrs";
		break;

	case 2996:
		prot = "vsixml";
		break;

	case 2997:
		prot = "rebol";
		break;

	case 2998:
		prot = "realsecure";
		break;

	case 2999:
		prot = "remoteware-un";
		break;

	case 3000:
		prot = "hbci Or remoteware-cl";
		break;

	case 3001:
		prot = "redwood-broker";
		break;

	case 3002:
		prot = "exlm-agent Or remoteware-srv";
		break;

	case 3003:
		prot = "cgms";
		break;

	case 3004:
		prot = "csoftragent";
		break;

	case 3005:
		prot = "geniuslm";
		break;

	case 3006:
		prot = "ii-admin";
		break;

	case 3007:
		prot = "lotusmtap";
		break;

	case 3008:
		prot = "midnight-tech";
		break;

	case 3009:
		prot = "pxc-ntfy";
		break;

	case 3010:
		prot = "gw Or ping-pong";
		break;

	case 3011:
		prot = "trusted-web";
		break;

	case 3012:
		prot = "twsdss";
		break;

	case 3013:
		prot = "gilatskysurfer";
		break;

	case 3014:
		prot = "broker_service";
		break;

	case 3015:
		prot = "nati-dstp";
		break;

	case 3016:
		prot = "notify_srvr";
		break;

	case 3017:
		prot = "event_listener";
		break;

	case 3018:
		prot = "srvc_registry";
		break;

	case 3019:
		prot = "resource_mgr";
		break;

	case 3020:
		prot = "cifs";
		break;

	case 3021:
		prot = "agriserver";
		break;

	case 3022:
		prot = "csregagent";
		break;

	case 3023:
		prot = "magicnotes";
		break;

	case 3024:
		prot = "nds_sso";
		break;

	case 3025:
		prot = "arepa-raft";
		break;

	case 3026:
		prot = "agri-gateway";
		break;

	case 3027:
		prot = "LiebDevMgmt_C";
		break;

	case 3028:
		prot = "LiebDevMgmt_DM";
		break;

	case 3029:
		prot = "LiebDevMgmt_A";
		break;

	case 3030:
		prot = "arepa-cas";
		break;

	case 3031:
		prot = "eppc";
		break;

	case 3032:
		prot = "redwood-chat";
		break;

	case 3033:
		prot = "pdb";
		break;

	case 3034:
		prot = "osmosis-aeea";
		break;

	case 3035:
		prot = "fjsv-gssagt";
		break;

	case 3036:
		prot = "hagel-dump";
		break;

	case 3037:
		prot = "hp-san-mgmt";
		break;

	case 3038:
		prot = "santak-ups";
		break;

	case 3039:
		prot = "cogitate";
		break;

	case 3040:
		prot = "tomato-springs";
		break;

	case 3041:
		prot = "di-traceware";
		break;

	case 3042:
		prot = "journee";
		break;

	case 3043:
		prot = "brp";
		break;

	case 3044:
		prot = "epp";
		break;

	case 3045:
		prot = "responsenet";
		break;

	case 3046:
		prot = "di-ase";
		break;

	case 3047:
		prot = "hlserver";
		break;

	case 3048:
		prot = "pctrader";
		break;

	case 3049:
		prot = "nsws";
		break;

	case 3050:
		prot = "gds_db";
		break;

	case 3051:
		prot = "galaxy-server";
		break;

	case 3052:
		prot = "apc-3052";
		break;

	case 3053:
		prot = "dsom-server";
		break;

	case 3054:
		prot = "amt-cnf-prot";
		break;

	case 3055:
		prot = "policyserver";
		break;

	case 3056:
		prot = "cdl-server";
		break;

	case 3057:
		prot = "goahead-fldup";
		break;

	case 3058:
		prot = "videobeans";
		break;

	case 3059:
		prot = "qsoft";
		break;

	case 3060:
		prot = "interserver";
		break;

	case 3061:
		prot = "cautcpd";
		break;

	case 3062:
		prot = "ncacn-ip-tcp";
		break;

	case 3063:
		prot = "ncadg-ip-udp";
		break;

	case 3064:
		prot = "rprt";
		break;

	case 3065:
		prot = "slinterbase";
		break;

	case 3066:
		prot = "netattachsdmp";
		break;

	case 3067:
		prot = "fjhpjp";
		break;

	case 3068:
		prot = "ls3bcast";
		break;

	case 3069:
		prot = "ls3";
		break;

	case 3070:
		prot = "mgxswitch";
		break;

	case 3071:
		prot = "csd-mgmt-port";
		break;

	case 3072:
		prot = "csd-monitor";
		break;

	case 3073:
		prot = "vcrp";
		break;

	case 3074:
		prot = "xbox";
		break;

	case 3075:
		prot = "orbix-locator";
		break;

	case 3076:
		prot = "orbix-config";
		break;

	case 3077:
		prot = "orbix-loc-ssl";
		break;

	case 3078:
		prot = "orbix-cfg-ssl";
		break;

	case 3079:
		prot = "lv-frontpanel";
		break;

	case 3080:
		prot = "stm_pproc";
		break;

	case 3081:
		prot = "tl1-lv";
		break;

	case 3082:
		prot = "tl1-raw";
		break;

	case 3083:
		prot = "tl1-telnet";
		break;

	case 3084:
		prot = "itm-mccs";
		break;

	case 3085:
		prot = "pcihreq";
		break;

	case 3086:
		prot = "jdl-dbkitchen";
		break;

	case 3087:
		prot = "asoki-sma";
		break;

	case 3088:
		prot = "xdtp";
		break;

	case 3089:
		prot = "ptk-alink";
		break;

	case 3090:
		prot = "rtss";
		break;

	case 3091:
		prot = "1ci-smcs";
		break;

	case 3092:
		prot = "njfss";
		break;

	case 3093:
		prot = "rapidmq-center";
		break;

	case 3094:
		prot = "rapidmq-reg";
		break;

	case 3095:
		prot = "panasas";
		break;

	case 3096:
		prot = "ndl-aps";
		break;

	case 3097:
		prot = "itu-bicc-stc";
		break;

	case 3098:
		prot = "umm-port";
		break;

	case 3099:
		prot = "chmd";
		break;

	case 3100:
		prot = "opcon-xps";
		break;

	case 3101:
		prot = "hp-pxpib";
		break;

	case 3102:
		prot = "slslavemon";
		break;

	case 3103:
		prot = "autocuesmi";
		break;

	case 3104:
		prot = "autocuelog Or autocuetime";
		break;

	case 3105:
		prot = "cardbox";
		break;

	case 3106:
		prot = "cardbox-http";
		break;

	case 3107:
		prot = "business";
		break;

	case 3108:
		prot = "geolocate";
		break;

	case 3109:
		prot = "personnel";
		break;

	case 3110:
		prot = "sim-control";
		break;

	case 3111:
		prot = "wsynch";
		break;

	case 3112:
		prot = "ksysguard";
		break;

	case 3113:
		prot = "cs-auth-svr";
		break;

	case 3114:
		prot = "ccmad";
		break;

	case 3115:
		prot = "mctet-master";
		break;

	case 3116:
		prot = "mctet-gateway";
		break;

	case 3117:
		prot = "mctet-jserv";
		break;

	case 3118:
		prot = "pkagent";
		break;

	case 3119:
		prot = "d2000kernel";
		break;

	case 3120:
		prot = "d2000webserver";
		break;

	case 3121:
		prot = "epp-temp";
		break;

	case 3122:
		prot = "vtr-emulator";
		break;

	case 3123:
		prot = "edix";
		break;

	case 3124:
		prot = "beacon-port";
		break;

	case 3125:
		prot = "a13-an";
		break;

	case 3126:
		prot = "ms-dotnetster";
		break;

	case 3127:
		prot = "ctx-bridge";
		break;

	case 3128:
		prot = "ndl-aas";
		break;

	case 3129:
		prot = "netport-id";
		break;

	case 3130:
		prot = "icpv2";
		break;

	case 3131:
		prot = "netbookmark";
		break;

	case 3132:
		prot = "ms-rule-engine";
		break;

	case 3133:
		prot = "prism-deploy";
		break;

	case 3134:
		prot = "ecp";
		break;

	case 3135:
		prot = "peerbook-port";
		break;

	case 3136:
		prot = "grubd";
		break;

	case 3137:
		prot = "rtnt-1";
		break;

	case 3138:
		prot = "rtnt-2";
		break;

	case 3139:
		prot = "incognitorv";
		break;

	case 3140:
		prot = "ariliamulti";
		break;

	case 3141:
		prot = "vmodem";
		break;

	case 3142:
		prot = "rdc-wh-eos";
		break;

	case 3143:
		prot = "seaview";
		break;

	case 3144:
		prot = "tarantella";
		break;

	case 3145:
		prot = "csi-lfap";
		break;

	case 3146:
		prot = "bears-02";
		break;

	case 3147:
		prot = "rfio";
		break;

	case 3148:
		prot = "nm-game-admin";
		break;

	case 3149:
		prot = "nm-game-server";
		break;

	case 3150:
		prot = "nm-asses-admin";
		break;

	case 3151:
		prot = "nm-assessor";
		break;

	case 3152:
		prot = "feitianrockey";
		break;

	case 3153:
		prot = "s8-client-port";
		break;

	case 3154:
		prot = "ccmrmi";
		break;

	case 3155:
		prot = "jpegmpeg";
		break;

	case 3156:
		prot = "indura";
		break;

	case 3157:
		prot = "e3consultants";
		break;

	case 3158:
		prot = "stvp";
		break;

	case 3159:
		prot = "navegaweb-port";
		break;

	case 3160:
		prot = "tip-app-server";
		break;

	case 3161:
		prot = "doc1lm";
		break;

	case 3162:
		prot = "sflm";
		break;

	case 3163:
		prot = "res-sap";
		break;

	case 3164:
		prot = "imprs";
		break;

	case 3165:
		prot = "newgenpay";
		break;

	case 3166:
		prot = "qrepos";
		break;

	case 3167:
		prot = "poweroncontact";
		break;

	case 3168:
		prot = "poweronnud";
		break;

	case 3169:
		prot = "serverview-as";
		break;

	case 3170:
		prot = "serverview-asn";
		break;

	case 3171:
		prot = "serverview-gf";
		break;

	case 3172:
		prot = "serverview-rm";
		break;

	case 3173:
		prot = "serverview-icc";
		break;

	case 3174:
		prot = "armi-server";
		break;

	case 3175:
		prot = "t1-e1-over-ip";
		break;

	case 3176:
		prot = "ars-master";
		break;

	case 3177:
		prot = "phonex-port";
		break;

	case 3178:
		prot = "radclientport";
		break;

	case 3179:
		prot = "h2gf-w-2m";
		break;

	case 3180:
		prot = "mc-brk-srv";
		break;

	case 3181:
		prot = "bmcpatrolagent";
		break;

	case 3182:
		prot = "bmcpatrolrnvu";
		break;

	case 3183:
		prot = "cops-tls";
		break;

	case 3184:
		prot = "apogeex-port";
		break;

	case 3185:
		prot = "smpppd";
		break;

	case 3186:
		prot = "iiw-port";
		break;

	case 3187:
		prot = "odi-port";
		break;

	case 3188:
		prot = "brcm-comm-port";
		break;

	case 3189:
		prot = "pcle-infex";
		break;

	case 3190:
		prot = "csvr-proxy";
		break;

	case 3191:
		prot = "csvr-sslproxy";
		break;

	case 3192:
		prot = "firemonrcc";
		break;

	case 3193:
		prot = "cordataport";
		break;

	case 3194:
		prot = "magbind";
		break;

	case 3195:
		prot = "ncu-1";
		break;

	case 3196:
		prot = "ncu-2";
		break;

	case 3197:
		prot = "embrace-dp-s";
		break;

	case 3198:
		prot = "embrace-dp-c";
		break;

	case 3199:
		prot = "dmod-workspace";
		break;

	case 3200:
		prot = "tick-port";
		break;

	case 3201:
		prot = "cpq-tasksmart";
		break;

	case 3202:
		prot = "intraintra";
		break;

	case 3203:
		prot = "netwatcher-mon";
		break;

	case 3204:
		prot = "netwatcher-db";
		break;

	case 3205:
		prot = "isns";
		break;

	case 3206:
		prot = "ironmail";
		break;

	case 3207:
		prot = "vx-auth-port";
		break;

	case 3208:
		prot = "pfu-prcallback";
		break;

	case 3209:
		prot = "netwkpathengine";
		break;

	case 3210:
		prot = "flamenco-proxy";
		break;

	case 3211:
		prot = "avsecuremgmt";
		break;

	case 3212:
		prot = "surveyinst";
		break;

	case 3213:
		prot = "neon24x7";
		break;

	case 3214:
		prot = "jmq-daemon-1";
		break;

	case 3215:
		prot = "jmq-daemon-2";
		break;

	case 3216:
		prot = "ferrari-foam";
		break;

	case 3217:
		prot = "unite";
		break;

	case 3218:
		prot = "smartpackets";
		break;

	case 3219:
		prot = "wms-messenger";
		break;

	case 3220:
		prot = "xnm-ssl";
		break;

	case 3221:
		prot = "xnm-clear-text";
		break;

	case 3222:
		prot = "glbp";
		break;

	case 3223:
		prot = "digivote";
		break;

	case 3224:
		prot = "aes-discovery";
		break;

	case 3225:
		prot = "fcip-port";
		break;

	case 3226:
		prot = "isi-irp";
		break;

	case 3227:
		prot = "dwnmshttp";
		break;

	case 3228:
		prot = "dwmsgserver";
		break;

	case 3229:
		prot = "global-cd-port";
		break;

	case 3230:
		prot = "sftdst-port";
		break;

	case 3231:
		prot = "dsnl";
		break;

	case 3232:
		prot = "mdtp";
		break;

	case 3233:
		prot = "whisker";
		break;

	case 3234:
		prot = "alchemy";
		break;

	case 3235:
		prot = "mdap-port";
		break;

	case 3236:
		prot = "apparenet-ts";
		break;

	case 3237:
		prot = "apparenet-tps";
		break;

	case 3238:
		prot = "apparenet-as";
		break;

	case 3239:
		prot = "apparenet-ui";
		break;

	case 3240:
		prot = "triomotion";
		break;

	case 3241:
		prot = "sysorb";
		break;

	case 3242:
		prot = "sdp-id-port";
		break;

	case 3243:
		prot = "timelot";
		break;

	case 3244:
		prot = "onesaf";
		break;

	case 3245:
		prot = "vieo-fe";
		break;

	case 3246:
		prot = "dvt-system";
		break;

	case 3247:
		prot = "dvt-data";
		break;

	case 3248:
		prot = "procos-lm";
		break;

	case 3249:
		prot = "ssp";
		break;

	case 3250:
		prot = "hicp";
		break;

	case 3251:
		prot = "sysscanner";
		break;

	case 3252:
		prot = "dhe";
		break;

	case 3253:
		prot = "pda-data";
		break;

	case 3254:
		prot = "pda-sys";
		break;

	case 3255:
		prot = "semaphore";
		break;

	case 3256:
		prot = "cpqrpm-agent";
		break;

	case 3257:
		prot = "cpqrpm-server";
		break;

	case 3258:
		prot = "ivecon-port";
		break;

	case 3259:
		prot = "epncdp2";
		break;

	case 3260:
		prot = "iscsi-target";
		break;

	case 3261:
		prot = "winshadow";
		break;

	case 3262:
		prot = "necp";
		break;

	case 3263:
		prot = "ecolor-imager";
		break;

	case 3264:
		prot = "ccmail";
		break;

	case 3265:
		prot = "altav-tunnel";
		break;

	case 3266:
		prot = "ns-cfg-server";
		break;

	case 3267:
		prot = "ibm-dial-out";
		break;

	case 3268:
		prot = "msft-gc";
		break;

	case 3269:
		prot = "msft-gc-ssl";
		break;

	case 3270:
		prot = "verismart";
		break;

	case 3271:
		prot = "csoft-prev";
		break;

	case 3272:
		prot = "user-manager";
		break;

	case 3273:
		prot = "sxmp";
		break;

	case 3274:
		prot = "ordinox-server";
		break;

	case 3275:
		prot = "samd";
		break;

	case 3276:
		prot = "maxim-asics";
		break;

	case 3277:
		prot = "awg-proxy";
		break;

	case 3278:
		prot = "lkcmserver";
		break;

	case 3279:
		prot = "admind";
		break;

	case 3280:
		prot = "vs-server";
		break;

	case 3281:
		prot = "sysopt";
		break;

	case 3282:
		prot = "datusorb";
		break;

	case 3283:
		prot = "net-assistant";
		break;

	case 3284:
		prot = "4talk";
		break;

	case 3285:
		prot = "plato";
		break;

	case 3286:
		prot = "e-net";
		break;

	case 3287:
		prot = "directvdata";
		break;

	case 3288:
		prot = "cops";
		break;

	case 3289:
		prot = "enpc";
		break;

	case 3290:
		prot = "caps-lm";
		break;

	case 3291:
		prot = "sah-lm";
		break;

	case 3292:
		prot = "cart-o-rama";
		break;

	case 3293:
		prot = "fg-fps";
		break;

	case 3294:
		prot = "fg-gip";
		break;

	case 3295:
		prot = "dyniplookup";
		break;

	case 3296:
		prot = "rib-slm";
		break;

	case 3297:
		prot = "cytel-lm";
		break;

	case 3298:
		prot = "deskview";
		break;

	case 3299:
		prot = "pdrncs";
		break;

	case 3302:
		prot = "mcs-fastmail";
		break;

	case 3303:
		prot = "opsession-clnt";
		break;

	case 3304:
		prot = "opsession-srvr";
		break;

	case 3305:
		prot = "odette-ftp";
		break;

	case 3306:
		prot = "mysql";
		break;

	case 3307:
		prot = "opsession-prxy";
		break;

	case 3308:
		prot = "tns-server";
		break;

	case 3309:
		prot = "tns-adv";
		break;

	case 3310:
		prot = "dyna-access";
		break;

	case 3311:
		prot = "mcns-tel-ret";
		break;

	case 3312:
		prot = "appman-server";
		break;

	case 3313:
		prot = "uorb";
		break;

	case 3314:
		prot = "uohost";
		break;

	case 3315:
		prot = "cdid";
		break;

	case 3316:
		prot = "aicc-cmi";
		break;

	case 3317:
		prot = "vsaiport";
		break;

	case 3318:
		prot = "ssrip";
		break;

	case 3319:
		prot = "sdt-lmd";
		break;

	case 3320:
		prot = "officelink2000";
		break;

	case 3321:
		prot = "vnsstr";
		break;

	case 3326:
		prot = "sftu";
		break;

	case 3327:
		prot = "bbars";
		break;

	case 3328:
		prot = "egptlm";
		break;

	case 3329:
		prot = "hp-device-disc";
		break;

	case 3330:
		prot = "mcs-calypsoicf";
		break;

	case 3331:
		prot = "mcs-messaging";
		break;

	case 3332:
		prot = "mcs-mailsvr";
		break;

	case 3333:
		prot = "dec-notes";
		break;

	case 3334:
		prot = "directv-web";
		break;

	case 3335:
		prot = "directv-soft";
		break;

	case 3336:
		prot = "directv-tick";
		break;

	case 3337:
		prot = "directv-catlg";
		break;

	case 3338:
		prot = "anet-b";
		break;

	case 3339:
		prot = "anet-l";
		break;

	case 3340:
		prot = "anet-m";
		break;

	case 3341:
		prot = "anet-h";
		break;

	case 3342:
		prot = "webtie";
		break;

	case 3343:
		prot = "ms-cluster-net";
		break;

	case 3344:
		prot = "bnt-manager";
		break;

	case 3345:
		prot = "influence";
		break;

	case 3346:
		prot = "trnsprntproxy";
		break;

	case 3347:
		prot = "phoenix-rpc";
		break;

	case 3348:
		prot = "pangolin-laser";
		break;

	case 3349:
		prot = "chevinservices";
		break;

	case 3350:
		prot = "findviatv";
		break;

	case 3351:
		prot = "btrieve";
		break;

	case 3352:
		prot = "ssql";
		break;

	case 3353:
		prot = "fatpipe";
		break;

	case 3354:
		prot = "suitjd";
		break;

	case 3355:
		prot = "ordinox-dbase";
		break;

	case 3356:
		prot = "upnotifyps";
		break;

	case 3357:
		prot = "adtech-test";
		break;

	case 3358:
		prot = "mpsysrmsvr";
		break;

	case 3359:
		prot = "wg-netforce";
		break;

	case 3360:
		prot = "kv-server";
		break;

	case 3361:
		prot = "kv-agent";
		break;

	case 3362:
		prot = "dj-ilm";
		break;

	case 3363:
		prot = "nati-vi-server";
		break;

	case 3364:
		prot = "creativeserver";
		break;

	case 3365:
		prot = "contentserver";
		break;

	case 3366:
		prot = "creativepartnr";
		break;

	case 3372:
		prot = "tip2";
		break;

	case 3373:
		prot = "lavenir-lm";
		break;

	case 3374:
		prot = "cluster-disc";
		break;

	case 3375:
		prot = "vsnm-agent";
		break;

	case 3376:
		prot = "cdbroker";
		break;

	case 3377:
		prot = "cogsys-lm";
		break;

	case 3378:
		prot = "wsicopy";
		break;

	case 3379:
		prot = "socorfs";
		break;

	case 3380:
		prot = "sns-channels";
		break;

	case 3381:
		prot = "geneous";
		break;

	case 3382:
		prot = "fujitsu-neat";
		break;

	case 3383:
		prot = "esp-lm";
		break;

	case 3384:
		prot = "hp-clic";
		break;

	case 3385:
		prot = "qnxnetman";
		break;

	case 3386:
		prot = "gprs-data Or gprs-sig";
		break;

	case 3387:
		prot = "backroomnet";
		break;

	case 3388:
		prot = "cbserver";
		break;

	case 3389:
		prot = "ms-wbt-server";
		break;

	case 3390:
		prot = "dsc";
		break;

	case 3391:
		prot = "savant";
		break;

	case 3392:
		prot = "efi-lm";
		break;

	case 3393:
		prot = "d2k-tapestry1";
		break;

	case 3394:
		prot = "d2k-tapestry2";
		break;

	case 3395:
		prot = "dyna-lm";
		break;

	case 3396:
		prot = "printer_agent";
		break;

	case 3397:
		prot = "cloanto-lm";
		break;

	case 3398:
		prot = "mercantile";
		break;

	case 3399:
		prot = "csms";
		break;

	case 3400:
		prot = "csms2";
		break;

	case 3401:
		prot = "filecast";
		break;

	case 3402:
		prot = "fxaengine-net";
		break;

	case 3403:
		prot = "copysnap";
		break;

	case 3405:
		prot = "nokia-ann-ch1";
		break;

	case 3406:
		prot = "nokia-ann-ch2";
		break;

	case 3407:
		prot = "ldap-admin";
		break;

	case 3408:
		prot = "issapi";
		break;

	case 3409:
		prot = "networklens";
		break;

	case 3410:
		prot = "networklenss";
		break;

	case 3411:
		prot = "biolink-auth";
		break;

	case 3412:
		prot = "xmlblaster";
		break;

	case 3413:
		prot = "svnet";
		break;

	case 3414:
		prot = "wip-port";
		break;

	case 3415:
		prot = "bcinameservice";
		break;

	case 3416:
		prot = "commandport";
		break;

	case 3417:
		prot = "csvr";
		break;

	case 3418:
		prot = "rnmap";
		break;

	case 3419:
		prot = "softaudit";
		break;

	case 3420:
		prot = "ifcp-port";
		break;

	case 3421:
		prot = "bmap";
		break;

	case 3422:
		prot = "rusb-sys-port";
		break;

	case 3423:
		prot = "xtrm";
		break;

	case 3424:
		prot = "xtrms";
		break;

	case 3425:
		prot = "agps-port";
		break;

	case 3426:
		prot = "arkivio";
		break;

	case 3427:
		prot = "websphere-snmp";
		break;

	case 3428:
		prot = "twcss";
		break;

	case 3429:
		prot = "gcsp";
		break;

	case 3430:
		prot = "ssdispatch";
		break;

	case 3431:
		prot = "ndl-als";
		break;

	case 3432:
		prot = "osdcp";
		break;

	case 3433:
		prot = "alta-smp";
		break;

	case 3434:
		prot = "opencm";
		break;

	case 3435:
		prot = "pacom";
		break;

	case 3436:
		prot = "gc-config";
		break;

	case 3437:
		prot = "autocueds";
		break;

	case 3438:
		prot = "spiral-admin";
		break;

	case 3439:
		prot = "hri-port";
		break;

	case 3440:
		prot = "ans-console";
		break;

	case 3441:
		prot = "connect-client";
		break;

	case 3442:
		prot = "connect-server";
		break;

	case 3443:
		prot = "ov-nnm-websrv";
		break;

	case 3444:
		prot = "denali-server";
		break;

	case 3445:
		prot = "monp";
		break;

	case 3446:
		prot = "3comfaxrpc";
		break;

	case 3447:
		prot = "cddn";
		break;

	case 3448:
		prot = "dnc-port";
		break;

	case 3449:
		prot = "hotu-chat";
		break;

	case 3450:
		prot = "castorproxy";
		break;

	case 3451:
		prot = "asam";
		break;

	case 3452:
		prot = "sabp-signal";
		break;

	case 3453:
		prot = "pscupd";
		break;

	case 3454:
		prot = "mira";
		break;

	case 3455:
		prot = "prsvp";
		break;

	case 3456:
		prot = "vat";
		break;

	case 3457:
		prot = "vat-control";
		break;

	case 3458:
		prot = "d3winosfi";
		break;

	case 3459:
		prot = "integral";
		break;

	case 3460:
		prot = "edm-manager";
		break;

	case 3461:
		prot = "edm-stager";
		break;

	case 3462:
		prot = "edm-std-notify";
		break;

	case 3463:
		prot = "edm-adm-notify";
		break;

	case 3464:
		prot = "edm-mgr-sync";
		break;

	case 3465:
		prot = "edm-mgr-cntrl";
		break;

	case 3466:
		prot = "workflow";
		break;

	case 3467:
		prot = "rcst";
		break;

	case 3468:
		prot = "ttcmremotectrl";
		break;

	case 3469:
		prot = "pluribus";
		break;

	case 3470:
		prot = "jt400";
		break;

	case 3471:
		prot = "jt400-ssl";
		break;

	case 3472:
		prot = "jaugsremotec-1";
		break;

	case 3473:
		prot = "jaugsremotec-2";
		break;

	case 3474:
		prot = "ttntspauto";
		break;

	case 3475:
		prot = "genisar-port";
		break;

	case 3476:
		prot = "nppmp";
		break;

	case 3477:
		prot = "ecomm";
		break;

	case 3478:
		prot = "nat-stun-port";
		break;

	case 3479:
		prot = "twrpc";
		break;

	case 3480:
		prot = "plethora";
		break;

	case 3481:
		prot = "cleanerliverc";
		break;

	case 3482:
		prot = "vulture";
		break;

	case 3483:
		prot = "slim-devices";
		break;

	case 3484:
		prot = "gbs-stp";
		break;

	case 3485:
		prot = "celatalk";
		break;

	case 3486:
		prot = "ifsf-hb-port";
		break;

	case 3487:
		prot = "ltc";
		break;

	case 3488:
		prot = "fs-rh-srv";
		break;

	case 3489:
		prot = "dtp-dia";
		break;

	case 3490:
		prot = "colubris";
		break;

	case 3491:
		prot = "swr-port";
		break;

	case 3492:
		prot = "tvdumtray-port";
		break;

	case 3493:
		prot = "nut";
		break;

	case 3494:
		prot = "ibm3494";
		break;

	case 3495:
		prot = "seclayer-tcp";
		break;

	case 3496:
		prot = "seclayer-tls";
		break;

	case 3497:
		prot = "ipether232port";
		break;

	case 3498:
		prot = "dashpas-port";
		break;

	case 3499:
		prot = "sccip-media";
		break;

	case 3500:
		prot = "rtmp-port";
		break;

	case 3501:
		prot = "isoft-p2p";
		break;

	case 3502:
		prot = "avinstalldisc";
		break;

	case 3503:
		prot = "lsp-ping";
		break;

	case 3504:
		prot = "ironstorm";
		break;

	case 3505:
		prot = "ccmcomm";
		break;

	case 3506:
		prot = "apc-3506";
		break;

	case 3507:
		prot = "nesh-broker";
		break;

	case 3508:
		prot = "interactionweb";
		break;

	case 3509:
		prot = "vt-ssl";
		break;

	case 3510:
		prot = "xss-port";
		break;

	case 3511:
		prot = "webmail-2";
		break;

	case 3512:
		prot = "aztec";
		break;

	case 3513:
		prot = "arcpd";
		break;

	case 3514:
		prot = "must-p2p";
		break;

	case 3515:
		prot = "must-backplane";
		break;

	case 3516:
		prot = "smartcard-port";
		break;

	case 3517:
		prot = "802-11-iapp";
		break;

	case 3518:
		prot = "artifact-msg";
		break;

	case 3519:
		prot = "galileo Or nvmsgd";
		break;

	case 3520:
		prot = "galileolog";
		break;

	case 3521:
		prot = "mc3ss";
		break;

	case 3522:
		prot = "nssocketport";
		break;

	case 3523:
		prot = "odeumservlink";
		break;

	case 3524:
		prot = "ecmport";
		break;

	case 3525:
		prot = "eisport";
		break;

	case 3526:
		prot = "starquiz-port";
		break;

	case 3527:
		prot = "beserver-msg-q";
		break;

	case 3528:
		prot = "jboss-iiop";
		break;

	case 3529:
		prot = "jboss-iiop-ssl";
		break;

	case 3530:
		prot = "gf";
		break;

	case 3531:
		prot = "joltid";
		break;

	case 3532:
		prot = "raven-rmp";
		break;

	case 3533:
		prot = "raven-rdp";
		break;

	case 3534:
		prot = "urld-port";
		break;

	case 3535:
		prot = "ms-la";
		break;

	case 3536:
		prot = "snac";
		break;

	case 3537:
		prot = "ni-visa-remote";
		break;

	case 3538:
		prot = "ibm-diradm";
		break;

	case 3539:
		prot = "ibm-diradm-ssl";
		break;

	case 3540:
		prot = "pnrp-port";
		break;

	case 3541:
		prot = "voispeed-port";
		break;

	case 3542:
		prot = "hacl-monitor";
		break;

	case 3543:
		prot = "qftest-lookup";
		break;

	case 3544:
		prot = "teredo";
		break;

	case 3545:
		prot = "camac";
		break;

	case 3547:
		prot = "symantec-sim";
		break;

	case 3548:
		prot = "interworld";
		break;

	case 3549:
		prot = "tellumat-nms";
		break;

	case 3550:
		prot = "ssmpp";
		break;

	case 3551:
		prot = "apcupsd";
		break;

	case 3552:
		prot = "taserver";
		break;

	case 3553:
		prot = "rbr-discovery";
		break;

	case 3554:
		prot = "questnotify";
		break;

	case 3555:
		prot = "razor";
		break;

	case 3556:
		prot = "sky-transport";
		break;

	case 3557:
		prot = "personalos-001";
		break;

	case 3558:
		prot = "mcp-port";
		break;

	case 3559:
		prot = "cctv-port";
		break;

	case 3560:
		prot = "iniserve-port";
		break;

	case 3561:
		prot = "bmc-onekey";
		break;

	case 3562:
		prot = "sdbproxy";
		break;

	case 3563:
		prot = "watcomdebug";
		break;

	case 3564:
		prot = "esimport";
		break;

	case 3565:
		prot = "m2pa";
		break;

	case 3566:
		prot = "quest-launcher";
		break;

	case 3567:
		prot = "emware-oft";
		break;

	case 3568:
		prot = "emware-epss";
		break;

	case 3569:
		prot = "mbg-ctrl";
		break;

	case 3570:
		prot = "mccwebsvr-port";
		break;

	case 3571:
		prot = "megardsvr-port";
		break;

	case 3572:
		prot = "megaregsvrport";
		break;

	case 3573:
		prot = "tag-ups-1";
		break;

	case 3574:
		prot = "dmaf";
		break;

	case 3575:
		prot = "ccm-port";
		break;

	case 3576:
		prot = "cmc-port";
		break;

	case 3577:
		prot = "config-port";
		break;

	case 3578:
		prot = "data-port";
		break;

	case 3579:
		prot = "ttat3lb";
		break;

	case 3580:
		prot = "nati-svrloc";
		break;

	case 3581:
		prot = "kfxaclicensing";
		break;

	case 3582:
		prot = "press";
		break;

	case 3583:
		prot = "canex-watch";
		break;

	case 3584:
		prot = "u-dbap";
		break;

	case 3585:
		prot = "emprise-lls";
		break;

	case 3586:
		prot = "emprise-lsc";
		break;

	case 3587:
		prot = "p2pgroup";
		break;

	case 3588:
		prot = "sentinel";
		break;

	case 3589:
		prot = "isomair";
		break;

	case 3590:
		prot = "wv-csp-sms";
		break;

	case 3591:
		prot = "gtrack-server";
		break;

	case 3592:
		prot = "gtrack-ne";
		break;

	case 3593:
		prot = "bpmd";
		break;

	case 3594:
		prot = "mediaspace";
		break;

	case 3595:
		prot = "shareapp";
		break;

	case 3596:
		prot = "iw-mmogame";
		break;

	case 3597:
		prot = "a14";
		break;

	case 3598:
		prot = "a15";
		break;

	case 3599:
		prot = "quasar-server";
		break;

	case 3600:
		prot = "trap-daemon";
		break;

	case 3601:
		prot = "visinet-gui";
		break;

	case 3602:
		prot = "infiniswitchcl";
		break;

	case 3603:
		prot = "int-rcv-cntrl";
		break;

	case 3604:
		prot = "bmc-jmx-port";
		break;

	case 3605:
		prot = "comcam-io";
		break;

	case 3606:
		prot = "splitlock";
		break;

	case 3607:
		prot = "precise-i3";
		break;

	case 3608:
		prot = "trendchip-dcp";
		break;

	case 3609:
		prot = "cpdi-pidas-cm";
		break;

	case 3610:
		prot = "echonet";
		break;

	case 3611:
		prot = "six-degrees";
		break;

	case 3612:
		prot = "hp-dataprotect";
		break;

	case 3613:
		prot = "alaris-disc";
		break;

	case 3614:
		prot = "sigma-port";
		break;

	case 3615:
		prot = "start-network";
		break;

	case 3616:
		prot = "cd3o-protocol";
		break;

	case 3617:
		prot = "sharp-server";
		break;

	case 3618:
		prot = "aairnet-1";
		break;

	case 3619:
		prot = "aairnet-2";
		break;

	case 3620:
		prot = "ep-pcp";
		break;

	case 3621:
		prot = "ep-nsp";
		break;

	case 3622:
		prot = "ff-lr-port";
		break;

	case 3623:
		prot = "haipe-discover";
		break;

	case 3624:
		prot = "dist-upgrade";
		break;

	case 3625:
		prot = "volley";
		break;

	case 3626:
		prot = "bvcdaemon-port";
		break;

	case 3627:
		prot = "jamserverport";
		break;

	case 3628:
		prot = "ept-machine";
		break;

	case 3629:
		prot = "escvpnet";
		break;

	case 3630:
		prot = "cs-remote-db";
		break;

	case 3631:
		prot = "cs-services";
		break;

	case 3632:
		prot = "distcc";
		break;

	case 3633:
		prot = "wacp";
		break;

	case 3634:
		prot = "hlibmgr";
		break;

	case 3635:
		prot = "sdo";
		break;

	case 3636:
		prot = "opscenter";
		break;

	case 3637:
		prot = "scservp";
		break;

	case 3638:
		prot = "ehp-backup";
		break;

	case 3639:
		prot = "xap-ha";
		break;

	case 3640:
		prot = "netplay-port1";
		break;

	case 3641:
		prot = "netplay-port2";
		break;

	case 3642:
		prot = "juxml-port";
		break;

	case 3643:
		prot = "audiojuggler";
		break;

	case 3644:
		prot = "ssowatch";
		break;

	case 3645:
		prot = "cyc";
		break;

	case 3646:
		prot = "xss-srv-port";
		break;

	case 3647:
		prot = "splitlock-gw";
		break;

	case 3648:
		prot = "fjcp";
		break;

	case 3649:
		prot = "nmmp";
		break;

	case 3650:
		prot = "prismiq-plugin";
		break;

	case 3651:
		prot = "xrpc-registry";
		break;

	case 3652:
		prot = "vxcrnbuport";
		break;

	case 3653:
		prot = "tsp";
		break;

	case 3654:
		prot = "vaprtm";
		break;

	case 3655:
		prot = "abatemgr";
		break;

	case 3656:
		prot = "abatjss";
		break;

	case 3657:
		prot = "immedianet-bcn";
		break;

	case 3658:
		prot = "ps-ams";
		break;

	case 3659:
		prot = "apple-sasl";
		break;

	case 3660:
		prot = "can-nds-ssl";
		break;

	case 3661:
		prot = "can-ferret-ssl";
		break;

	case 3662:
		prot = "pserver";
		break;

	case 3663:
		prot = "dtp";
		break;

	case 3664:
		prot = "ups-engine";
		break;

	case 3665:
		prot = "ent-engine";
		break;

	case 3666:
		prot = "eserver-pap";
		break;

	case 3667:
		prot = "infoexch";
		break;

	case 3668:
		prot = "dell-rm-port";
		break;

	case 3669:
		prot = "casanswmgmt";
		break;

	case 3670:
		prot = "smile";
		break;

	case 3671:
		prot = "efcp";
		break;

	case 3672:
		prot = "lispworks-orb";
		break;

	case 3673:
		prot = "mediavault-gui";
		break;

	case 3674:
		prot = "wininstall-ipc";
		break;

	case 3675:
		prot = "calltrax";
		break;

	case 3676:
		prot = "va-pacbase";
		break;

	case 3677:
		prot = "roverlog";
		break;

	case 3678:
		prot = "ipr-dglt";
		break;

	case 3679:
		prot = "newton-dock";
		break;

	case 3680:
		prot = "npds-tracker";
		break;

	case 3681:
		prot = "bts-x73";
		break;

	case 3682:
		prot = "cas-mapi";
		break;

	case 3683:
		prot = "bmc-ea";
		break;

	case 3684:
		prot = "faxstfx-port";
		break;

	case 3685:
		prot = "dsx-agent";
		break;

	case 3686:
		prot = "tnmpv2";
		break;

	case 3687:
		prot = "simple-push";
		break;

	case 3688:
		prot = "simple-push-s";
		break;

	case 3689:
		prot = "daap";
		break;

	case 3690:
		prot = "svn";
		break;

	case 3691:
		prot = "magaya-network";
		break;

	case 3692:
		prot = "intelsync";
		break;

	case 3693:
		prot = "gttp";
		break;

	case 3694:
		prot = "vpncpp";
		break;

	case 3695:
		prot = "bmc-data-coll";
		break;

	case 3696:
		prot = "telnetcpcd";
		break;

	case 3697:
		prot = "nw-license";
		break;

	case 3698:
		prot = "sagectlpanel";
		break;

	case 3699:
		prot = "kpn-icw";
		break;

	case 3700:
		prot = "lrs-paging";
		break;

	case 3701:
		prot = "netcelera";
		break;

	case 3702:
		prot = "upnp-discovery";
		break;

	case 3703:
		prot = "adobeserver-3";
		break;

	case 3704:
		prot = "adobeserver-4";
		break;

	case 3705:
		prot = "adobeserver-5";
		break;

	case 3706:
		prot = "rt-event";
		break;

	case 3707:
		prot = "rt-event-s";
		break;

	case 3708:
		prot = "sun-as-iiops";
		break;

	case 3709:
		prot = "ca-idms";
		break;

	case 3710:
		prot = "portgate-auth";
		break;

	case 3711:
		prot = "edb-server2";
		break;

	case 3712:
		prot = "sentinel-ent";
		break;

	case 3713:
		prot = "tftps";
		break;

	case 3714:
		prot = "delos-dms";
		break;

	case 3715:
		prot = "anoto-rendezv";
		break;

	case 3716:
		prot = "wv-csp-sms-cir";
		break;

	case 3717:
		prot = "wv-csp-udp-cir";
		break;

	case 3718:
		prot = "opus-services";
		break;

	case 3719:
		prot = "itelserverport";
		break;

	case 3720:
		prot = "ufastro-instr";
		break;

	case 3721:
		prot = "xsync";
		break;

	case 3722:
		prot = "xserveraid";
		break;

	case 3723:
		prot = "sychrond";
		break;

	case 3724:
		prot = "battlenet";
		break;

	case 3725:
		prot = "na-er-tip";
		break;

	case 3726:
		prot = "array-manager";
		break;

	case 3727:
		prot = "e-mdu";
		break;

	case 3728:
		prot = "e-woa";
		break;

	case 3729:
		prot = "fksp-audit";
		break;

	case 3730:
		prot = "client-ctrl";
		break;

	case 3731:
		prot = "smap";
		break;

	case 3732:
		prot = "m-wnn";
		break;

	case 3733:
		prot = "multip-msg";
		break;

	case 3734:
		prot = "synel-data";
		break;

	case 3735:
		prot = "pwdis";
		break;

	case 3736:
		prot = "rs-rmi";
		break;

	case 3738:
		prot = "versatalk";
		break;

	case 3739:
		prot = "launchbird-lm";
		break;

	case 3740:
		prot = "heartbeat";
		break;

	case 3741:
		prot = "wysdma";
		break;

	case 3742:
		prot = "cst-port";
		break;

	case 3743:
		prot = "ipcs-command";
		break;

	case 3744:
		prot = "sasg";
		break;

	case 3745:
		prot = "gw-call-port";
		break;

	case 3746:
		prot = "linktest";
		break;

	case 3747:
		prot = "linktest-s";
		break;

	case 3748:
		prot = "webdata";
		break;

	case 3749:
		prot = "cimtrak";
		break;

	case 3750:
		prot = "cbos-ip-port";
		break;

	case 3751:
		prot = "gprs-cube";
		break;

	case 3752:
		prot = "vipremoteagent";
		break;

	case 3753:
		prot = "nattyserver";
		break;

	case 3754:
		prot = "timestenbroker";
		break;

	case 3755:
		prot = "sas-remote-hlp";
		break;

	case 3756:
		prot = "canon-capt";
		break;

	case 3757:
		prot = "grf-port";
		break;

	case 3758:
		prot = "apw-registry";
		break;

	case 3759:
		prot = "exapt-lmgr";
		break;

	case 3760:
		prot = "adtempusclient";
		break;

	case 3761:
		prot = "gsakmp";
		break;

	case 3762:
		prot = "gbs-smp";
		break;

	case 3763:
		prot = "xo-wave";
		break;

	case 3764:
		prot = "mni-prot-rout";
		break;

	case 3765:
		prot = "rtraceroute";
		break;

	case 3767:
		prot = "listmgr-port";
		break;

	case 3768:
		prot = "rblcheckd";
		break;

	case 3769:
		prot = "haipe-otnk";
		break;

	case 3770:
		prot = "cindycollab";
		break;

	case 3771:
		prot = "paging-port";
		break;

	case 3772:
		prot = "ctp";
		break;

	case 3773:
		prot = "ctdhercules";
		break;

	case 3774:
		prot = "zicom";
		break;

	case 3775:
		prot = "ispmmgr";
		break;

	case 3776:
		prot = "dvcprov-port";
		break;

	case 3777:
		prot = "jibe-eb";
		break;

	case 3778:
		prot = "c-h-it-port";
		break;

	case 3779:
		prot = "cognima";
		break;

	case 3780:
		prot = "nnp";
		break;

	case 3781:
		prot = "abcvoice-port";
		break;

	case 3782:
		prot = "iso-tp0s";
		break;

	case 3783:
		prot = "bim-pem";
		break;

	case 3784:
		prot = "bfd-control";
		break;

	case 3785:
		prot = "bfd-echo";
		break;

	case 3786:
		prot = "upstriggervsw";
		break;

	case 3787:
		prot = "fintrx";
		break;

	case 3788:
		prot = "isrp-port";
		break;

	case 3789:
		prot = "remotedeploy";
		break;

	case 3790:
		prot = "quickbooksrds";
		break;

	case 3791:
		prot = "tvnetworkvideo";
		break;

	case 3792:
		prot = "sitewatch";
		break;

	case 3793:
		prot = "dcsoftware";
		break;

	case 3794:
		prot = "jaus";
		break;

	case 3795:
		prot = "myblast";
		break;

	case 3796:
		prot = "spw-dialer";
		break;

	case 3797:
		prot = "idps";
		break;

	case 3798:
		prot = "minilock";
		break;

	case 3799:
		prot = "radius-dynauth";
		break;

	case 3800:
		prot = "pwgpsi";
		break;

	case 3801:
		prot = "ibm-mgr";
		break;

	case 3802:
		prot = "vhd";
		break;

	case 3803:
		prot = "soniqsync";
		break;

	case 3804:
		prot = "iqnet-port";
		break;

	case 3805:
		prot = "tcpdataserver";
		break;

	case 3806:
		prot = "wsmlb";
		break;

	case 3807:
		prot = "spugna";
		break;

	case 3808:
		prot = "sun-as-iiops-ca";
		break;

	case 3809:
		prot = "apocd";
		break;

	case 3810:
		prot = "wlanauth";
		break;

	case 3811:
		prot = "amp";
		break;

	case 3812:
		prot = "neto-wol-server";
		break;

	case 3813:
		prot = "rap-ip";
		break;

	case 3814:
		prot = "neto-dcs";
		break;

	case 3815:
		prot = "lansurveyorxml";
		break;

	case 3816:
		prot = "sunlps-http";
		break;

	case 3817:
		prot = "tapeware";
		break;

	case 3818:
		prot = "crinis-hb";
		break;

	case 3819:
		prot = "epl-slp";
		break;

	case 3820:
		prot = "scp";
		break;

	case 3821:
		prot = "pmcp";
		break;

	case 3822:
		prot = "acp-discovery";
		break;

	case 3823:
		prot = "acp-conduit";
		break;

	case 3824:
		prot = "acp-policy";
		break;

	case 3831:
		prot = "dvapps";
		break;

	case 3832:
		prot = "xxnetserver";
		break;

	case 3833:
		prot = "aipn-auth";
		break;

	case 3834:
		prot = "spectardata";
		break;

	case 3835:
		prot = "spectardb";
		break;

	case 3836:
		prot = "markem-dcp";
		break;

	case 3837:
		prot = "mkm-discovery";
		break;

	case 3838:
		prot = "sos";
		break;

	case 3839:
		prot = "amx-rms";
		break;

	case 3840:
		prot = "flirtmitmir";
		break;

	case 3841:
		prot = "zfirm-shiprush3";
		break;

	case 3842:
		prot = "nhci";
		break;

	case 3843:
		prot = "quest-agent";
		break;

	case 3844:
		prot = "rnm";
		break;

	case 3845:
		prot = "v-one-spp";
		break;

	case 3846:
		prot = "an-pcp";
		break;

	case 3847:
		prot = "msfw-control";
		break;

	case 3848:
		prot = "item";
		break;

	case 3849:
		prot = "spw-dnspreload";
		break;

	case 3850:
		prot = "qtms-bootstrap";
		break;

	case 3851:
		prot = "spectraport";
		break;

	case 3852:
		prot = "sse-app-config";
		break;

	case 3853:
		prot = "sscan";
		break;

	case 3854:
		prot = "stryker-com";
		break;

	case 3855:
		prot = "opentrac";
		break;

	case 3856:
		prot = "informer";
		break;

	case 3857:
		prot = "trap-port";
		break;

	case 3858:
		prot = "trap-port-mom";
		break;

	case 3859:
		prot = "nav-port";
		break;

	case 3860:
		prot = "sasp";
		break;

	case 3861:
		prot = "winshadow-hd";
		break;

	case 3862:
		prot = "giga-pocket";
		break;

	case 3863:
		prot = "asap";
		break;

	case 3864:
		prot = "asap-tcp-tls";
		break;

	case 3865:
		prot = "xpl";
		break;

	case 3866:
		prot = "dzdaemon";
		break;

	case 3867:
		prot = "dzoglserver";
		break;

	case 3868:
		prot = "diameter";
		break;

	case 3869:
		prot = "ovsam-mgmt";
		break;

	case 3870:
		prot = "ovsam-d-agent";
		break;

	case 3871:
		prot = "avocent-adsap";
		break;

	case 3872:
		prot = "oem-agent";
		break;

	case 3873:
		prot = "fagordnc";
		break;

	case 3874:
		prot = "sixxsconfig";
		break;

	case 3875:
		prot = "pnbscada";
		break;

	case 3876:
		prot = "dl_agent";
		break;

	case 3877:
		prot = "xmpcr-interface";
		break;

	case 3878:
		prot = "fotogcad";
		break;

	case 3879:
		prot = "appss-lm";
		break;

	case 3880:
		prot = "igrs";
		break;

	case 3881:
		prot = "idac";
		break;

	case 3882:
		prot = "msdts1";
		break;

	case 3883:
		prot = "vrpn";
		break;

	case 3884:
		prot = "softrack-meter";
		break;

	case 3885:
		prot = "topflow-ssl";
		break;

	case 3886:
		prot = "nei-management";
		break;

	case 3887:
		prot = "ciphire-data";
		break;

	case 3888:
		prot = "ciphire-serv";
		break;

	case 3889:
		prot = "dandv-tester";
		break;

	case 3890:
		prot = "ndsconnect";
		break;

	case 3891:
		prot = "rtc-pm-port";
		break;

	case 3892:
		prot = "pcc-image-port";
		break;

	case 3893:
		prot = "cgi-starapi";
		break;

	case 3894:
		prot = "syam-agent";
		break;

	case 3895:
		prot = "syam-smc";
		break;

	case 3896:
		prot = "sdo-tls";
		break;

	case 3897:
		prot = "sdo-ssh";
		break;

	case 3898:
		prot = "senip";
		break;

	case 3899:
		prot = "itv-control";
		break;

	case 3900:
		prot = "udt_os";
		break;

	case 3901:
		prot = "nimsh";
		break;

	case 3902:
		prot = "nimaux";
		break;

	case 3903:
		prot = "charsetmgr";
		break;

	case 3904:
		prot = "omnilink-port";
		break;

	case 3905:
		prot = "mupdate";
		break;

	case 3906:
		prot = "topovista-data";
		break;

	case 3907:
		prot = "imoguia-port";
		break;

	case 3908:
		prot = "hppronetman";
		break;

	case 3909:
		prot = "surfcontrolcpa";
		break;

	case 3910:
		prot = "prnrequest";
		break;

	case 3911:
		prot = "prnstatus";
		break;

	case 3912:
		prot = "gbmt-stars";
		break;

	case 3913:
		prot = "listcrt-port";
		break;

	case 3914:
		prot = "listcrt-port-2";
		break;

	case 3915:
		prot = "agcat";
		break;

	case 3916:
		prot = "wysdmc";
		break;

	case 3917:
		prot = "aftmux";
		break;

	case 3918:
		prot = "pktcablemmcops";
		break;

	case 3919:
		prot = "hyperip";
		break;

	case 3920:
		prot = "exasoftport1";
		break;

	case 3921:
		prot = "herodotus-net";
		break;

	case 3922:
		prot = "sor-update";
		break;

	case 3923:
		prot = "symb-sb-port";
		break;

	case 3924:
		prot = "mpl-gprs-port";
		break;

	case 3925:
		prot = "zmp";
		break;

	case 3926:
		prot = "winport";
		break;

	case 3927:
		prot = "natdataservice";
		break;

	case 3928:
		prot = "netboot-pxe";
		break;

	case 3929:
		prot = "smauth-port";
		break;

	case 3930:
		prot = "syam-webserver";
		break;

	case 3931:
		prot = "msr-plugin-port";
		break;

	case 3932:
		prot = "dyn-site";
		break;

	case 3933:
		prot = "plbserve-port";
		break;

	case 3934:
		prot = "sunfm-port";
		break;

	case 3935:
		prot = "sdp-portmapper";
		break;

	case 3936:
		prot = "mailprox";
		break;

	case 3937:
		prot = "dvbservdscport";
		break;

	case 3938:
		prot = "dbcontrol_agent";
		break;

	case 3939:
		prot = "aamp";
		break;

	case 3940:
		prot = "xecp-node";
		break;

	case 3941:
		prot = "homeportal-web";
		break;

	case 3942:
		prot = "srdp";
		break;

	case 3943:
		prot = "tig";
		break;

	case 3944:
		prot = "sops";
		break;

	case 3945:
		prot = "emcads";
		break;

	case 3946:
		prot = "backupedge";
		break;

	case 3947:
		prot = "ccp";
		break;

	case 3948:
		prot = "apdap";
		break;

	case 3949:
		prot = "drip";
		break;

	case 3950:
		prot = "namemunge";
		break;

	case 3951:
		prot = "pwgippfax";
		break;

	case 3952:
		prot = "i3-sessionmgr";
		break;

	case 3953:
		prot = "xmlink-connect";
		break;

	case 3954:
		prot = "adrep";
		break;

	case 3955:
		prot = "p2pcommunity";
		break;

	case 3956:
		prot = "gvcp";
		break;

	case 3957:
		prot = "mqe-broker";
		break;

	case 3958:
		prot = "mqe-agent";
		break;

	case 3959:
		prot = "treehopper";
		break;

	case 3960:
		prot = "bess";
		break;

	case 3961:
		prot = "proaxess";
		break;

	case 3962:
		prot = "sbi-agent";
		break;

	case 3963:
		prot = "thrp";
		break;

	case 3964:
		prot = "sasggprs";
		break;

	case 3965:
		prot = "ati-ip-to-ncpe";
		break;

	case 3966:
		prot = "bflckmgr";
		break;

	case 3967:
		prot = "ppsms";
		break;

	case 3968:
		prot = "ianywhere-dbns";
		break;

	case 3969:
		prot = "landmarks";
		break;

	case 3970:
		prot = "lanrevagent";
		break;

	case 3971:
		prot = "lanrevserver";
		break;

	case 3972:
		prot = "iconp";
		break;

	case 3973:
		prot = "progistics";
		break;

	case 3974:
		prot = "citysearch";
		break;

	case 3975:
		prot = "airshot";
		break;

	case 3976:
		prot = "opswagent";
		break;

	case 3977:
		prot = "opswmanager";
		break;

	case 3978:
		prot = "secure-cfg-svr";
		break;

	case 3979:
		prot = "smwan";
		break;

	case 3980:
		prot = "acms";
		break;

	case 3981:
		prot = "starfish";
		break;

	case 3982:
		prot = "eis";
		break;

	case 3983:
		prot = "eisp";
		break;

	case 3984:
		prot = "mapper-nodemgr";
		break;

	case 3985:
		prot = "mapper-mapethd";
		break;

	case 3986:
		prot = "mapper-ws_ethd";
		break;

	case 3987:
		prot = "centerline";
		break;

	case 3988:
		prot = "dcs-config";
		break;

	case 3989:
		prot = "bv-queryengine";
		break;

	case 3990:
		prot = "bv-is";
		break;

	case 3991:
		prot = "bv-smcsrv";
		break;

	case 3992:
		prot = "bv-ds";
		break;

	case 3993:
		prot = "bv-agent";
		break;

	case 3994:
		prot = "objserver";
		break;

	case 3995:
		prot = "iss-mgmt-ssl";
		break;

	case 3996:
		prot = "abcsoftware Or abscoftware";
		break;

	case 3997:
		prot = "agentsease-db";
		break;

	case 4000:
		prot = "terabase";
		break;

	case 4001:
		prot = "newoak";
		break;

	case 4002:
		prot = "pxc-spvr-ft";
		break;

	case 4003:
		prot = "pxc-splr-ft";
		break;

	case 4004:
		prot = "pxc-roid";
		break;

	case 4005:
		prot = "pxc-pin";
		break;

	case 4006:
		prot = "pxc-spvr";
		break;

	case 4007:
		prot = "pxc-splr";
		break;

	case 4008:
		prot = "netcheque";
		break;

	case 4009:
		prot = "chimera-hwm";
		break;

	case 4010:
		prot = "samsung-unidex";
		break;

	case 4011:
		prot = "altserviceboot";
		break;

	case 4012:
		prot = "pda-gate";
		break;

	case 4013:
		prot = "acl-manager";
		break;

	case 4014:
		prot = "taiclock";
		break;

	case 4015:
		prot = "talarian-mcast1";
		break;

	case 4016:
		prot = "talarian-mcast2";
		break;

	case 4017:
		prot = "talarian-mcast3";
		break;

	case 4018:
		prot = "talarian-mcast4";
		break;

	case 4019:
		prot = "talarian-mcast5";
		break;

	case 4020:
		prot = "trap";
		break;

	case 4021:
		prot = "nexus-portal";
		break;

	case 4022:
		prot = "dnox";
		break;

	case 4023:
		prot = "esnm-zoning";
		break;

	case 4024:
		prot = "tnp1-port";
		break;

	case 4025:
		prot = "partimage";
		break;

	case 4026:
		prot = "as-debug";
		break;

	case 4027:
		prot = "bxp";
		break;

	case 4028:
		prot = "dtserver-port";
		break;

	case 4029:
		prot = "ip-qsig";
		break;

	case 4030:
		prot = "jdmn-port";
		break;

	case 4031:
		prot = "suucp";
		break;

	case 4032:
		prot = "vrts-auth-port";
		break;

	case 4033:
		prot = "sanavigator";
		break;

	case 4034:
		prot = "ubxd";
		break;

	case 4035:
		prot = "wap-push-http";
		break;

	case 4036:
		prot = "wap-push-https";
		break;

	case 4037:
		prot = "ravehd";
		break;

	case 4038:
		prot = "fazzt-ptp";
		break;

	case 4039:
		prot = "fazzt-admin";
		break;

	case 4040:
		prot = "yo-main";
		break;

	case 4041:
		prot = "houston";
		break;

	case 4042:
		prot = "ldxp";
		break;

	case 4043:
		prot = "nirp";
		break;

	case 4044:
		prot = "ltp";
		break;

	case 4045:
		prot = "npp";
		break;

	case 4046:
		prot = "acp-proto";
		break;

	case 4047:
		prot = "ctp-state";
		break;

	case 4048:
		prot = "objadmin";
		break;

	case 4049:
		prot = "wafs";
		break;

	case 4050:
		prot = "cisco-wafs";
		break;

	case 4051:
		prot = "cppdp";
		break;

	case 4052:
		prot = "interact";
		break;

	case 4053:
		prot = "ccu-comm-1";
		break;

	case 4054:
		prot = "ccu-comm-2";
		break;

	case 4055:
		prot = "ccu-comm-3";
		break;

	case 4056:
		prot = "lms";
		break;

	case 4057:
		prot = "wfm";
		break;

	case 4058:
		prot = "kingfisher";
		break;

	case 4059:
		prot = "dlms-cosem";
		break;

	case 4060:
		prot = "dsmeter_iatc";
		break;

	case 4061:
		prot = "ice-location";
		break;

	case 4062:
		prot = "ice-slocation";
		break;

	case 4063:
		prot = "ice-router";
		break;

	case 4064:
		prot = "ice-srouter";
		break;

	case 4089:
		prot = "opencore";
		break;

	case 4090:
		prot = "omasgport";
		break;

	case 4091:
		prot = "ewinstaller";
		break;

	case 4092:
		prot = "ewdgs";
		break;

	case 4093:
		prot = "pvxpluscs";
		break;

	case 4094:
		prot = "sysrqd";
		break;

	case 4095:
		prot = "xtgui";
		break;

	case 4096:
		prot = "bre";
		break;

	case 4097:
		prot = "patrolview";
		break;

	case 4098:
		prot = "drmsfsd";
		break;

	case 4099:
		prot = "dpcp";
		break;

	case 4100:
		prot = "igo-incognito";
		break;

	case 4101:
		prot = "brlp-0";
		break;

	case 4102:
		prot = "brlp-1";
		break;

	case 4103:
		prot = "brlp-2";
		break;

	case 4104:
		prot = "brlp-3";
		break;

	case 4105:
		prot = "shofarplayer";
		break;

	case 4106:
		prot = "synchronite";
		break;

	case 4107:
		prot = "j-ac";
		break;

	case 4108:
		prot = "accel";
		break;

	case 4111:
		prot = "xgrid";
		break;

	case 4112:
		prot = "apple-vpns-rp";
		break;

	case 4113:
		prot = "aipn-reg";
		break;

	case 4114:
		prot = "jomamqmonitor";
		break;

	case 4115:
		prot = "cds";
		break;

	case 4116:
		prot = "smartcard-tls";
		break;

	case 4117:
		prot = "xmlivestream";
		break;

	case 4118:
		prot = "netscript";
		break;

	case 4119:
		prot = "assuria-slm";
		break;

	case 4120:
		prot = "xtreamx";
		break;

	case 4121:
		prot = "e-builder";
		break;

	case 4122:
		prot = "fprams";
		break;

	case 4132:
		prot = "nuts_dem";
		break;

	case 4133:
		prot = "nuts_bootp";
		break;

	case 4134:
		prot = "nifty-hmi";
		break;

	case 4135:
		prot = "cl-db-attach";
		break;

	case 4136:
		prot = "cl-db-request";
		break;

	case 4137:
		prot = "cl-db-remote";
		break;

	case 4138:
		prot = "nettest";
		break;

	case 4139:
		prot = "thrtx";
		break;

	case 4140:
		prot = "cedros_fds";
		break;

	case 4141:
		prot = "oirtgsvc";
		break;

	case 4142:
		prot = "oidocsvc";
		break;

	case 4143:
		prot = "oidsr";
		break;

	case 4145:
		prot = "vvr-control";
		break;

	case 4146:
		prot = "tgcconnect";
		break;

	case 4147:
		prot = "vrxpservman";
		break;

	case 4154:
		prot = "atlinks";
		break;

	case 4159:
		prot = "nss";
		break;

	case 4160:
		prot = "jini-discovery";
		break;

	case 4161:
		prot = "omscontact";
		break;

	case 4162:
		prot = "omstopology";
		break;

	case 4199:
		prot = "eims-admin";
		break;

	case 4300:
		prot = "corelccam";
		break;

	case 4301:
		prot = "d-data";
		break;

	case 4302:
		prot = "d-data-control";
		break;

	case 4320:
		prot = "fdt-rcatp";
		break;

	case 4321:
		prot = "rwhois";
		break;

	case 4325:
		prot = "geognosisman";
		break;

	case 4326:
		prot = "geognosis";
		break;

	case 4343:
		prot = "unicall";
		break;

	case 4344:
		prot = "vinainstall";
		break;

	case 4345:
		prot = "m4-network-as";
		break;

	case 4346:
		prot = "elanlm";
		break;

	case 4347:
		prot = "lansurveyor";
		break;

	case 4348:
		prot = "itose";
		break;

	case 4349:
		prot = "fsportmap";
		break;

	case 4350:
		prot = "net-device";
		break;

	case 4351:
		prot = "plcy-net-svcs";
		break;

	case 4352:
		prot = "pjlink";
		break;

	case 4353:
		prot = "f5-iquery";
		break;

	case 4354:
		prot = "qsnet-trans";
		break;

	case 4355:
		prot = "qsnet-workst";
		break;

	case 4356:
		prot = "qsnet-assist";
		break;

	case 4357:
		prot = "qsnet-cond";
		break;

	case 4358:
		prot = "qsnet-nucl";
		break;

	case 4368:
		prot = "wxbrief";
		break;

	case 4369:
		prot = "epmd";
		break;

	case 4400:
		prot = "ds-srv";
		break;

	case 4401:
		prot = "ds-srvr";
		break;

	case 4402:
		prot = "ds-clnt";
		break;

	case 4403:
		prot = "ds-user";
		break;

	case 4404:
		prot = "ds-admin";
		break;

	case 4405:
		prot = "ds-mail";
		break;

	case 4406:
		prot = "ds-slp";
		break;

	case 4426:
		prot = "beacon-port-2";
		break;

	case 4442:
		prot = "saris";
		break;

	case 4443:
		prot = "pharos";
		break;

	case 4444:
		prot = "krb524 Or nv-video";
		break;

	case 4445:
		prot = "upnotifyp";
		break;

	case 4446:
		prot = "n1-fwp";
		break;

	case 4447:
		prot = "n1-rmgmt";
		break;

	case 4448:
		prot = "asc-slmd";
		break;

	case 4449:
		prot = "privatewire";
		break;

	case 4450:
		prot = "camp";
		break;

	case 4451:
		prot = "ctisystemmsg";
		break;

	case 4452:
		prot = "ctiprogramload";
		break;

	case 4453:
		prot = "nssalertmgr";
		break;

	case 4454:
		prot = "nssagentmgr";
		break;

	case 4455:
		prot = "prchat-user";
		break;

	case 4456:
		prot = "prchat-server";
		break;

	case 4457:
		prot = "prRegister";
		break;

	case 4458:
		prot = "mcp";
		break;

	case 4484:
		prot = "hpssmgmt";
		break;

	case 4500:
		prot = "ipsec-msft";
		break;

	case 4535:
		prot = "ehs";
		break;

	case 4536:
		prot = "ehs-ssl";
		break;

	case 4537:
		prot = "wssauthsvc";
		break;

	case 4538:
		prot = "isigate";
		break;

	case 4545:
		prot = "worldscores";
		break;

	case 4546:
		prot = "sf-lm";
		break;

	case 4547:
		prot = "lanner-lm";
		break;

	case 4548:
		prot = "synchromesh";
		break;

	case 4549:
		prot = "aegate";
		break;

	case 4550:
		prot = "gds-adppiw-db";
		break;

	case 4554:
		prot = "msfrs";
		break;

	case 4555:
		prot = "rsip";
		break;

	case 4556:
		prot = "dtn-bundle";
		break;

	case 4559:
		prot = "hylafax";
		break;

	case 4566:
		prot = "kwtc";
		break;

	case 4567:
		prot = "tram";
		break;

	case 4568:
		prot = "bmc-reporting";
		break;

	case 4569:
		prot = "iax";
		break;

	case 4597:
		prot = "a21-an-1xbs";
		break;

	case 4598:
		prot = "a16-an-an";
		break;

	case 4599:
		prot = "a17-an-an";
		break;

	case 4600:
		prot = "piranha1";
		break;

	case 4601:
		prot = "piranha2";
		break;

	case 4658:
		prot = "playsta2-app";
		break;

	case 4659:
		prot = "playsta2-lob";
		break;

	case 4660:
		prot = "smaclmgr";
		break;

	case 4661:
		prot = "kar2ouche";
		break;

	case 4662:
		prot = "oms";
		break;

	case 4663:
		prot = "noteit";
		break;

	case 4664:
		prot = "ems";
		break;

	case 4665:
		prot = "contclientms";
		break;

	case 4666:
		prot = "eportcomm";
		break;

	case 4667:
		prot = "mmacomm";
		break;

	case 4668:
		prot = "mmaeds";
		break;

	case 4669:
		prot = "eportcommdata";
		break;

	case 4670:
		prot = "light";
		break;

	case 4671:
		prot = "acter";
		break;

	case 4672:
		prot = "rfa";
		break;

	case 4673:
		prot = "cxws";
		break;

	case 4674:
		prot = "appiq-mgmt";
		break;

	case 4675:
		prot = "dhct-status";
		break;

	case 4676:
		prot = "dhct-alerts";
		break;

	case 4677:
		prot = "bcs";
		break;

	case 4678:
		prot = "traversal";
		break;

	case 4679:
		prot = "mgesupervision";
		break;

	case 4680:
		prot = "mgemanagement";
		break;

	case 4681:
		prot = "parliant";
		break;

	case 4682:
		prot = "finisar";
		break;

	case 4683:
		prot = "spike";
		break;

	case 4684:
		prot = "rfid-rp1";
		break;

	case 4685:
		prot = "autopac";
		break;

	case 4686:
		prot = "msp-os";
		break;

	case 4687:
		prot = "nst";
		break;

	case 4688:
		prot = "mobile-p2p";
		break;

	case 4689:
		prot = "altovacentral";
		break;

	case 4690:
		prot = "prelude";
		break;

	case 4691:
		prot = "monotone";
		break;

	case 4692:
		prot = "conspiracy";
		break;

	case 4700:
		prot = "netxms-agent";
		break;

	case 4701:
		prot = "netxms-mgmt";
		break;

	case 4702:
		prot = "netxms-sync";
		break;

	case 4728:
		prot = "capmux";
		break;

	case 4737:
		prot = "ipdr-sp";
		break;

	case 4738:
		prot = "solera-lpn";
		break;

	case 4739:
		prot = "ipfix";
		break;

	case 4740:
		prot = "ipfixs";
		break;

	case 4742:
		prot = "sicct Or sicct-sdp";
		break;

	case 4743:
		prot = "openhpid";
		break;

	case 4749:
		prot = "profilemac";
		break;

	case 4750:
		prot = "ssad";
		break;

	case 4751:
		prot = "spocp";
		break;

	case 4752:
		prot = "snap";
		break;

	case 4784:
		prot = "bfd-multi-ctl";
		break;

	case 4800:
		prot = "iims";
		break;

	case 4801:
		prot = "iwec";
		break;

	case 4802:
		prot = "ilss";
		break;

	case 4827:
		prot = "htcp";
		break;

	case 4837:
		prot = "varadero-0";
		break;

	case 4838:
		prot = "varadero-1";
		break;

	case 4839:
		prot = "varadero-2";
		break;

	case 4840:
		prot = "opcua";
		break;

	case 4841:
		prot = "quosa";
		break;

	case 4842:
		prot = "gw-asv";
		break;

	case 4843:
		prot = "opcua-tls";
		break;

	case 4844:
		prot = "gw-log";
		break;

	case 4848:
		prot = "appserv-http";
		break;

	case 4849:
		prot = "appserv-https";
		break;

	case 4850:
		prot = "sun-as-nodeagt";
		break;

	case 4867:
		prot = "unify-debug";
		break;

	case 4868:
		prot = "phrelay";
		break;

	case 4869:
		prot = "phrelaydbg";
		break;

	case 4870:
		prot = "cc-tracking";
		break;

	case 4871:
		prot = "wired";
		break;

	case 4885:
		prot = "abbs";
		break;

	case 4894:
		prot = "lyskom";
		break;

	case 4899:
		prot = "radmin-port";
		break;

	case 4900:
		prot = "hfcs";
		break;

	case 4949:
		prot = "munin";
		break;

	case 4951:
		prot = "pwgwims";
		break;

	case 4952:
		prot = "sagxtsds";
		break;

	case 4969:
		prot = "ccss-qmm";
		break;

	case 4970:
		prot = "ccss-qsm";
		break;

	case 4983:
		prot = "att-intercom";
		break;

	case 4986:
		prot = "mrip";
		break;

	case 4987:
		prot = "smar-se-port1";
		break;

	case 4988:
		prot = "smar-se-port2";
		break;

	case 4989:
		prot = "parallel";
		break;

	case 4999:
		prot = "hfcs-manager";
		break;

	case 5000:
		prot = "commplex-main";
		break;

	case 5001:
		prot = "commplex-link";
		break;

	case 5002:
		prot = "rfe";
		break;

	case 5003:
		prot = "fmpro-internal";
		break;

	case 5004:
		prot = "avt-profile-1";
		break;

	case 5005:
		prot = "avt-profile-2";
		break;

	case 5006:
		prot = "wsm-server";
		break;

	case 5007:
		prot = "wsm-server-ssl";
		break;

	case 5008:
		prot = "synapsis-edge";
		break;

	case 5009:
		prot = "winfs";
		break;

	case 5010:
		prot = "telelpathstart";
		break;

	case 5011:
		prot = "telelpathattack";
		break;

	case 5020:
		prot = "zenginkyo-1";
		break;

	case 5021:
		prot = "zenginkyo-2";
		break;

	case 5022:
		prot = "mice";
		break;

	case 5023:
		prot = "htuilsrv";
		break;

	case 5024:
		prot = "scpi-telnet";
		break;

	case 5025:
		prot = "scpi-raw";
		break;

	case 5026:
		prot = "strexec-d";
		break;

	case 5027:
		prot = "strexec-s";
		break;

	case 5030:
		prot = "surfpass";
		break;

	case 5042:
		prot = "asnaacceler8db";
		break;

	case 5043:
		prot = "swxadmin";
		break;

	case 5044:
		prot = "lxi-evntsvc";
		break;

	case 5049:
		prot = "ivocalize";
		break;

	case 5050:
		prot = "mmcc";
		break;

	case 5051:
		prot = "ita-agent";
		break;

	case 5052:
		prot = "ita-manager";
		break;

	case 5055:
		prot = "unot";
		break;

	case 5056:
		prot = "intecom-ps1";
		break;

	case 5057:
		prot = "intecom-ps2";
		break;

	case 5059:
		prot = "sds";
		break;

	case 5060:
		prot = "sip";
		break;

	case 5061:
		prot = "sip-tls";
		break;

	case 5064:
		prot = "ca-1";
		break;

	case 5065:
		prot = "ca-2";
		break;

	case 5066:
		prot = "stanag-5066";
		break;

	case 5067:
		prot = "authentx";
		break;

	case 5069:
		prot = "i-net-2000-npr";
		break;

	case 5070:
		prot = "vtsas";
		break;

	case 5071:
		prot = "powerschool";
		break;

	case 5072:
		prot = "ayiya";
		break;

	case 5073:
		prot = "tag-pm";
		break;

	case 5074:
		prot = "alesquery";
		break;

	case 5081:
		prot = "sdl-ets";
		break;

	case 5084:
		prot = "llrp";
		break;

	case 5085:
		prot = "encrypted-llrp";
		break;

	case 5093:
		prot = "sentinel-lm";
		break;

	case 5099:
		prot = "sentlm-srv2srv";
		break;

	case 5100:
		prot = "socalia";
		break;

	case 5101:
		prot = "talarian";
		break;

	case 5102:
		prot = "oms-nonsecure";
		break;

	case 5112:
		prot = "pm-cmdsvr";
		break;

	case 5133:
		prot = "nbt-pc";
		break;

	case 5137:
		prot = "ctsd";
		break;

	case 5145:
		prot = "rmonitor_secure";
		break;

	case 5150:
		prot = "atmp";
		break;

	case 5151:
		prot = "esri_sde";
		break;

	case 5152:
		prot = "sde-discovery";
		break;

	case 5154:
		prot = "bzflag";
		break;

	case 5155:
		prot = "asctrl-agent";
		break;

	case 5165:
		prot = "ife_icorp";
		break;

	case 5166:
		prot = "winpcs";
		break;

	case 5167:
		prot = "scte104";
		break;

	case 5168:
		prot = "scte30";
		break;

	case 5190:
		prot = "aol";
		break;

	case 5191:
		prot = "aol-1";
		break;

	case 5192:
		prot = "aol-2";
		break;

	case 5193:
		prot = "aol-3";
		break;

	case 5200:
		prot = "targus-getdata";
		break;

	case 5201:
		prot = "targus-getdata1";
		break;

	case 5202:
		prot = "targus-getdata2";
		break;

	case 5203:
		prot = "targus-getdata3";
		break;

	case 5222:
		prot = "jabber-client";
		break;

	case 5225:
		prot = "hp-server";
		break;

	case 5226:
		prot = "hp-status";
		break;

	case 5234:
		prot = "eenet";
		break;

	case 5236:
		prot = "padl2sim";
		break;

	case 5250:
		prot = "igateway";
		break;

	case 5251:
		prot = "caevms";
		break;

	case 5252:
		prot = "movaz-ssc";
		break;

	case 5264:
		prot = "3com-njack-1";
		break;

	case 5265:
		prot = "3com-njack-2";
		break;

	case 5269:
		prot = "jabber-server";
		break;

	case 5272:
		prot = "pk";
		break;

	case 5282:
		prot = "transmit-port";
		break;

	case 5300:
		prot = "hacl-hb";
		break;

	case 5301:
		prot = "hacl-gs";
		break;

	case 5302:
		prot = "hacl-cfg";
		break;

	case 5303:
		prot = "hacl-probe";
		break;

	case 5304:
		prot = "hacl-local";
		break;

	case 5305:
		prot = "hacl-test";
		break;

	case 5306:
		prot = "sun-mc-grp";
		break;

	case 5307:
		prot = "sco-aip";
		break;

	case 5308:
		prot = "cfengine";
		break;

	case 5309:
		prot = "jprinter";
		break;

	case 5310:
		prot = "outlaws";
		break;

	case 5312:
		prot = "permabit-cs";
		break;

	case 5313:
		prot = "rrdp";
		break;

	case 5314:
		prot = "opalis-rbt-ipc";
		break;

	case 5315:
		prot = "hacl-poll";
		break;

	case 5343:
		prot = "kfserver";
		break;

	case 5344:
		prot = "xkotodrcp";
		break;

	case 5351:
		prot = "nat-pmp";
		break;

	case 5352:
		prot = "dns-llq";
		break;

	case 5353:
		prot = "mdns";
		break;

	case 5354:
		prot = "mdnsresponder";
		break;

	case 5355:
		prot = "llmnr";
		break;

	case 5356:
		prot = "ms-smlbiz";
		break;

	case 5357:
		prot = "wsdapi";
		break;

	case 5358:
		prot = "wsdapi-s";
		break;

	case 5397:
		prot = "stresstester";
		break;

	case 5398:
		prot = "elektron-admin";
		break;

	case 5399:
		prot = "securitychase";
		break;

	case 5400:
		prot = "excerpt";
		break;

	case 5401:
		prot = "excerpts";
		break;

	case 5402:
		prot = "mftp";
		break;

	case 5403:
		prot = "hpoms-ci-lstn";
		break;

	case 5404:
		prot = "hpoms-dps-lstn";
		break;

	case 5405:
		prot = "netsupport";
		break;

	case 5406:
		prot = "systemics-sox";
		break;

	case 5407:
		prot = "foresyte-clear";
		break;

	case 5408:
		prot = "foresyte-sec";
		break;

	case 5409:
		prot = "salient-dtasrv";
		break;

	case 5410:
		prot = "salient-usrmgr";
		break;

	case 5411:
		prot = "actnet";
		break;

	case 5412:
		prot = "continuus";
		break;

	case 5413:
		prot = "wwiotalk";
		break;

	case 5414:
		prot = "statusd";
		break;

	case 5415:
		prot = "ns-server";
		break;

	case 5416:
		prot = "sns-gateway";
		break;

	case 5417:
		prot = "sns-agent";
		break;

	case 5418:
		prot = "mcntp";
		break;

	case 5419:
		prot = "dj-ice";
		break;

	case 5420:
		prot = "cylink-c";
		break;

	case 5421:
		prot = "netsupport2";
		break;

	case 5422:
		prot = "salient-mux";
		break;

	case 5423:
		prot = "virtualuser";
		break;

	case 5424:
		prot = "beyond-remote";
		break;

	case 5425:
		prot = "br-channel";
		break;

	case 5426:
		prot = "devbasic";
		break;

	case 5427:
		prot = "sco-peer-tta";
		break;

	case 5428:
		prot = "telaconsole";
		break;

	case 5429:
		prot = "base";
		break;

	case 5430:
		prot = "radec-corp";
		break;

	case 5431:
		prot = "park-agent";
		break;

	case 5432:
		prot = "postgresql";
		break;

	case 5433:
		prot = "pyrrho";
		break;

	case 5434:
		prot = "sgi-arrayd";
		break;

	case 5435:
		prot = "dttl";
		break;

	case 5453:
		prot = "surebox";
		break;

	case 5454:
		prot = "apc-5454";
		break;

	case 5455:
		prot = "apc-5455";
		break;

	case 5456:
		prot = "apc-5456";
		break;

	case 5461:
		prot = "silkmeter";
		break;

	case 5462:
		prot = "ttl-publisher";
		break;

	case 5463:
		prot = "ttlpriceproxy";
		break;

	case 5464:
		prot = "quailnet";
		break;

	case 5465:
		prot = "netops-broker";
		break;

	case 5500:
		prot = "fcp-addr-srvr1";
		break;

	case 5501:
		prot = "fcp-addr-srvr2";
		break;

	case 5502:
		prot = "fcp-srvr-inst1";
		break;

	case 5503:
		prot = "fcp-srvr-inst2";
		break;

	case 5504:
		prot = "fcp-cics-gw1";
		break;

	case 5553:
		prot = "sgi-eventmond";
		break;

	case 5554:
		prot = "sgi-esphttp";
		break;

	case 5555:
		prot = "personal-agent";
		break;

	case 5556:
		prot = "freeciv";
		break;

	case 5566:
		prot = "udpplus";
		break;

	case 5567:
		prot = "m-oap";
		break;

	case 5568:
		prot = "sdt";
		break;

	case 5580:
		prot = "tmosms0";
		break;

	case 5581:
		prot = "tmosms1";
		break;

	case 5584:
		prot = "bis-web";
		break;

	case 5585:
		prot = "bis-sync";
		break;

	case 5597:
		prot = "ininmessaging";
		break;

	case 5598:
		prot = "mctfeed";
		break;

	case 5599:
		prot = "esinstall";
		break;

	case 5600:
		prot = "esmmanager";
		break;

	case 5601:
		prot = "esmagent";
		break;

	case 5602:
		prot = "a1-msc";
		break;

	case 5603:
		prot = "a1-bs";
		break;

	case 5604:
		prot = "a3-sdunode";
		break;

	case 5605:
		prot = "a4-sdunode";
		break;

	case 5627:
		prot = "ninaf";
		break;

	case 5629:
		prot = "symantec-sfdb";
		break;

	case 5630:
		prot = "precise-comm";
		break;

	case 5631:
		prot = "pcanywheredata";
		break;

	case 5632:
		prot = "pcanywherestat";
		break;

	case 5633:
		prot = "beorl";
		break;

	case 5672:
		prot = "amqp";
		break;

	case 5673:
		prot = "jms";
		break;

	case 5674:
		prot = "hyperscsi-port";
		break;

	case 5675:
		prot = "v5ua";
		break;

	case 5676:
		prot = "raadmin";
		break;

	case 5677:
		prot = "questdb2-lnchr";
		break;

	case 5678:
		prot = "rrac";
		break;

	case 5679:
		prot = "dccm";
		break;

	case 5680:
		prot = "auriga-router";
		break;

	case 5681:
		prot = "ncxcp";
		break;

	case 5688:
		prot = "ggz";
		break;

	case 5689:
		prot = "qmvideo";
		break;

	case 5713:
		prot = "proshareaudio";
		break;

	case 5714:
		prot = "prosharevideo";
		break;

	case 5715:
		prot = "prosharedata";
		break;

	case 5716:
		prot = "prosharerequest";
		break;

	case 5717:
		prot = "prosharenotify";
		break;

	case 5718:
		prot = "dpm";
		break;

	case 5719:
		prot = "dpm-agent";
		break;

	case 5720:
		prot = "ms-licensing";
		break;

	case 5721:
		prot = "dtpt";
		break;

	case 5722:
		prot = "msdfsr";
		break;

	case 5723:
		prot = "omhs";
		break;

	case 5724:
		prot = "omsdk";
		break;

	case 5729:
		prot = "openmail";
		break;

	case 5730:
		prot = "unieng";
		break;

	case 5741:
		prot = "ida-discover1";
		break;

	case 5742:
		prot = "ida-discover2";
		break;

	case 5743:
		prot = "watchdoc-pod";
		break;

	case 5744:
		prot = "watchdoc";
		break;

	case 5745:
		prot = "fcopy-server";
		break;

	case 5746:
		prot = "fcopys-server";
		break;

	case 5747:
		prot = "tunatic";
		break;

	case 5748:
		prot = "tunalyzer";
		break;

	case 5755:
		prot = "openmailg";
		break;

	case 5757:
		prot = "x500ms";
		break;

	case 5766:
		prot = "openmailns";
		break;

	case 5767:
		prot = "s-openmail";
		break;

	case 5768:
		prot = "openmailpxy";
		break;

	case 5769:
		prot = "spramsca";
		break;

	case 5770:
		prot = "spramsd";
		break;

	case 5771:
		prot = "netagent";
		break;

	case 5777:
		prot = "dali-port";
		break;

	case 5813:
		prot = "icmpd";
		break;

	case 5814:
		prot = "spt-automation";
		break;

	case 5859:
		prot = "wherehoo";
		break;

	case 5863:
		prot = "ppsuitemsg";
		break;

	case 5900:
		prot = "vnc-server";
		break;

	case 5963:
		prot = "indy";
		break;

	case 5968:
		prot = "mppolicy-v5";
		break;

	case 5969:
		prot = "mppolicy-mgr";
		break;

	case 5985:
		prot = "wsman";
		break;

	case 5986:
		prot = "wsmans";
		break;

	case 5987:
		prot = "wbem-rmi";
		break;

	case 5988:
		prot = "wbem-http";
		break;

	case 5989:
		prot = "wbem-https";
		break;

	case 5990:
		prot = "wbem-exp-https";
		break;

	case 5991:
		prot = "nuxsl";
		break;

	case 5992:
		prot = "consul-insight";
		break;

	case 5999:
		prot = "cvsup";
		break;

	case 6064:
		prot = "ndl-ahp-svc";
		break;

	case 6065:
		prot = "winpharaoh";
		break;

	case 6066:
		prot = "ewctsp";
		break;

	case 6067:
		prot = "srb";
		break;

	case 6068:
		prot = "gsmp";
		break;

	case 6069:
		prot = "trip";
		break;

	case 6070:
		prot = "messageasap";
		break;

	case 6071:
		prot = "ssdtp";
		break;

	case 6072:
		prot = "diagnose-proc";
		break;

	case 6073:
		prot = "directplay8";
		break;

	case 6074:
		prot = "max";
		break;

	case 6085:
		prot = "konspire2b";
		break;

	case 6086:
		prot = "pdtp";
		break;

	case 6087:
		prot = "ldss";
		break;

	case 6100:
		prot = "synchronet-db";
		break;

	case 6101:
		prot = "synchronet-rtc";
		break;

	case 6102:
		prot = "synchronet-upd";
		break;

	case 6103:
		prot = "rets";
		break;

	case 6104:
		prot = "dbdb";
		break;

	case 6105:
		prot = "primaserver";
		break;

	case 6106:
		prot = "mpsserver";
		break;

	case 6107:
		prot = "etc-control";
		break;

	case 6108:
		prot = "sercomm-scadmin";
		break;

	case 6109:
		prot = "globecast-id";
		break;

	case 6110:
		prot = "softcm";
		break;

	case 6111:
		prot = "spc";
		break;

	case 6112:
		prot = "dtspcd";
		break;

	case 6122:
		prot = "bex-webadmin";
		break;

	case 6123:
		prot = "backup-express";
		break;

	case 6133:
		prot = "nbt-wol";
		break;

	case 6141:
		prot = "meta-corp";
		break;

	case 6142:
		prot = "aspentec-lm";
		break;

	case 6143:
		prot = "watershed-lm";
		break;

	case 6144:
		prot = "statsci1-lm";
		break;

	case 6145:
		prot = "statsci2-lm";
		break;

	case 6146:
		prot = "lonewolf-lm";
		break;

	case 6147:
		prot = "montage-lm";
		break;

	case 6148:
		prot = "ricardo-lm";
		break;

	case 6149:
		prot = "tal-pod";
		break;

	case 6161:
		prot = "patrol-ism";
		break;

	case 6162:
		prot = "patrol-coll";
		break;

	case 6163:
		prot = "pscribe";
		break;

	case 6200:
		prot = "lm-x";
		break;

	case 6222:
		prot = "radmind";
		break;

	case 6253:
		prot = "crip";
		break;

	case 6268:
		prot = "grid";
		break;

	case 6269:
		prot = "grid-alt";
		break;

	case 6300:
		prot = "bmc-grx";
		break;

	case 6301:
		prot = "bmc_ctd_ldap";
		break;

	case 6320:
		prot = "repsvc";
		break;

	case 6321:
		prot = "emp-server1";
		break;

	case 6322:
		prot = "emp-server2";
		break;

	case 6343:
		prot = "sflow";
		break;

	case 6346:
		prot = "gnutella-svc";
		break;

	case 6347:
		prot = "gnutella-rtr";
		break;

	case 6382:
		prot = "metatude-mds";
		break;

	case 6389:
		prot = "clariion-evr01";
		break;

	case 6417:
		prot = "faxcomservice";
		break;

	case 6420:
		prot = "nim-vdrshell";
		break;

	case 6421:
		prot = "nim-wan";
		break;

	case 6443:
		prot = "sun-sr-https";
		break;

	case 6444:
		prot = "sge_qmaster";
		break;

	case 6445:
		prot = "sge_execd";
		break;

	case 6455:
		prot = "skip-cert-recv";
		break;

	case 6456:
		prot = "skip-cert-send";
		break;

	case 6471:
		prot = "lvision-lm";
		break;

	case 6480:
		prot = "sun-sr-http";
		break;

	case 6484:
		prot = "sun-sr-jms";
		break;

	case 6485:
		prot = "sun-sr-iiop";
		break;

	case 6486:
		prot = "sun-sr-iiops";
		break;

	case 6487:
		prot = "sun-sr-iiop-aut";
		break;

	case 6488:
		prot = "sun-sr-jmx";
		break;

	case 6489:
		prot = "sun-sr-admin";
		break;

	case 6500:
		prot = "boks";
		break;

	case 6501:
		prot = "boks_servc";
		break;

	case 6502:
		prot = "boks_servm";
		break;

	case 6503:
		prot = "boks_clntd";
		break;

	case 6505:
		prot = "badm_priv";
		break;

	case 6506:
		prot = "badm_pub";
		break;

	case 6507:
		prot = "bdir_priv";
		break;

	case 6508:
		prot = "bdir_pub";
		break;

	case 6509:
		prot = "mgcs-mfp-port";
		break;

	case 6510:
		prot = "mcer-port";
		break;

	case 6543:
		prot = "lds-distrib";
		break;

	case 6544:
		prot = "lds-dump";
		break;

	case 6547:
		prot = "apc-6547";
		break;

	case 6548:
		prot = "apc-6548";
		break;

	case 6549:
		prot = "apc-6549";
		break;

	case 6550:
		prot = "fg-sysupdate";
		break;

	case 6558:
		prot = "xdsxdm";
		break;

	case 6566:
		prot = "sane-port";
		break;

	case 6579:
		prot = "affiliate";
		break;

	case 6580:
		prot = "parsec-master";
		break;

	case 6581:
		prot = "parsec-peer";
		break;

	case 6582:
		prot = "parsec-game";
		break;

	case 6583:
		prot = "joaJewelSuite";
		break;

	case 6619:
		prot = "odette-ftps";
		break;

	case 6620:
		prot = "kftp-data";
		break;

	case 6621:
		prot = "kftp";
		break;

	case 6622:
		prot = "mcftp";
		break;

	case 6623:
		prot = "ktelnet";
		break;

	case 6626:
		prot = "wago-service";
		break;

	case 6627:
		prot = "nexgen";
		break;

	case 6628:
		prot = "afesc-mc";
		break;

	case 6631:
		prot = "mach";
		break;

	case 6670:
		prot = "vocaltec-gold";
		break;

	case 6672:
		prot = "vision_server";
		break;

	case 6673:
		prot = "vision_elmd";
		break;

	case 6701:
		prot = "kti-icad-srvr";
		break;

	case 6702:
		prot = "e-design-net";
		break;

	case 6703:
		prot = "e-design-web";
		break;

	case 6714:
		prot = "ibprotocol";
		break;

	case 6715:
		prot = "fibotrader-com";
		break;

	case 6767:
		prot = "bmc-perf-agent";
		break;

	case 6768:
		prot = "bmc-perf-mgrd";
		break;

	case 6769:
		prot = "adi-gxp-srvprt";
		break;

	case 6770:
		prot = "plysrv-http";
		break;

	case 6771:
		prot = "plysrv-https";
		break;

	case 6785:
		prot = "dgpf-exchg";
		break;

	case 6786:
		prot = "smc-jmx";
		break;

	case 6787:
		prot = "smc-admin";
		break;

	case 6788:
		prot = "smc-http";
		break;

	case 6789:
		prot = "smc-https";
		break;

	case 6790:
		prot = "hnmp";
		break;

	case 6791:
		prot = "hnm";
		break;

	case 6831:
		prot = "ambit-lm";
		break;

	case 6841:
		prot = "netmo-default";
		break;

	case 6842:
		prot = "netmo-http";
		break;

	case 6850:
		prot = "iccrushmore";
		break;

	case 6888:
		prot = "muse";
		break;

	case 6936:
		prot = "xsmsvc";
		break;

	case 6946:
		prot = "bioserver";
		break;

	case 6951:
		prot = "otlp";
		break;

	case 6961:
		prot = "jmact3";
		break;

	case 6962:
		prot = "jmevt2";
		break;

	case 6963:
		prot = "swismgr1";
		break;

	case 6964:
		prot = "swismgr2";
		break;

	case 6965:
		prot = "swistrap";
		break;

	case 6966:
		prot = "swispol";
		break;

	case 6969:
		prot = "acmsoda";
		break;

	case 6998:
		prot = "iatp-highpri";
		break;

	case 6999:
		prot = "iatp-normalpri";
		break;

	case 7000:
		prot = "afs3-fileserver";
		break;

	case 7001:
		prot = "afs3-callback";
		break;

	case 7002:
		prot = "afs3-prserver";
		break;

	case 7003:
		prot = "afs3-vlserver";
		break;

	case 7004:
		prot = "afs3-kaserver";
		break;

	case 7005:
		prot = "afs3-volser";
		break;

	case 7006:
		prot = "afs3-errors";
		break;

	case 7007:
		prot = "afs3-bos";
		break;

	case 7008:
		prot = "afs3-update";
		break;

	case 7009:
		prot = "afs3-rmtsys";
		break;

	case 7010:
		prot = "ups-onlinet";
		break;

	case 7011:
		prot = "talon-disc";
		break;

	case 7012:
		prot = "talon-engine";
		break;

	case 7013:
		prot = "microtalon-dis";
		break;

	case 7014:
		prot = "microtalon-com";
		break;

	case 7015:
		prot = "talon-webserver";
		break;

	case 7020:
		prot = "dpserve";
		break;

	case 7021:
		prot = "dpserveadmin";
		break;

	case 7022:
		prot = "ctdp";
		break;

	case 7023:
		prot = "ct2nmcs";
		break;

	case 7024:
		prot = "vmsvc";
		break;

	case 7025:
		prot = "vmsvc-2";
		break;

	case 7030:
		prot = "op-probe";
		break;

	case 7070:
		prot = "arcp OR pnm-pna";
		break;

	case 7099:
		prot = "lazy-ptop";
		break;

	case 7100:
		prot = "font-service";
		break;

	case 7121:
		prot = "virprot-lm";
		break;

	case 7128:
		prot = "scenidm";
		break;

	case 7129:
		prot = "scenccs";
		break;

	case 7161:
		prot = "cabsm-comm";
		break;

	case 7162:
		prot = "caistoragemgr";
		break;

	case 7163:
		prot = "cacsambroker";
		break;

	case 7174:
		prot = "clutild";
		break;

	case 7200:
		prot = "fodms";
		break;

	case 7201:
		prot = "dlip";
		break;

	case 7227:
		prot = "ramp";
		break;

	case 7272:
		prot = "watchme-7272";
		break;

	case 7273:
		prot = "oma-rlp";
		break;

	case 7274:
		prot = "oma-rlp-s";
		break;

	case 7275:
		prot = "oma-ulp";
		break;

	case 7280:
		prot = "itactionserver1";
		break;

	case 7281:
		prot = "itactionserver2";
		break;

	case 7365:
		prot = "lcm-server";
		break;

	case 7391:
		prot = "mindfilesys";
		break;

	case 7392:
		prot = "mrssrendezvous";
		break;

	case 7393:
		prot = "nfoldman";
		break;

	case 7394:
		prot = "fse";
		break;

	case 7395:
		prot = "winqedit";
		break;

	case 7397:
		prot = "hexarc";
		break;

	case 7400:
		prot = "rtps-discovery";
		break;

	case 7401:
		prot = "rtps-dd-ut";
		break;

	case 7402:
		prot = "rtps-dd-mt";
		break;

	case 7410:
		prot = "ionixnetmon";
		break;

	case 7421:
		prot = "mtportmon";
		break;

	case 7426:
		prot = "pmdmgr";
		break;

	case 7427:
		prot = "oveadmgr";
		break;

	case 7428:
		prot = "ovladmgr";
		break;

	case 7429:
		prot = "opi-sock";
		break;

	case 7430:
		prot = "xmpv7";
		break;

	case 7431:
		prot = "pmd";
		break;

	case 7437:
		prot = "faximum";
		break;

	case 7443:
		prot = "oracleas-https";
		break;

	case 7491:
		prot = "telops-lmd";
		break;

	case 7500:
		prot = "silhouette";
		break;

	case 7501:
		prot = "ovbus";
		break;

	case 7510:
		prot = "ovhpas";
		break;

	case 7511:
		prot = "pafec-lm";
		break;

	case 7543:
		prot = "atul";
		break;

	case 7544:
		prot = "nta-ds";
		break;

	case 7545:
		prot = "nta-us";
		break;

	case 7546:
		prot = "cfs";
		break;

	case 7547:
		prot = "cwmp";
		break;

	case 7548:
		prot = "tidp";
		break;

	case 7549:
		prot = "nls-tl";
		break;

	case 7560:
		prot = "sncp";
		break;

	case 7566:
		prot = "vsi-omega";
		break;

	case 7570:
		prot = "aries-kfinder";
		break;

	case 7588:
		prot = "sun-lm";
		break;

	case 7624:
		prot = "indi";
		break;

	case 7626:
		prot = "simco";
		break;

	case 7627:
		prot = "soap-http";
		break;

	case 7628:
		prot = "zen-pawn";
		break;

	case 7629:
		prot = "xdas";
		break;

	case 7633:
		prot = "pmdfmgt";
		break;

	case 7648:
		prot = "cuseeme";
		break;

	case 7674:
		prot = "imqtunnels";
		break;

	case 7675:
		prot = "imqtunnel";
		break;

	case 7676:
		prot = "imqbrokerd";
		break;

	case 7677:
		prot = "sun-user-https";
		break;

	case 7697:
		prot = "klio";
		break;

	case 7707:
		prot = "sync-em7";
		break;

	case 7708:
		prot = "scinet";
		break;

	case 7720:
		prot = "medimageportal";
		break;

	case 7725:
		prot = "nitrogen";
		break;

	case 7726:
		prot = "freezexservice";
		break;

	case 7727:
		prot = "trident-data";
		break;

	case 7738:
		prot = "aiagent";
		break;

	case 7743:
		prot = "sstp-1";
		break;

	case 7744:
		prot = "raqmon-pdu";
		break;

	case 7777:
		prot = "cbt";
		break;

	case 7778:
		prot = "interwise";
		break;

	case 7779:
		prot = "vstat";
		break;

	case 7781:
		prot = "accu-lmgr";
		break;

	case 7786:
		prot = "minivend";
		break;

	case 7787:
		prot = "popup-reminders";
		break;

	case 7789:
		prot = "office-tools";
		break;

	case 7794:
		prot = "q3ade";
		break;

	case 7797:
		prot = "pnet-conn";
		break;

	case 7798:
		prot = "pnet-enc";
		break;

	case 7800:
		prot = "asr";
		break;

	case 7801:
		prot = "ssp-client";
		break;

	case 7845:
		prot = "apc-7845";
		break;

	case 7846:
		prot = "apc-7846";
		break;

	case 7887:
		prot = "ubroker";
		break;

	case 7900:
		prot = "mevent";
		break;

	case 7901:
		prot = "tnos-sp";
		break;

	case 7902:
		prot = "tnos-dp";
		break;

	case 7903:
		prot = "tnos-dps";
		break;

	case 7913:
		prot = "qo-secure";
		break;

	case 7932:
		prot = "t2-drm";
		break;

	case 7933:
		prot = "t2-brm";
		break;

	case 7967:
		prot = "supercell";
		break;

	case 7979:
		prot = "micromuse-ncps";
		break;

	case 7980:
		prot = "quest-vista";
		break;

	case 7999:
		prot = "irdmi2";
		break;

	case 8000:
		prot = "irdmi";
		break;

	case 8001:
		prot = "vcom-tunnel";
		break;

	case 8002:
		prot = "teradataordbms";
		break;

	case 8008:
		prot = "http-alt";
		break;

	case 8020:
		prot = "intu-ec-svcdisc";
		break;

	case 8021:
		prot = "intu-ec-client";
		break;

	case 8022:
		prot = "oa-system";
		break;

	case 8025:
		prot = "ca-audit-da";
		break;

	case 8026:
		prot = "ca-audit-ds";
		break;

	case 8032:
		prot = "pro-ed";
		break;

	case 8033:
		prot = "mindprint";
		break;

	case 8052:
		prot = "senomix01";
		break;

	case 8053:
		prot = "senomix02";
		break;

	case 8054:
		prot = "senomix03";
		break;

	case 8055:
		prot = "senomix04";
		break;

	case 8056:
		prot = "senomix05";
		break;

	case 8057:
		prot = "senomix06";
		break;

	case 8058:
		prot = "senomix07";
		break;

	case 8059:
		prot = "senomix08";
		break;

	case 8074:
		prot = "gadugadu";
		break;

	case 8080:
		prot = "http-alt";
		break;

	case 8081:
		prot = "sunproxyadmin";
		break;

	case 8082:
		prot = "us-cli";
		break;

	case 8083:
		prot = "us-srv";
		break;

	case 8088:
		prot = "radan-http";
		break;

	case 8097:
		prot = "sac";
		break;

	case 8100:
		prot = "xprint-server";
		break;

	case 8115:
		prot = "mtl8000-matrix";
		break;

	case 8116:
		prot = "cp-cluster";
		break;

	case 8118:
		prot = "privoxy";
		break;

	case 8121:
		prot = "apollo-data";
		break;

	case 8122:
		prot = "apollo-admin";
		break;

	case 8128:
		prot = "paycash-online";
		break;

	case 8129:
		prot = "paycash-wbp";
		break;

	case 8130:
		prot = "indigo-vrmi";
		break;

	case 8131:
		prot = "indigo-vbcp";
		break;

	case 8132:
		prot = "dbabble";
		break;

	case 8148:
		prot = "isdd";
		break;

	case 8160:
		prot = "patrol";
		break;

	case 8161:
		prot = "patrol-snmp";
		break;

	case 8192:
		prot = "spytechphone";
		break;

	case 8194:
		prot = "blp1";
		break;

	case 8195:
		prot = "blp2";
		break;

	case 8199:
		prot = "vvr-data";
		break;

	case 8200:
		prot = "trivnet1";
		break;

	case 8201:
		prot = "trivnet2";
		break;

	case 8204:
		prot = "lm-perfworks";
		break;

	case 8205:
		prot = "lm-instmgr";
		break;

	case 8206:
		prot = "lm-dta";
		break;

	case 8207:
		prot = "lm-sserver";
		break;

	case 8208:
		prot = "lm-webwatcher";
		break;

	case 8230:
		prot = "rexecj";
		break;

	case 8292:
		prot = "blp3";
		break;

	case 8294:
		prot = "blp4";
		break;

	case 8300:
		prot = "tmi";
		break;

	case 8301:
		prot = "amberon";
		break;

	case 8351:
		prot = "server-find";
		break;

	case 8376:
		prot = "cruise-enum";
		break;

	case 8377:
		prot = "cruise-swroute";
		break;

	case 8378:
		prot = "cruise-config";
		break;

	case 8379:
		prot = "cruise-diags";
		break;

	case 8380:
		prot = "cruise-update";
		break;

	case 8383:
		prot = "m2mservices";
		break;

	case 8400:
		prot = "cvd";
		break;

	case 8401:
		prot = "sabarsd";
		break;

	case 8402:
		prot = "abarsd";
		break;

	case 8403:
		prot = "admind";
		break;

	case 8416:
		prot = "espeech";
		break;

	case 8417:
		prot = "espeech-rtp";
		break;

	case 8443:
		prot = "pcsync-https";
		break;

	case 8444:
		prot = "pcsync-http";
		break;

	case 8450:
		prot = "npmp";
		break;

	case 8473:
		prot = "vp2p";
		break;

	case 8474:
		prot = "noteshare";
		break;

	case 8500:
		prot = "fmtp";
		break;

	case 8554:
		prot = "rtsp-alt";
		break;

	case 8555:
		prot = "d-fence";
		break;

	case 8567:
		prot = "oap-admin";
		break;

	case 8600:
		prot = "asterix";
		break;

	case 8611:
		prot = "canon-bjnp1";
		break;

	case 8612:
		prot = "canon-bjnp2";
		break;

	case 8613:
		prot = "canon-bjnp3";
		break;

	case 8614:
		prot = "canon-bjnp4";
		break;

	case 8668:
		prot = "natd";
		break;

	case 8686:
		prot = "sun-as-jmxrmi";
		break;

	case 8699:
		prot = "vnyx";
		break;

	case 8733:
		prot = "ibus";
		break;

	case 8763:
		prot = "mc-appserver";
		break;

	case 8764:
		prot = "openqueue";
		break;

	case 8765:
		prot = "ultraseek-http";
		break;

	case 8770:
		prot = "dpap";
		break;

	case 8786:
		prot = "msgclnt";
		break;

	case 8787:
		prot = "msgsrvr";
		break;

	case 8800:
		prot = "sunwebadmin";
		break;

	case 8804:
		prot = "truecm";
		break;

	case 8873:
		prot = "dxspider";
		break;

	case 8880:
		prot = "cddbp-alt";
		break;

	case 8888:
		prot = "ddi";
		break;

	case 8889:
		prot = "ddi";
		break;

	case 8890:
		prot = "ddi";
		break;

	case 8891:
		prot = "ddi";
		break;

	case 8892:
		prot = "ddi";
		break;

	case 8893:
		prot = "ddi";
		break;

	case 8894:
		prot = "ddi";
		break;

	case 8900:
		prot = "jmb-cds1";
		break;

	case 8901:
		prot = "jmb-cds2";
		break;

	case 8910:
		prot = "manyone-http";
		break;

	case 8911:
		prot = "manyone-xml";
		break;

	case 8912:
		prot = "wcbackup";
		break;

	case 8913:
		prot = "dragonfly";
		break;

	case 8954:
		prot = "cumulus-admin";
		break;

	case 8989:
		prot = "sunwebadmins";
		break;

	case 8999:
		prot = "bctp";
		break;

	case 9000:
		prot = "cslistener";
		break;

	case 9001:
		prot = "etlservicemgr";
		break;

	case 9002:
		prot = "dynamid";
		break;

	case 9009:
		prot = "pichat";
		break;

	case 9020:
		prot = "tambora";
		break;

	case 9021:
		prot = "panagolin-ident";
		break;

	case 9022:
		prot = "paragent";
		break;

	case 9023:
		prot = "swa-1";
		break;

	case 9024:
		prot = "swa-2";
		break;

	case 9025:
		prot = "swa-3";
		break;

	case 9026:
		prot = "swa-4";
		break;

	case 9080:
		prot = "glrpc";
		break;

	case 9088:
		prot = "sqlexec";
		break;

	case 9089:
		prot = "sqlexec-ssl";
		break;

	case 9090:
		prot = "websm";
		break;

	case 9091:
		prot = "xmltec-xmlmail";
		break;

	case 9092:
		prot = "XmlIpcRegSvc";
		break;

	case 9100:
		prot = "hp-pdl-datastr Or pdl-datastream";
		break;

	case 9101:
		prot = "bacula-dir";
		break;

	case 9102:
		prot = "bacula-fd";
		break;

	case 9103:
		prot = "bacula-sd";
		break;

	case 9104:
		prot = "peerwire";
		break;

	case 9119:
		prot = "mxit";
		break;

	case 9131:
		prot = "dddp";
		break;

	case 9160:
		prot = "netlock1";
		break;

	case 9161:
		prot = "netlock2";
		break;

	case 9162:
		prot = "netlock3";
		break;

	case 9163:
		prot = "netlock4";
		break;

	case 9164:
		prot = "netlock5";
		break;

	case 9191:
		prot = "sun-as-jpda";
		break;

	case 9200:
		prot = "wap-wsp";
		break;

	case 9201:
		prot = "wap-wsp-wtp";
		break;

	case 9202:
		prot = "wap-wsp-s";
		break;

	case 9203:
		prot = "wap-wsp-wtp-s";
		break;

	case 9204:
		prot = "wap-vcard";
		break;

	case 9205:
		prot = "wap-vcal";
		break;

	case 9206:
		prot = "wap-vcard-s";
		break;

	case 9207:
		prot = "wap-vcal-s";
		break;

	case 9208:
		prot = "rjcdb-vcards";
		break;

	case 9209:
		prot = "almobile-system";
		break;

	case 9210:
		prot = "lif-mlp";
		break;

	case 9211:
		prot = "lif-mlp-s";
		break;

	case 9212:
		prot = "serverviewdbms";
		break;

	case 9213:
		prot = "serverstart";
		break;

	case 9214:
		prot = "ipdcesgbs";
		break;

	case 9215:
		prot = "insis";
		break;

	case 9216:
		prot = "acme";
		break;

	case 9217:
		prot = "fsc-port";
		break;

	case 9222:
		prot = "teamcoherence";
		break;

	case 9281:
		prot = "swtp-port1";
		break;

	case 9282:
		prot = "swtp-port2";
		break;

	case 9283:
		prot = "callwaveiam";
		break;

	case 9284:
		prot = "visd";
		break;

	case 9285:
		prot = "n2h2server";
		break;

	case 9287:
		prot = "cumulus";
		break;

	case 9292:
		prot = "armtechdaemon";
		break;

	case 9293:
		prot = "storview";
		break;

	case 9294:
		prot = "armcenterhttp";
		break;

	case 9295:
		prot = "armcenterhttps";
		break;

	case 9300:
		prot = "vrace";
		break;

	case 9318:
		prot = "secure-ts";
		break;

	case 9321:
		prot = "guibase";
		break;

	case 9343:
		prot = "mpidcmgr";
		break;

	case 9344:
		prot = "mphlpdmc";
		break;

	case 9346:
		prot = "ctechlicensing";
		break;

	case 9374:
		prot = "fjdmimgr";
		break;

	case 9396:
		prot = "fjinvmgr";
		break;

	case 9397:
		prot = "mpidcagt";
		break;

	case 9418:
		prot = "git";
		break;

	case 9443:
		prot = "tungsten-https";
		break;

	case 9500:
		prot = "ismserver";
		break;

	case 9535:
		prot = "mngsuite";
		break;

	case 9555:
		prot = "trispen-sra";
		break;

	case 9592:
		prot = "ldgateway";
		break;

	case 9593:
		prot = "cba8";
		break;

	case 9594:
		prot = "msgsys";
		break;

	case 9595:
		prot = "pds";
		break;

	case 9596:
		prot = "mercury-disc";
		break;

	case 9597:
		prot = "pd-admin";
		break;

	case 9598:
		prot = "vscp";
		break;

	case 9599:
		prot = "robix";
		break;

	case 9600:
		prot = "micromuse-ncpw";
		break;

	case 9612:
		prot = "streamcomm-ds";
		break;

	case 9700:
		prot = "board-roar";
		break;

	case 9747:
		prot = "l5nas-parchan";
		break;

	case 9750:
		prot = "board-voip";
		break;

	case 9753:
		prot = "rasadv";
		break;

	case 9762:
		prot = "tungsten-http";
		break;

	case 9800:
		prot = "davsrc";
		break;

	case 9801:
		prot = "sstp-2";
		break;

	case 9802:
		prot = "davsrcs";
		break;

	case 9875:
		prot = "sapv1";
		break;

	case 9876:
		prot = "sd";
		break;

	case 9888:
		prot = "cyborg-systems";
		break;

	case 9898:
		prot = "monkeycom";
		break;

	case 9899:
		prot = "sctp-tunneling";
		break;

	case 9900:
		prot = "iua";
		break;

	case 9901:
		prot = "enrp";
		break;

	case 9909:
		prot = "domaintime";
		break;

	case 9911:
		prot = "sype-transport";
		break;

	case 9950:
		prot = "apc-9950";
		break;

	case 9951:
		prot = "apc-9951";
		break;

	case 9952:
		prot = "apc-9952";
		break;

	case 9953:
		prot = "acis";
		break;

	case 9966:
		prot = "odnsp";
		break;

	case 9987:
		prot = "dsm-scm-target";
		break;

	case 9990:
		prot = "osm-appsrvr";
		break;

	case 9991:
		prot = "osm-oev";
		break;

	case 9992:
		prot = "palace-1";
		break;

	case 9993:
		prot = "palace-2";
		break;

	case 9994:
		prot = "palace-3";
		break;

	case 9995:
		prot = "palace-4";
		break;

	case 9996:
		prot = "palace-5";
		break;

	case 9997:
		prot = "palace-6";
		break;

	case 9998:
		prot = "distinct32";
		break;

	case 9999:
		prot = "distinct";
		break;

	case 10000:
		prot = "ndmp";
		break;

	case 10001:
		prot = "scp-config";
		break;

	case 10007:
		prot = "mvs-capacity";
		break;

	case 10008:
		prot = "octopus";
		break;

	case 10009:
		prot = "swdtp-sv";
		break;

	case 10050:
		prot = "zabbix-agent";
		break;

	case 10051:
		prot = "zabbix-trapper";
		break;

	case 10080:
		prot = "amanda";
		break;

	case 10081:
		prot = "famdc";
		break;

	case 10100:
		prot = "itap-ddtp";
		break;

	case 10101:
		prot = "ezmeeting-2";
		break;

	case 10102:
		prot = "ezproxy-2";
		break;

	case 10103:
		prot = "ezrelay";
		break;

	case 10104:
		prot = "swdtp";
		break;

	case 10107:
		prot = "bctp-server";
		break;

	case 10113:
		prot = "netiq-endpoint";
		break;

	case 10114:
		prot = "netiq-qcheck";
		break;

	case 10115:
		prot = "netiq-endpt";
		break;

	case 10116:
		prot = "netiq-voipa";
		break;

	case 10128:
		prot = "bmc-perf-sd";
		break;

	case 10160:
		prot = "qb-db-server";
		break;

	case 10200:
		prot = "trisoap";
		break;

	case 10252:
		prot = "apollo-relay";
		break;

	case 10260:
		prot = "axis-wimp-port";
		break;

	case 10288:
		prot = "blocks";
		break;

	case 10800:
		prot = "gap";
		break;

	case 10805:
		prot = "lpdg";
		break;

	case 10990:
		prot = "rmiaux";
		break;

	case 11000:
		prot = "irisa";
		break;

	case 11001:
		prot = "metasys";
		break;

	case 11111:
		prot = "vce";
		break;

	case 11112:
		prot = "dicom";
		break;

	case 11161:
		prot = "suncacao-snmp";
		break;

	case 11162:
		prot = "suncacao-jmxmp";
		break;

	case 11163:
		prot = "suncacao-rmi";
		break;

	case 11164:
		prot = "suncacao-csa";
		break;

	case 11165:
		prot = "suncacao-websvc";
		break;

	case 11201:
		prot = "smsqp";
		break;

	case 11208:
		prot = "wifree";
		break;

	case 11319:
		prot = "imip";
		break;

	case 11320:
		prot = "imip-channels";
		break;

	case 11321:
		prot = "arena-server";
		break;

	case 11367:
		prot = "atm-uhas";
		break;

	case 11371:
		prot = "hkp";
		break;

	case 11600:
		prot = "tempest-port";
		break;

	case 11720:
		prot = "h323callsigalt";
		break;

	case 11751:
		prot = "intrepid-ssl";
		break;

	case 11967:
		prot = "sysinfo-sp";
		break;

	case 12000:
		prot = "entextxid";
		break;

	case 12001:
		prot = "entextnetwk";
		break;

	case 12002:
		prot = "entexthigh";
		break;

	case 12003:
		prot = "entextmed";
		break;

	case 12004:
		prot = "entextlow";
		break;

	case 12005:
		prot = "dbisamserver1";
		break;

	case 12006:
		prot = "dbisamserver2";
		break;

	case 12007:
		prot = "accuracer";
		break;

	case 12008:
		prot = "accuracer-dbms";
		break;

	case 12012:
		prot = "vipera";
		break;

	case 12109:
		prot = "rets-ssl";
		break;

	case 12121:
		prot = "nupaper-ss";
		break;

	case 12168:
		prot = "cawas";
		break;

	case 12172:
		prot = "hivep";
		break;

	case 12300:
		prot = "linogridengine";
		break;

	case 12321:
		prot = "warehouse-sss";
		break;

	case 12322:
		prot = "warehouse";
		break;

	case 12345:
		prot = "italk";
		break;

	case 12753:
		prot = "tsaf";
		break;

	case 13160:
		prot = "i-zipqd";
		break;

	case 13223:
		prot = "powwow-client";
		break;

	case 13224:
		prot = "powwow-server";
		break;

	case 13720:
		prot = "bprd";
		break;

	case 13721:
		prot = "bpdbm";
		break;

	case 13722:
		prot = "bpjava-msvc";
		break;

	case 13724:
		prot = "vnetd";
		break;

	case 13782:
		prot = "bpcd";
		break;

	case 13783:
		prot = "vopied";
		break;

	case 13785:
		prot = "nbdb";
		break;

	case 13786:
		prot = "nomdb";
		break;

	case 13818:
		prot = "dsmcc-config";
		break;

	case 13819:
		prot = "dsmcc-session";
		break;

	case 13820:
		prot = "dsmcc-passthru";
		break;

	case 13821:
		prot = "dsmcc-download";
		break;

	case 13822:
		prot = "dsmcc-ccp";
		break;

	case 14001:
		prot = "sua";
		break;

	case 14033:
		prot = "sage-best-com1";
		break;

	case 14034:
		prot = "sage-best-com2";
		break;

	case 14141:
		prot = "vcs-app";
		break;

	case 14142:
		prot = "icpp";
		break;

	case 14145:
		prot = "gcm-app";
		break;

	case 14149:
		prot = "vrts-tdd";
		break;

	case 14154:
		prot = "vad";
		break;

	case 14414:
		prot = "ca-web-update";
		break;

	case 14936:
		prot = "hde-lcesrvr-1";
		break;

	case 14937:
		prot = "hde-lcesrvr-2";
		break;

	case 15000:
		prot = "hydap";
		break;

	case 15345:
		prot = "xpilot";
		break;

	case 15363:
		prot = "3link";
		break;

	case 15555:
		prot = "cisco-snat";
		break;

	case 15740:
		prot = "ptp";
		break;

	case 16161:
		prot = "sun-sea-port";
		break;

	case 16309:
		prot = "etb4j";
		break;

	case 16310:
		prot = "pduncs";
		break;

	case 16360:
		prot = "netserialext1";
		break;

	case 16361:
		prot = "netserialext2";
		break;

	case 16367:
		prot = "netserialext3";
		break;

	case 16368:
		prot = "netserialext4";
		break;

	case 16384:
		prot = "connected";
		break;

	case 16991:
		prot = "intel-rci-mp";
		break;

	case 16992:
		prot = "amt-soap-http";
		break;

	case 16993:
		prot = "amt-soap-https";
		break;

	case 16994:
		prot = "amt-redir-tcp";
		break;

	case 16995:
		prot = "amt-redir-tls";
		break;

	case 17007:
		prot = "isode-dua";
		break;

	case 17185:
		prot = "soundsvirtual";
		break;

	case 17219:
		prot = "chipper";
		break;

	case 17235:
		prot = "ssh-mgmt";
		break;

	case 17500:
		prot = "Dropbox-LanSync";
		break;

	case 17729:
		prot = "ea";
		break;

	case 17754:
		prot = "zep";
		break;

	case 17755:
		prot = "zigbee-ip";
		break;

	case 17756:
		prot = "zigbee-ips";
		break;

	case 18000:
		prot = "biimenu";
		break;

	case 18181:
		prot = "opsec-cvp";
		break;

	case 18182:
		prot = "opsec-ufp";
		break;

	case 18183:
		prot = "opsec-sam";
		break;

	case 18184:
		prot = "opsec-lea";
		break;

	case 18185:
		prot = "opsec-omi";
		break;

	case 18186:
		prot = "ohsc";
		break;

	case 18187:
		prot = "opsec-ela";
		break;

	case 18241:
		prot = "checkpoint-rtm";
		break;

	case 18463:
		prot = "ac-cluster";
		break;

	case 18769:
		prot = "ique";
		break;

	case 18881:
		prot = "infotos";
		break;

	case 18888:
		prot = "apc-necmp";
		break;

	case 19000:
		prot = "igrid";
		break;

	case 19191:
		prot = "opsec-uaa";
		break;

	case 19194:
		prot = "ua-secureagent";
		break;

	case 19283:
		prot = "keysrvr";
		break;

	case 19315:
		prot = "keyshadow";
		break;

	case 19398:
		prot = "mtrgtrans";
		break;

	case 19410:
		prot = "hp-sco";
		break;

	case 19411:
		prot = "hp-sca";
		break;

	case 19412:
		prot = "hp-sessmon";
		break;

	case 19539:
		prot = "fxuptp";
		break;

	case 19540:
		prot = "sxuptp";
		break;

	case 19541:
		prot = "jcp";
		break;

	case 20000:
		prot = "dnp";
		break;

	case 20001:
		prot = "microsan";
		break;

	case 20002:
		prot = "commtact-http";
		break;

	case 20003:
		prot = "commtact-https";
		break;

	case 20014:
		prot = "opendeploy";
		break;

	case 20034:
		prot = "nburn_id";
		break;

	case 20167:
		prot = "tolfab";
		break;

	case 20202:
		prot = "ipdtp-port";
		break;

	case 20222:
		prot = "ipulse-ics";
		break;

	case 20670:
		prot = "track";
		break;

	case 20999:
		prot = "athand-mmp";
		break;

	case 21000:
		prot = "irtrans";
		break;

	case 21554:
		prot = "dfserver";
		break;

	case 21590:
		prot = "vofr-gateway";
		break;

	case 21800:
		prot = "tvpm";
		break;

	case 21845:
		prot = "webphone";
		break;

	case 21846:
		prot = "netspeak-is";
		break;

	case 21847:
		prot = "netspeak-cs";
		break;

	case 21848:
		prot = "netspeak-acd";
		break;

	case 21849:
		prot = "netspeak-cps";
		break;

	case 22000:
		prot = "snapenetio";
		break;

	case 22001:
		prot = "optocontrol";
		break;

	case 22002:
		prot = "optohost002";
		break;

	case 22003:
		prot = "optohost003";
		break;

	case 22004:
		prot = "optohost004";
		break;

	case 22005:
		prot = "optohost004";
		break;

	case 22273:
		prot = "wnn6";
		break;

	case 22555:
		prot = "vocaltec-phone Or vocaltec-wconf";
		break;

	case 22763:
		prot = "talikaserver";
		break;

	case 22800:
		prot = "aws-brf";
		break;

	case 22951:
		prot = "brf-gw";
		break;

	case 23000:
		prot = "inovaport1";
		break;

	case 23001:
		prot = "inovaport2";
		break;

	case 23002:
		prot = "inovaport3";
		break;

	case 23003:
		prot = "inovaport4";
		break;

	case 23004:
		prot = "inovaport5";
		break;

	case 23005:
		prot = "inovaport6";
		break;

	case 23400:
		prot = "novar-dbase";
		break;

	case 23401:
		prot = "novar-alarm";
		break;

	case 23402:
		prot = "novar-global";
		break;

	case 24000:
		prot = "med-ltp";
		break;

	case 24001:
		prot = "med-fsp-rx";
		break;

	case 24002:
		prot = "med-fsp-tx";
		break;

	case 24003:
		prot = "med-supp";
		break;

	case 24004:
		prot = "med-ovw";
		break;

	case 24005:
		prot = "med-ci";
		break;

	case 24006:
		prot = "med-net-svc";
		break;

	case 24242:
		prot = "filesphere";
		break;

	case 24249:
		prot = "vista-4gl";
		break;

	case 24321:
		prot = "ild";
		break;

	case 24386:
		prot = "intel_rci";
		break;

	case 24554:
		prot = "binkp";
		break;

	case 24677:
		prot = "flashfiler";
		break;

	case 24678:
		prot = "proactivate";
		break;

	case 24680:
		prot = "tcc-http";
		break;

	case 24922:
		prot = "snip";
		break;

	case 25000:
		prot = "icl-twobase1";
		break;

	case 25001:
		prot = "icl-twobase2";
		break;

	case 25002:
		prot = "icl-twobase3";
		break;

	case 25003:
		prot = "icl-twobase4";
		break;

	case 25004:
		prot = "icl-twobase5";
		break;

	case 25005:
		prot = "icl-twobase6";
		break;

	case 25006:
		prot = "icl-twobase7";
		break;

	case 25007:
		prot = "icl-twobase8";
		break;

	case 25008:
		prot = "icl-twobase9";
		break;

	case 25009:
		prot = "icl-twobase10";
		break;

	case 25793:
		prot = "vocaltec-hos";
		break;

	case 25900:
		prot = "tasp-net";
		break;

	case 25901:
		prot = "niobserver";
		break;

	case 25903:
		prot = "niprobe";
		break;

	case 26000:
		prot = "quake";
		break;

	case 26208:
		prot = "wnn6-ds";
		break;

	case 26260:
		prot = "ezproxy";
		break;

	case 26261:
		prot = "ezmeeting";
		break;

	case 26262:
		prot = "k3software-svr";
		break;

	case 26263:
		prot = "k3software-cli";
		break;

	case 26264:
		prot = "gserver";
		break;

	case 26486:
		prot = "exoline";
		break;

	case 26487:
		prot = "exoconfig";
		break;

	case 26489:
		prot = "exonet";
		break;

	case 27345:
		prot = "imagepump";
		break;

	case 27442:
		prot = "jesmsjc";
		break;

	case 27504:
		prot = "kopek-httphead";
		break;

	case 27782:
		prot = "ars-vista";
		break;

	case 27999:
		prot = "tw-auth-key";
		break;

	case 28000:
		prot = "nxlmd";
		break;

	case 28240:
		prot = "siemensgsm";
		break;

	case 29167:
		prot = "otmp";
		break;

	case 30001:
		prot = "pago-services1";
		break;

	case 30002:
		prot = "pago-services2";
		break;

	case 30999:
		prot = "ovobs";
		break;

	case 31416:
		prot = "xqosd";
		break;

	case 31457:
		prot = "tetrinet";
		break;

	case 31620:
		prot = "lm-mon";
		break;

	case 31765:
		prot = "gamesmith-port";
		break;

	case 31948:
		prot = "iceedcp_tx";
		break;

	case 31949:
		prot = "iceedcp_rx";
		break;

	case 32249:
		prot = "t1distproc60";
		break;

	case 32483:
		prot = "apm-link";
		break;

	case 32635:
		prot = "sec-ntb-clnt";
		break;

	case 32767:
		prot = "filenet-powsrm";
		break;

	case 32768:
		prot = "filenet-tms";
		break;

	case 32769:
		prot = "filenet-rpc";
		break;

	case 32770:
		prot = "filenet-nch";
		break;

	case 32771:
		prot = "filenet-rmi";
		break;

	case 32772:
		prot = "filenet-pa";
		break;

	case 32773:
		prot = "filenet-cm";
		break;

	case 32774:
		prot = "filenet-re";
		break;

	case 32775:
		prot = "filenet-pch";
		break;

	case 32776:
		prot = "filenet-peior";
		break;

	case 32777:
		prot = "filenet-obrok";
		break;

	case 32896:
		prot = "idmgratm";
		break;

	case 33331:
		prot = "diamondport";
		break;

	case 33434:
		prot = "traceroute";
		break;

	case 33656:
		prot = "snip-slave";
		break;

	case 34249:
		prot = "turbonote-2";
		break;

	case 34378:
		prot = "p-net-local";
		break;

	case 34379:
		prot = "p-net-remote";
		break;

	case 34962:
		prot = "profinet-rt";
		break;

	case 34963:
		prot = "profinet-rtm";
		break;

	case 34964:
		prot = "profinet-cm";
		break;

	case 34980:
		prot = "ethercat";
		break;

	case 36865:
		prot = "kastenxpipe";
		break;

	case 37475:
		prot = "neckar";
		break;

	case 37654:
		prot = "unisys-eportal";
		break;

	case 38201:
		prot = "galaxy7-data";
		break;

	case 38202:
		prot = "fairview";
		break;

	case 38203:
		prot = "agpolicy";
		break;

	case 39681:
		prot = "turbonote-1";
		break;

	case 40000:
		prot = "safetynetp";
		break;

	case 40841:
		prot = "cscp";
		break;

	case 40842:
		prot = "csccredir";
		break;

	case 40843:
		prot = "csccfirewall";
		break;

	case 41111:
		prot = "fs-qos";
		break;

	case 41794:
		prot = "crestron-cip";
		break;

	case 41795:
		prot = "crestron-ctp";
		break;

	case 42508:
		prot = "candp";
		break;

	case 42509:
		prot = "candrp";
		break;

	case 42510:
		prot = "caerpc";
		break;

	case 43188:
		prot = "reachout";
		break;

	case 43189:
		prot = "ndm-agent-port";
		break;

	case 43190:
		prot = "ip-provision";
		break;

	case 43441:
		prot = "ciscocsdb";
		break;

	case 44321:
		prot = "pmcd";
		break;

	case 44322:
		prot = "pmcdproxy";
		break;

	case 44553:
		prot = "rbr-debug";
		break;

	case 44818:
		prot = "rockwell-encap";
		break;

	case 45054:
		prot = "invision-ag";
		break;

	case 45678:
		prot = "eba";
		break;

	case 45966:
		prot = "ssr-servermgr";
		break;

	case 46999:
		prot = "mediabox";
		break;

	case 47000:
		prot = "mbus";
		break;

	case 47557:
		prot = "dbbrowse";
		break;

	case 47624:
		prot = "directplaysrvr";
		break;

	case 47806:
		prot = "ap";
		break;

	case 47808:
		prot = "bacnet";
		break;

	case 48000:
		prot = "nimcontroller";
		break;

	case 48001:
		prot = "nimspooler";
		break;

	case 48002:
		prot = "nimhub";
		break;

	case 48003:
		prot = "nimgtw";
		break;

	case 48128:
		prot = "isnetserv";
		break;

	case 48129:
		prot = "blp5";
		break;

	case 48556:
		prot = "com-bardac-dw";
		break;

	default:
		prot = "Unknown";
		break;
	}

	string p = boost::lexical_cast<string>(porta);
	prot = prot + " (" + p + ")";
	string * a = new string(prot);
	return *a;
}
