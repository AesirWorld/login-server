Login Server
===========

A re-implementation in Go of the eAthena/rAthena login-server.

###TODO
* case 0x2714: logchrif_parse_ackusercount(fd, cid)
* case 0x2715: logchrif_parse_updmail(fd, cid, ip)
* case 0x2722: logchrif_parse_reqchangemail(fd, cid, ip)
* case 0x2724: logchrif_parse_requpdaccstate(fd, cid, ip)
* case 0x2725: logchrif_parse_reqbanacc(fd, cid, ip)
* case 0x2727: logchrif_parse_reqchgsex(fd, cid, ip)
* case 0x2728: logchrif_parse_updreg2(fd, cid, ip)
* case 0x272a: logchrif_parse_requnbanacc(fd, cid, ip)
* case 0x272b: logchrif_parse_setacconline(fd, cid)
* case 0x2736: logchrif_parse_updcharip(fd, cid)
* case 0x2737: logchrif_parse_setalloffline(fd, cid)
* case 0x2738: logchrif_parse_updpincode(fd)
* case 0x2739: logchrif_parse_pincode_authfail(fd)
* case 0x2740: logchrif_parse_bankvault(fd, cid, ip)
* case 0x2742: logchrif_parse_reqvipdata(fd) //Vip sys
