/*
# legend:
# patterns are in java pattern notation
# * = 0..n
# + = 1..n
# ? = 0 or 1
# EOF = end of file
*/

grammar OMiPolicy;

policy
        : syntax? (logsource | xmlsource | gensource | snmpsource | msgsource | 
                   advmonsource | schedsource | wbemsource mgrconfsource)+ EOF
        ;
syntax
        : 'SYNTAX_VERSION' INT
        ;

logsource
        : 'LOGFILE' stringLiteral  'DESCRIPTION' stringLiteral logdefopts conditions
        ;
xmlsource
        : 'XML' stringLiteral 'DESCRIPTION' stringLiteral xmldefopts xmlconditions
        ;

gensource
        : 'GENERIC_SOURCE' stringLiteral 'DESCRIPTION' stringLiteral 'POLTYPE' 
           stringLiteral gensrcnode xmldefopts xmlconditions
        ;
snmpsource
        : 'SNMP' stringLiteral 'DESCRIPTION' stringLiteral snmpdefopts snmpconditions
        ;
wbemsource
        : 'WBEM' stringLiteral 'DESCRIPTION' stringLiteral wbemdefopts wbemconditions
        | 'WMI' stringLiteral 'DESCRIPTION' stringLiteral wbemdefopts wbemconditions
        ;
msgsource
        : 'OPCMSG' stringLiteral 'DESCRIPTION' stringLiteral msgdefopts conditions
        ;
schedsource
        : 'SCHEDULE' stringLiteral 'DESCRIPTION' stringLiteral condsuppdupl schedsetopts
        ;
advmonsource
        : 'ADVMONITOR' stringLiteral 'DESCRIPTION' stringLiteral advmondefaults 
           advmonsourcedef advmonconditions
        ;
logdefopts
        : (logdefault | logoption | sourceoption )*  
        ;
logdefault
        : stddefault
        | 'NODE' node
        ;
logoption
        : 'LOGPATH' stringLiteral
        | 'EXEFILE' stringLiteral
        | 'READFILE' stringLiteral
        | 'INTERVAL' stringLiteral
        | 'CHSET' chset
        | 'FROM_LAST_POS'
        | 'ALWAYS_FROM_BEGIN'
        | 'FIRST_FROM_BEGIN'
        | 'NO_LOGFILE_MSG'
        | 'CLOSE_AFTER_READ'
        ;
xmldefopts
        : (xmldefault | xmloption | commonsourceoption | 'MAP' stringLiteral mapdesc 
           definput map )*
        ;
gensrcnode
        : 'GROUP' stringLiteral gensrcatts gensrcnode_body 'GROUP_END'
        | 'GROUP' stringLiteral gensrcatts 'GROUP_END'
        ;
        
gensrcnode_body
        : (gensrcnode | gensrcparam)+
        ;
gensrcparam
        : 'PARAM' stringLiteral stringLiteral gensrcatts
        ;
gensrcatts
        : ('ATT' stringLiteral stringLiteral)*
        ;
definput
        : ('INPUT' stringLiteral)?
        ;
mapdesc
        : ('DESCRIPTION' stringLiteral)?
        ;
map
        : ('FROM' stringLiteral 'TO' stringLiteral)*
        ;
        xmldefault
        : 'DEFAULTMSG' sets
        ;
xmloption
        : 'LOGPATH' stringLiteral
        | 'INTERVAL' stringLiteral
        | 'CHSET' chset
        | 'FROM_LAST_POS'
        | 'ALWAYS_FROM_BEGIN'
        | 'FIRST_FROM_BEGIN'
        | 'NO_LOGFILE_MSG'
        | 'CLOSE_AFTER_READ'
        | 'XMLROOT' stringLiteral
        | 'XMLROOT' stringLiteral 'XMLCONVERT' stringLiteral
        ;
snmpdefopts
        : (stddefault | sourceoption )*  
        ;
wbemdefopts
        : (wbemdefault | wbemoption | sourceoption )*
        ;
wbemdefault
        : stddefault
        | 'NODE' node
        ;
wbemoption
        : 'NAMESPACE' stringLiteral
        | 'CLASS' stringLiteral
        | 'WITHIN' stringLiteral
        | 'WHERE_CLAUSE' stringLiteral
        | 'QUERY_LANGUAGE' stringLiteral
        | 'QUERY' stringLiteral
        | 'INSTANCE_CREATION_EVENT'
        | 'INSTANCE_MODIFICATION_EVENT'
        | 'INSTANCE_DELETION_EVENT'
        | 'CLASS_CREATION_EVENT'
        | 'CLASS_MODIFICATION_EVENT'
        | 'CLASS_DELETION_EVENT'
        | 'NAMESPACE_CREATION_EVENT'
        | 'NAMESPACE_MODIFICATION_EVENT'
        | 'NAMESPACE_DELETION_EVENT'
        | 'INTERVAL' stringLiteral
        | 'WMI_USERNAME' stringLiteral 'WMI_PASSWORD' stringLiteral
        ;
msgdefopts
        : (stddefault | sourceoption )* 
        ;
stddefault
        : 'SEVERITY' SEV_VAL
        | 'APPLICATION' stringLiteral
        | 'MSGGRP' stringLiteral
        | 'OBJECT' stringLiteral
        | 'SERVICE_NAME' stringLiteral
        | 'MSGKEY' stringLiteral
        | 'HELPTEXT' stringLiteral
        | 'HELP' stringLiteral
        | 'INSTRUCTION_TEXT_INTERFACE' stringLiteral
        | 'INSTRUCTION_PARAMETERS' stringLiteral
        ;
commonsourceoption
        : 'LOGMATCHEDMSGCOND'
        | 'LOGMATCHEDSUPPRESS'
        | 'LOGUNMATCHED'
        | 'FORWARDUNMATCHED'
        | 'UNMATCHEDLOGONLY'
        | 'SUPP_DUPL_COND' suppdupl
        | 'SUPP_DUPL_IDENT' suppdupl
        | 'SUPP_DUPL_IDENT_OUTPUT_MSG' suppdupl
        | 'SEPARATORS' stringLiteral
        | icase
        ;

sourceoption
        : commonsourceoption
        | 'MPI_AGT_COPY_MSG'
        | 'MPI_AGT_DIVERT_MSG'
        | 'MPI_AGT_NO_OUTPUT'
        | 'MPI_IMMEDIATE_LOCAL_ACTIONS'
        ;
advmondefaults
        : (sourceoption | stddefault | 'NODE' node | advmonoption )*
        ;
advmonoption
        : 'INTERVAL' stringLiteral
        | 'INSTANCEMODE' 'ALL'
        | 'INSTANCEMODE' 'SAME'
        | 'INSTANCEMODE' 'ONCE'
        | 'MULTISOURCE'
        | 'INSTANCERULES'
        | 'AUTOMATIC_MSGKEY'
        | 'AUTOMATIC_MSGKEY' stringLiteral
        | 'MINTHRESHOLD'
        | 'MAXTHRESHOLD'
        | 'GEN_BELOW_THRESHOLD'
        | 'GEN_BELOW_RESET'
        | 'GEN_ALWAYS'
        | 'SCRIPTTYPE' stringLiteral
        | 'DDF' 'DATASOURCE' stringLiteral
        | 'DDF' 'OBJECT' stringLiteral
        ;
advmonsourcedef
        : ('PROGRAM' stringLiteral 'DESCRIPTION' stringLiteral advmonprog
        | 'EXTERNAL'    stringLiteral 'DESCRIPTION' stringLiteral ddf
        | 'NTPERFMON'   stringLiteral 'DESCRIPTION' stringLiteral advmonperfmon
        | 'SNMP'        stringLiteral 'DESCRIPTION' stringLiteral advmonsnmp
        | 'MEASUREMENT' stringLiteral 'DESCRIPTION' stringLiteral advmonme
        | 'CODA' stringLiteral 'DESCRIPTION' stringLiteral advmonme
        | 'WBEM' stringLiteral 'DESCRIPTION' stringLiteral advmonwbem)*
        ;
advmonprog
        : 'MONPROG' stringLiteral ddf
        ;
advmonperfmon
        : 'OBJECT' stringLiteral 'COUNTER' stringLiteral 'INSTANCE' stringLiteral ddf
        ;
advmonsnmp
        : 'MIB' stringLiteral v3par ddf
        | 'MIB' stringLiteral 'NODE' node v3par ddf
        ;
advmonme
        : 'COLLECTION' stringLiteral metrics
        | 'COLLECTION' stringLiteral 'GUID' stringLiteral metrics
        | 'DATASOURCE' stringLiteral 'COLLECTION' stringLiteral metrics
        ;
advmonwbem
        : 'NAMESPACE' stringLiteral 'CLASS' stringLiteral 'ATTRIBUTE' stringLiteral 
           instancefilter ddf
        | 'WMI_USERNAME' stringLiteral 'WMI_PASSWORD' stringLiteral 'NAMESPACE' 
           stringLiteral 'CLASS' stringLiteral 'ATTRIBUTE' stringLiteral instancefilter 
           ddf
        ;
instancefilter
        : ('INSTANCE_FILTER' stringLiteral)?
        ;
metrics
        : ('METRIC' stringLiteral metricguid useforinstance)*
        ;
v3par
        : ('SNMPV3_ENGINEID' stringLiteral)?
        | ('SNMPV3_USER' stringLiteral 'SNMPV3_AUTHTYPE' stringLiteral 
          'SNMPV3_AUTHPASSPHRASE' 
          stringLiteral  'SNMPV3_ENCRYPTTYPE' stringLiteral 'SNMPV3_ENCRYPTPASSPHRASE' 
          stringLiteral)?
        ;
ddf
        : ('DDF' 'DATASOURCE' stringLiteral 'OBJECT' stringLiteral 'METRIC' 
           stringLiteral)?
        ;
metricguid
        : ('GUID' stringLiteral)?
        ;
useforinstance
        : ('USEFORINSTANCE')?
        ;
advmonconditions
        : ('MSGCONDITIONS' advmonmsgconds | 'SUPPRESSCONDITIONS' advmonsuppressconds |
          'SUPP_UNM_CONDITIONS' advmonsupp_unm_conds)*
        ;
advmonmsgconds
        : (instancerule condition_description condsuppdupl condition_id 'CONDITION' 
           advmonconds advmonmsgsets )*
        ;
instancerule
        : ('INSTANCERULE' stringLiteral 'ID' stringLiteral)?
        ;
advmonmsgsets
        : ('SETSTART' sets | 'SETCONT'  sets | 'SETEND'   sets)*
        ;
advmonsuppressconds
        : (condition_description condition_id 'CONDITION' advmonconds )*
        ;
advmonsupp_unm_conds
        : (condition_description condition_id 'CONDITION' advmonconds )*
        ;
advmonconds
        : ('THRESHOLD' numval duration | 'THRESHOLD' condscript duration | 
           'THRESHOLD' stringLiteral duration | 'RESET' numval | 'RESET' condscript |
           'RESET' stringLiteral | 'OBJECT' pattern | 'OBJECT' condscript )*
        ;
condscript
        : 'SCRIPTTYPE' stringLiteral 'SCRIPT' stringLiteral
        | 'SCRIPT' stringLiteral
        ;
duration
        : ('FOR' stringLiteral)?
        ;
numval
        : INT
        | FLOAT
        ;
schedsetopts
        : ('SCRIPTTYPE' stringLiteral 'SCRIPT' stringLiteral | 'SCHEDPROG' stringLiteral |
           'USER' stringLiteral | 'USER' stringLiteral 'PWD' stringLiteral |
           'MONTH' stringLiteral | 'MONTHDAY' stringLiteral | 'WEEKDAY' stringLiteral |
           'HOUR' stringLiteral | 'MINUTE' stringLiteral | 'TIMEZONE_VALUE' stringLiteral |
           'YEAR' INT | 'INTERVAL' stringLiteral | 'LOGLOCAL' | 'SEND_OUTPUT' |
           'TIMEZONE_TYPE' tz_type | 'BEFORE' 'SET' sets condsuppdupl |
           'FAILURE' 'SET' sets condsuppdupl | 'SUCCESS' 'SET' sets condsuppdupl)*
        ;
tz_type
        : 'MGR_LOCAL'
        | 'AGT_LOCAL'
        | 'FIX'
        ;
conditions
        : ('MSGCONDITIONS' msgconds | 'SUPPRESSCONDITIONS' suppressconds | 
           'SUPP_UNM_CONDITIONS' supp_unm_conds)*
        ;
msgconds
        : (condition_description condsuppdupl condition_id 'CONDITION' conds 
           'SET' sets )*
        ;
suppressconds
        : (condition_description condition_id 'CONDITION' conds )*
        ;
supp_unm_conds
        : (condition_description condition_id 'CONDITION' conds )*
        ;
condsuppdupl
        : ('SUPP_DUPL_COND' suppdupl
        | 'SUPP_DUPL_IDENT' suppdupl
        | 'SUPP_DUPL_IDENT_OUTPUT_MSG' suppdupl)?
        ;
conds
        : ('SEVERITY' severities | 'NODE' nodelist | 'APPLICATION' stringLiteral | 
           'MSGGRP' stringLiteral | 'OBJECT' stringLiteral | 'TEXT' pattern )*
        ;
snmpconditions
        : ('MSGCONDITIONS' snmpmsgconds | 'SUPPRESSCONDITIONS' snmpsuppressconds |
           'SUPP_UNM_CONDITIONS' snmpsupp_unm_conds)*
        ;
snmpmsgconds
        : (condition_description condsuppdupl condition_id 'CONDITION' snmpconds 
           'SET' sets )*
        ;
snmpsuppressconds
        : (condition_description condition_id 'CONDITION' snmpconds )*
        ;
snmpsupp_unm_conds
        : (condition_description condition_id 'CONDITION' snmpconds )*
        ;
snmpconds
        : ('$e' stringLiteral | ('$G'|'$g') INT | '$S' INT | DOLLAR_VAR pattern |
           'NODE' nodelist )*
        ;
wbemconditions
        : ('MSGCONDITIONS' wbemmsgconds | 'SUPPRESSCONDITIONS' wbemsuppressconds |
           'SUPP_UNM_CONDITIONS' wbemsupp_unm_conds)*
        ;
wbemmsgconds
        : (condition_description condsuppdupl condition_id 'CONDITION' wbemconds 
           'SET' sets )*
        ;
wbemsuppressconds
        : (condition_description condition_id 'CONDITION' wbemconds )*
        ;
wbemsupp_unm_conds
        : (condition_description condition_id 'CONDITION' wbemconds )*
        ;
wbemconds
        : (stringLiteral '~=' pattern | stringLiteral wbemop wbemval )*
        ;
wbemop
        : '=='
        | '!='
        | '>='
        | '>'                                        

       | '<='
        | '<'
        ;
                                                        
wbemval
        : (stringLiteral | FLOAT | INT)
        ;
xmlconditions
        : ('MSGCONDITIONS' xmlmsgconds | 'SUPPRESSCONDITIONS' xmlsuppressconds |
           'SUPP_UNM_CONDITIONS' xmlsupp_unm_conds)*
        ;
xmlmsgconds
        : (condition_description condsuppdupl condition_id 'CONDITION' xmlconds 
           'SET' sets )*
        ;
xmlsuppressconds
        : (condition_description condition_id 'CONDITION' xmlconds )*
        ;
xmlsupp_unm_conds
        : (condition_description condition_id 'CONDITION' xmlconds )*
        ;
xmlconds
        : (xmllogop | stringLiteral '~=' pattern | stringLiteral xmlop xmlval )*
        ;
xmlop
        : '=='
        | '!='
        | '>='
        | '>'
        | '<='
        | '<'
        ;
xmllogop
        : 'OPEN'
        | 'OR'
        | 'NOT'
        | 'CLOSE'
        ;
xmlval
        : stringLiteral
        | FLOAT
        | INT
        | 'PROPERTY' stringLiteral
        ;
sets
        : (set)*
        ;
set
        : 'SEVERITY' SEV_VAL
        | 'SEVERITY' stringLiteral
        | 'NODE' node
        | 'APPLICATION' stringLiteral
        | 'MSGGRP' stringLiteral
        | 'OBJECT' stringLiteral
        | 'MSGTYPE' stringLiteral
        | 'TEXT' stringLiteral
        | 'SERVICE_NAME' stringLiteral
        | 'MSGKEY' stringLiteral
        | 'MSGKEYRELATION' 'ACK' keyrelpattern
        | 'CUSTOM' stringLiteral stringLiteral
        | 'SERVERLOGONLY'
        | 'SERVERLOGONLY' stringLiteral
        | 'AUTOACTION' action
        | 'OPACTION' action
        | 'NOTIFICATION' notification
        | 'MPI_AGT_COPY_MSG'
        | 'MPI_AGT_DIVERT_MSG'
        | 'MPI_AGT_NO_OUTPUT'
        | 'MPI_IMMEDIATE_LOCAL_ACTIONS'
        | 'HELPTEXT' stringLiteral
        | 'HELP' stringLiteral
        | 'INSTRUCTION_TEXT_INTERFACE' stringLiteral
        | 'INSTRUCTION_PARAMETERS' stringLiteral
        | 'TIMECREATED' stringLiteral
        ;
action
        : stringLiteral actionnode? annotate? acknowledge? msgsendmode? user? password?
          signature?
        ;
notification
        : stringLiteral?
        ;
condition_id
        : ('CONDITION_ID' stringLiteral)?
        ;
condition_description
        : 'DESCRIPTION' stringLiteral
        ;
actionnode
        : 'ACTIONNODE' node
        ;
annotate
        : 'ANNOTATE'
        ;
acknowledge
        : 'ACK'
        | 'ACK' stringLiteral
        ;
msgsendmode
        : 'SEND_MSG_AFTER_LOC_AA' msgsendok? msgsendfailed?
        ;
user
        : 'USER' stringLiteral
        ;
password
        : 'PWD' stringLiteral
        ;
signature
        : 'SIGNATURE' stringLiteral
        ;
msgsendok
        : 'SEND_OK_MSG' logonly
        ;
logonly
        : ('LOGONLY')?
        ;
msgsendfailed
        : 'SEND_FAILED_MSG'
        ;
pattern
        : stringLiteral separators? icase?
        ;
keyrelpattern
        : stringLiteral separators? icase
        | stringLiteral separators?
        ;
separators
        : 'SEPARATORS' stringLiteral
        ;
icase
        : 'ICASE'
        ;
chset
        : 'ASCII'  /* ASCII              */
        | 'ACP1250' /* NT ANSI Code page for Eastern Europe */
        | 'ACP1251' /* NT ANSI Code page for Russian */
        | 'ACP1252' /* NT ANSI Code page for Latin */
        | 'ACP1253' /* NT ANSI Code page for Greek */
        | 'ACP1254' /* NT ANSI Code page for Turkish */
        | 'ACP1255' /* NT ANSI Code page for Hebrew */
        | 'ACP1256' /* NT ANSI Code page for Arabic */
        | 'ACP1257' /* NT ANSI Code page for Baltic */
        | 'ACP1258' /* NT ANSI Code page for Vietnamese */
        | 'NT_OEM_JP' /* NT ANSI Japanese */
        | 'ACP932' /* ANSI CP 932 Japanese */
        | 'NT_ANSI_JP' /* NT ANSI Japanese */
        | 'OEMCP932' /* ANSI CP 932 Japanese */
        | 'ACP874' /* NT ANSI Code page for Thai */
        | 'NT_OEM_L1'  /* OEM Latin 1  */
        | 'NT_ANSI_L1'    /* NT ANSI Latin 1  */
        | 'OEMCP850' /* OEM CP 850 Latin 1 */
        | 'NT_OEM_US'    /* NT OEM      US               */
        | 'NT_UNICODE'
        | 'OEMCP852'  /* OEM Latin 2  */
        | 'OEMCP855'  /* OEM Cyrillic  */
        | 'OEMCP857'
        | 'OEMCP860'
        | 'OEMCP861'
        | 'OEMCP862'
        | 'OEMCP863'
        | 'OEMCP864'
        | 'OEMCP865'
        | 'OEMCP866'
        | 'OEMCP869'
        | 'OEMCP437'  /* OEM US           */
        | 'OEMCP737'
        | 'OEMCP775'
        | 'ROMAN8'
        | 'ISO8859'
        | 'ISO88591'
        | 'ISO885910'
        | 'ISO885911'
        | 'ISO885913'
        | 'ISO885914'
        | 'ISO885915'
        | 'ISO88592'
        | 'ISO88593'
        | 'ISO88594'
        | 'ISO88595'
        | 'ISO88596'
        | 'ISO88597'
        | 'ISO88598'
        | 'ISO88599'
        | 'TIS620'      /* TIS620          */
        | 'EBCDIC'
        | 'SJIS'
        | 'EUC'
        | 'EUCJP'
        | 'EUCKR'
        | 'EUCTW'
        | 'GB2312'
        | 'BIG5'
        | 'CCDC'
        | 'UTF8'
        | 'UNICODE'
        | 'UCS2'
        ;
severities
        : (SEV_VAL)*;
nodelist
        : (node)+
        ;
node
        : 'IP' IP_ADR
        | 'IP' IP_ADR stringLiteral
        ;
suppdupl
        : stringLiteral
        | stringLiteral 'RESEND' stringLiteral
        | stringLiteral 'COUNTER_THRESHOLD' INT
        | stringLiteral 'COUNTER_THRESHOLD' INT 'RESET_COUNTER_INTERVAL' stringLiteral
        | stringLiteral 'RESEND' stringLiteral 'COUNTER_THRESHOLD' INT
        | stringLiteral 'RESEND' stringLiteral 'COUNTER_THRESHOLD' INT 
        'RESET_COUNTER_INTERVAL' stringLiteral
        | 'COUNTER_THRESHOLD' INT
        | 'COUNTER_THRESHOLD' INT 'RESET_COUNTER_INTERVAL' stringLiteral
        ;
mgrconfsource : timetemplates? respmgrconfigs
        ;
timetemplates : 'TIMETEMPLATES' timetemplate*
        ;
timetemplate : 'TIMETEMPLATE' stringLiteral 'DESCRIPTION' stringLiteral timetmpldef?
                timetmplconds?
        ;
timetmpldef : 'TIMEZONETYPE' timezonetypevalue 'TIMEZONEVALUE' stringLiteral
        ;
timezonetypevalue : 'Fix' | 'Local' | 'Mgmtserver'
        ;
timetmplconds : 'TIMETMPLCONDS' timetmplcond*
        ;
timetmplcond : 'TIMETMPLCOND' timetmplcondinfo*
        ;
timetmplcondinfo
        : 'TIMECONDTYPE' condtype
        | 'TIME' 'FROM' timeval 'TO' timeval
        | 'WEEKDAY' weekdayinfo
        | 'DATE' dateinfo
        ;
condtype : 'Match' | 'Suppress' | 'Unmatch'
        ;
weekdayinfo
        : 'ON' weekday
        | 'FROM' weekday 'TO' weekday
        ;
weekday : 'Monday' | 'Tuesday' | 'Wednesday' | 'Thursday' | 'Friday' | 'Saturday' |
          'Sunday'
        ;
dateinfo
        : 'ON' date
        | 'FROM' date 'TO' date
        ;
timeval
        : HOUR_VAL ':' MINUTE_VAL
        | '24:00'
        ;
date
        : YEAR_VAL '/' MONTH_VAL '/' MONTHDAY_VAL
        | '*' '/' MONTH_VAL '/' MONTHDAY_VAL
        | YEAR_VAL '/' '*' '/' MONTHDAY_VAL
        | '*' '/' '*' '/' MONTHDAY_VAL
        | '*' '/' MONTH_VAL '/' '*'
        ;
respmgrconfigs : 'RESPMGRCONFIGS' respmgrconfig*
        ;
respmgrconfig : 'RESPMGRCONFIG' respmgrconfiginfo
        ;
respmgrconfiginfo : 'DESCRIPTION' stringLiteral respmgrconds
        ;
respmgrconds
        : 'SECONDARYMANAGERS' secondmgr* 'ACTIONALLOWMANAGERS' actallowmgr* 
          'MSGTARGETRULES' msgtargetrule*
        | 'SECONDARYMANAGERS' secondmgr* 'ACTIONALLOWMANAGERS' actallowmgr*
        | 'MSGTARGETRULES' msgtargetrule*
        ;
secondmgr : 'SECONDARYMANAGER' secondmgrinfo
        ;
secondmgrinfo
        : 'NODE' mgrconfnode 'DESCRIPTION' stringLiteral 
        | 'NODE' mgrconfnode
        ;
actallowmgr : 'ACTIONALLOWMANAGER' actallowmgrinfo
        ;
actallowmgrinfo
        : 'NODE' mgrconfnode 'DESCRIPTION' stringLiteral 
        | 'NODE' mgrconfnode
        ;
msgtargetrule : 'MSGTARGETRULE' msgtargetruleinfo
        ;
msgtargetruleinfo
        : 'DESCRIPTION' stringLiteral 'MSGTARGETRULECONDS' mtrcondition* 
          'MSGTARGETMANAGERS' msgtargetmgr*
        ;
mtrcondition : 'MSGTARGETRULECOND' mtrconditioninfo
        ;
mtrconditioninfo : 'DESCRIPTION' stringLiteral msgattrcond*
        ;
msgattrcond
        : 'SEVERITY' SEV_VAL
        | 'APPLICATION' stringLiteral
        | 'MSGGRP' stringLiteral
        | 'OBJECT' stringLiteral
        | 'TEXT' pattern
        | 'MSGTYPE' stringLiteral
        | 'MSGCONDTYPE' condtype
        | 'NODE' nodelist
        | 'CONDSTATUSVAR' stringLiteral
        | 'SERVICE' pattern
        ;
msgtargetmgr : 'MSGTARGETMANAGER' msgtargetmgrinfo
        ;
msgtargetmgrinfo : 'TIMETEMPLATE' stringLiteral 'OPCMGR' mgrconfnode
        ;
mgrconfnode
        : node 'ID' stringLiteral
        | node
        ;
stringLiteral
        :        STRING_LITERAL
        ;
SEV_VAL         : 'Unknown'|'Normal'|'Warning'|'Minor'|'Major'|'Critical';
IP_ADR          : INT'.'INT'.'INT'.'INT;
DOLLAR_VAR      : '$'INT;
HEXSTR          : '0x'('0'..'9'|'a'..'f'|'A'..'F')+;
ID      : ('a'..'z'|'A'..'Z'|'_') ('a'..'z'|'A'..'Z'|'0'..'9'|'_')*
        ;
INT     
        : ('+'|'-')?'0'..'9'+
        ;
FLOAT
        : ('+'|'-')?('0'..'9')+ '.' ('0'..'9')* EXPONENT?
        | ('+'|'-')?'.' ('0'..'9')+ EXPONENT?
        | ('+'|'-')?('0'..'9')+ EXPONENT
        ;
STRING_LITERAL
        : '"' .*? '"'
        ;
WS      : ( ' '
        | '\t'
        | '\r'
        | '\n'
        ) -> skip
        ;
CHAR:  '\'' ( ESC_SEQ | ~('\''|'\\') ) '\''
        ;
fragment
EXPONENT : ('e'|'E') ('+'|'-')? ('0'..'9')+ ;
fragment
DIGIT : ('0'..'9') ;
fragment
HEX_DIGIT : ('0'..'9'|'a'..'f'|'A'..'F') ;
fragment
MINUTE_VAL : ('0'..'5') ('0'..'9') ;
fragment
HOUR_VAL : ('0')? ('0'..'9') | ('1') ('0'..'9') | ('2') ('0'..'3');
fragment
YEAR_VAL : DIGIT DIGIT | DIGIT DIGIT DIGIT DIGIT;
fragment
MONTH_VAL
        : ('0')? ('1'..'9')
        | '1' ('0'..'2')
        ;
fragment
MONTHDAY_VAL
        : ('0')? ('1'..'9')
        | ('1'..'2') ('0'..'9')
        | '30' | '31'
        ;
fragment
ESC_SEQ
        :   '\\' (.)
        ;
fragment
OCTAL_ESC
        :       '\\' ('0'..'3') ('0'..'7') ('0'..'7')
        |       '\\' ('0'..'7') ('0'..'7')
        |       '\\' ('0'..'7')
        ;
fragment
UNICODE_ESC
        :       '\\' 'u' HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT
        ;
COMMENT
        : '#' ~( '\r' | '\n' )* {skip();}
        ;
