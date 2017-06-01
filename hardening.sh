#!/bin/bash

###############################################################

# Script de checagens de hardening;Diego Oliveira; Suporte Informática; 2017#
# ver: 1.00.0009

###############################################################

# importação do script que gera o o relatório em html
source geradorRelatorioHtml.sh

# Parametros Globais

export VERSAO="1.09"
export SELINUX=1
export SILENCIOSO=1
export TIPO_PACOTE=""
export REDHAT="0"
export IP_HOST=$(ip a | grep "inet "| awk '{print $2}'| grep -v "127.0.0.1/8" | cut -d"/" -f1| head -n1)
export LOGFILE="hardening-${IP_HOST}-$(hostname)-$(date +"%d-%m-%Y_%T").csv"

# tipo de gerenciador de inicialização (Systemv, SystemD ou Upstart)
export TIPO_INIT=''

# percentual de destaque de ocupação dos filesystems
export LIMITE_ALERTA_OCUPACAO_DISCO=80


function banner()
{
	echo "====================================================================="	
	echo " Ferramenta de avaliação de HARDENING - Versão: $VERSAO"
	echo "====================================================================="	
}

function isRoot()
{
	MyUID=$(id -u)
	MyUSER=$(getent passwd $MyUID | cut -d":" -f1)
	if [ "$MyUID" -ne "0" ];then
		echo "[ERROR] User $MyUSER not privileged. Use sudo $0"
		exit 1
	fi
	banner
}

function ls_sem_total()
{
	ls -l $1 | grep -v ^total
}

function status()
{
	echo "[ INFO ] $(date "+%x %T") -"
}

function gera_log ()
{	
	MENSAGEM="$1"	
	if [ "$SILENCIOSO" -eq 1 ];then
		echo "$(hostname)\;\"$MENSAGEM\"" >> $LOGFILE
	else
		echo "$(hostname)\;\"$MENSAGEM\"" | tee -a $LOGFILE	
	fi
}

function gera_log2 ()
{	
	ROTINA="$1"
	STATUS="$2"
	CATEGORIA="$3"	
	MENSAGEM="$4"
	
	case "$STATUS" in
		"FALHA")
			STATUS="<p class='falha'>$STATUS</p>"
		;;
		"SUCESSO")
			STATUS="<p class='sucesso'>$STATUS</p>"
		;;
		"INFO")
			STATUS="<p class='info'>$STATUS</p>"
		;;
		*)
		;;
	esac
		
	if [ "$SILENCIOSO" -eq 1 ];then
		#echo "$(hostname);$ROTINA;$STATUS;$CATEGORIA;\"$MENSAGEM\"" >> $LOGFILE
		echo "$(hostname);$ROTINA;$STATUS;$CATEGORIA;\"$MENSAGEM\"" >> $LOGFILE
	else
		#echo "$(hostname);$ROTINA;$STATUS;$CATEGORIA;\"$MENSAGEM\"" | tee -a $LOGFILE
		echo "$(hostname);$ROTINA;$STATUS;$CATEGORIA;\"$MENSAGEM\"" | tee -a $LOGFILE
	fi	
}

function gera_log3 ()
{	
	MENSAGEM="$1"	
	
	if [ "$SILENCIOSO" -eq 1 ];then
		echo "$(hostname);$MENSAGEM" >> $LOGFILE
	else
		echo "$(hostname);$MENSAGEM" | tee -a $LOGFILE
	fi	
}

function cabecalho()
{
	export TITULO="Resumo geral do Servidor"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	echo "$(status) Obtendo informações do servidor..."
	gera_log2 "$CONTROLE" "INFO" "Data de Apuração" "$(date +"%x %T")"
	gera_log2 "$CONTROLE" "INFO" "Usuário executor do levantamento" "$(whoami)"
	gera_log2 "$CONTROLE" "INFO" "Funcionamento desde" "$(uptime -s 2> /dev/null ||uptime 2> /dev/null)"
	export HOSTNAME_ATUAL=$(hostname -s 2>/dev/null || hostname 2>/dev/null)
	gera_log2 "$CONTROLE" "INFO" "Nome do computador" "$HOSTNAME_ATUAL"
	gera_log2 "$CONTROLE" "INFO" "Nome FQDN do computador" "$(hostname -f 2>/dev/null || hostname 2>/dev/null)"

	#gera_log2 "$CONTROLE" "INFO" "Sistema Operacional" "$(cat /etc/system-release)"

#	gera_log2 "$CONTROLE" "INFO" "Endereço IP do computador" "$(ip a | grep "inet "| awk '{print $2";"$7,$8";"}'| grep -v "127.0.0.1/8")"
	gera_log2 "$CONTROLE" "INFO" "Endereço IP do computador" "$(ip a | grep "inet "| awk '{print $2" ("$7,$8");"}'| grep -v "127.0.0.1/8"| tr '\n' ' '; echo)"
	gera_log2 "$CONTROLE" "INFO" "Versão do Kernel" "$(uname -r)"
	gera_log2 "$CONTROLE" "INFO" "Arquitetura" "$(arch)"
	
	#Habilita controles para Red Hat 
	cat /etc/system-release 2>/dev/null | grep -i "Red Hat" && export REDHAT=1
		
}

function getCpuInformation()
{
    echo "$(status) Obtendo dados da CPU..."
    export TITULO="CPU - Load average"
    export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESULTADO=$(uptime | awk '{print $5}')
	if [ "$RESULTADO" == 'load' ];then
		DADOS=$(uptime | sed 's/, /;/g' | awk '{print $7";"$8";"$9}' )
	else
		RESULTADO=$(uptime | awk '{print $6}')
		if [ "$RESULTADO" == 'load' ];then
			DADOS=$(uptime | sed 's/, /;/g' | awk '{print $8";"$9";"$10}')	
		else
			DADOS=$(uptime | sed 's/, /;/g' | awk '{print $9";"$10";"$11}')	
		fi
	fi		
    gera_log2 "$CONTROLE" "INFO" "Média de Carga 1min, 5min, 15min" "$DADOS"
	
	export TITULO="CPU - Total de CPUs"
    export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
		
    gera_log2 "$CONTROLE" "INFO" "Quantidade de CPUs" "$(cat /proc/cpuinfo | grep -c processor)"
	
	export TITULO="CPU - Informação da CPU"
    export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
		
    gera_log2 "$CONTROLE" "INFO" "Quantidade de CPUs" "$(lscpu 2>//dev/null | tr '\n' ';'; echo)"
	
}

function getLinuxVersion()
{
    echo "$(status) Obtendo informações sobre o sistema operacional..."
    export TITULO="Resumo geral do Servidor"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
    RHEL=$(cat /etc/redhat-release 2> /dev/null)
    DEBIAN=$(cat /etc/*release* 2> /dev/null | grep PRETTY_NAME | cut -d"=" -f2 | sed 's/"//g')
    VER=""
    
    #echo "RHEL: $RHEL, DEBIAN: $DEBIAN"
    if [ -z "$RHEL" ]; then
        if [ -z "$DEBIAN" ]; then
            # nenhuma coleta foi bem sucedida
            exit
        else
            VER="$DEBIAN"
            export TIPO_PACOTE="DEB"    
        fi
    else
        VER="$RHEL"
        export TIPO_PACOTE="RPM"    
    fi
    
    gera_log2 "$CONTROLE" "INFO" "Sistema Operacional" "$VER"

}

function getKernel()
{
    echo "$(status) Obtendo dados do kernel..."
    export TITULO="Versão do Kernel"
    export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	#uname -a
    gera_log2 "$CONTROLE" "INFO" "Sistema Operacional" "$(uname -a)"
}

function getTimeZone()
{
    echo "$(status) Obtendo dados do configurações regionais..."
    export TITULO="Configurações regionais"
    export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	timedatectl &> /dev/null
	RESP="$?"
	if [ "$RESP" -eq 0 ];then
		DADOS=$(timedatectl | tr '\n' ';'; echo)
		gera_log2 "$CONTROLE" "INFO" "Informações de Timezone" "$DADOS"
	else 
		DADOS=$(date +"%d-%m-%Y %T %Z (%z)" | tr '\n' ';'; echo)
		if [ -e "/etc/sysconfig/clock" ];then
			DADOS=$DADOS$(cat /etc/sysconfig/clock | tr '\n' ';'; echo)			
		fi
		gera_log2 "$CONTROLE" "INFO" "Informações de Timezone" "$DADOS"		
	fi
	    
    # cat /etc/locale.conf 
}


function getConfereDateTime()
{
    echo "$(status) Obtendo dados do configurações de horário..."
    export TITULO="Configurações de horário"
    export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	HORA_EXTERNA=$(curl -s --url "http://www.horariodebrasilia.org" | grep '<p id="relogio">' | egrep -o "([0-9]){2}\:([0-9]{2})\:([0-9]){2}")
	HORA_LOCAL=$(date "+%H:%M:%S")
	
	if [ "$HORA_EXTERNA" ==  "$HORA_LOCAL" ];then
		STATUS="SUCESSO"
		
	else 
		STATUS="FALHA"
	fi
	    
    gera_log2 "$CONTROLE" "$STATUS" "Verificação de horários" "Hora Externa: $HORA_EXTERNA. Hora Local: $HORA_LOCAL"
}



function getHosts()
{
	echo "$(status) Obtendo informação de hosts..."
	export TITULO="Arquivo de HOSTS - /etc/hosts"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(getent hosts| tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Configuração de /etc/hosts" "$DADOS"
			
}

function getSelinux()
{
	echo "$(status) Obtendo informação sobre SELinux..."
	export TITULO="SELinux - Configurações"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	getenforce &>/dev/null
	if [ $? -ne 0 ];then
		gera_log2 "$CONTROLE" "INFO" "Sistema não utiliza SELinux" "$DADOS"
		return 1	
	fi
	
	DADOS=$(getenforce | tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "SELinux em modo" "$DADOS"
	
	DADOS=$(cat /etc/sysconfig/selinux | grep "^SELINUX=" | tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "SELinux em modo persistente" "$DADOS"
			
}

function getRclocal()
{
	echo "$(status) Obtendo informação do /etc/rc.local..."
	export TITULO="Arquivo RC.LOCAL"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(cat /etc/rc.local | grep -v "^#" | tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Configuração de /etc/rc.local" "$DADOS"			
}

function getProcess()
{
	echo "$(status) Obtendo informação dos processos em execução..."
	export TITULO="Processos - Processos em execução"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(ps axo uname:20,group:20,pid,ppid,tty,vsz,time,stat,ucmd | sed "s/</'<'/g" |tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Processos em execução" "$DADOS"			
}

function getProcessPerUser()
{
	echo "$(status) Obtendo informação dos processos em execução por usuário..."
	export TITULO="Processos - Total de processos por Usuário"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(ps axo uname:20 --no-heading| sort | uniq -c | sort -r | sed "s/</'<'/g" |tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" " Total de processos em execução por usuário " "$DADOS"			
}

function getLimits()
{
	# apenas para RHEL
	echo "$(status) Obtendo informação de limites..."
	export TITULO="Limits - Limits ativos no sistema"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(ulimit -a| tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Configuração atual dos pam_limits" "$DADOS"
	
	FILE="/etc/security/limits.conf"
	if [ -e "$FILE" ];then
		# Só emite se o limits.conf for encontrado
		DADOS=$(cat $FILE|grep -v "^#"| tr '\n' ';'; echo)
		
		export TITULO="Limits - Definição de configurações padroes - Limits.conf"
		export FORMATO_HTML="LISTASIMPLES"
		export CONTROLE="$FORMATO_HTML;$TITULO"		
		
		gera_log2 "$CONTROLE" "INFO" "Configuração atual dos limits.conf" "$DADOS"
	fi
			
	export TITULO="Limits - Configurações dos arquivos no /etc/security/limits.d"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	echo "$(status) Obtendo informação de agendamentos em diretórios..."
	DADOS=$(for dir in /etc/security/limits.d;do 
				for file in $(ls $dir);do 
					#echo -e "<p class='info'>ARQUIVO:$dir/$file</p><br/>";
					echo -e "<p class='info'>ARQUIVO:$dir/$file</p>";
					#echo
					 
					cat $dir/$file | grep -v "^#" | grep -v "^$" ; 
				done; 
			done | tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Extras do /etc/security/limits.d.*" "$DADOS"				
}

function getCrontab()
{
	# apenas para RHEL
	echo "$(status) Obtendo informação de agendamentos..."
	export TITULO="Crontab - Agendamentos"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(cat /etc/crontab | grep -v ^# | grep -v ^$| tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Agendamentos do /etc/crontab" "$DADOS"

	echo "$(status) Obtendo informação de agendamentos em diretórios..."
	export TITULO="Crontab - Arquivos extras"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(for dir in /etc/cron.{d,daily,hourly,monthly,weekly};do 
				for file in $(ls $dir);do 
					echo -e "<p class='info'>ARQUIVO: $dir/$file</p>";
					cat $dir/$file | grep -v "^#" | grep -v "^$" ; 
					echo
				done; 
			done | tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Extras do /etc/cron.*" "$DADOS"			
}

function getRoutes()
{
	# apenas para RHEL
	echo "$(status) Obtendo informação de rotas..."
	export TITULO="Redes - Rotas ativas"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	DADOS=$(route -n| tr '\n' ';'; echo)		
	gera_log2 "$CONTROLE" "INFO" "Rotas e gateways do sistema" "$DADOS"			
}

function getOpenPorts()
{
	echo "$(status) Obtendo lista de serviços ativos..."
	export TITULO="Redes - Portas de serviços abertas"		
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	PORTAS=$(ss -putan4 | grep LISTEN | awk '{print $5"/"$1}'| awk -F":" '{print $2}')
	# echo $PORTAS   # debug
	for i in ${PORTAS}; do
		#cat /etc/services | grep " $i"| sed 's/#//g' | awk '{print $2"("$1");"$3,$4,$5,$6,$7,$8,$9}'
		gera_log2 "$CONTROLE" "INFO" "Portas de serviços em escuta" "$i;$(cat /etc/services | grep " $i"| sed 's/#//g' | awk '{print $2"("$1");"$3,$4,$5,$6,$7,$8,$9}')"
		
	done	
}

function getInternetAccess()
{
	echo "$(status) Obtendo informações sobre acesso a internet..."
	export TITULO="Redes - Acesso a internet"		
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	ping -c1 8.8.8.8 &> /dev/null
	RESP="$?"
	if [ "$RESP" -eq 0 ];then
		gera_log2 "$CONTROLE" "SUCESSO" "Acesso a internet usando Endereço IP" 
	else
		gera_log2 "$CONTROLE" "FALHA" "Falha no acesso a internet usando Endereço IP" 
	fi
	
	ping -c1 google.com &> /dev/null
	RESP="$?"
	if [ "$RESP" -eq 0 ];then
		gera_log2 "$CONTROLE" "SUCESSO" "Acesso a internet usando DNS" 
	else
		gera_log2 "$CONTROLE" "FALHA" "Falha no acesso a internet usando DNS" 
	fi
	
}

function getFirewalld()
{
	echo "$(status) Obtendo Configurações do Firewalld..."
	export TITULO="Redes - Firewall - Regras Firewalld"		
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	EXISTE=""
	EXISTE=$(ps -ef | grep "firewalld"| grep -v grep )
	if [ -n "$EXISTE" ];then
		REGRAS=$(firewall-cmd --list-all | tr '\n' ';'; echo)
		gera_log2 "$CONTROLE" "INFO" "Regras do firewalld" "$REGRAS"
	fi
	
}

function getIptables()
{
	echo "$(status) Obtendo Configurações do iptables..."
	export TITULO="Redes - Firewall - Regras Iptables"		
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	REGRAS=$(iptables -t filter -nL| tr '\n' ';'; echo)
	gera_log2 "$CONTROLE" "INFO" "<p class='info'>Regras da tabela Filter</p>" "$REGRAS"
	REGRAS=$(iptables -t nat -nL| tr '\n' ';'; echo)
	gera_log2 "$CONTROLE" "INFO" "<p class='info'>Regras da tabela NAT</p>" "$REGRAS"
	REGRAS=$(iptables -t mangle -nL| tr '\n' ';'; echo)
	gera_log2 "$CONTROLE" "INFO" "<p class='info'>Regras da tabela Mangle</p>" "$REGRAS"
		
	
}

function getInitManager()
{
	# identificando se o sistema utilizar SystemV, Systemd ou upstart
	#echo "Entrou na getInitManager"
	INIT_1=$(stat /proc/1/exe | grep proc | awk '{print $4}' | sed 's/[“”""]//g')
	#echo "INIT_1: $INIT_1"
	case "$INIT_1" in
	"/sbin/init"|/sbin/init)
		#echo "Entrou em: $INIT_1"  #DEBUG
		INIT_2=$(stat "$INIT_1" | grep init | awk '{print $2}' | sed 's/[“”""]//g')
		#echo "INIT_2: $INIT_2"  #DEBUG
		case "$INIT_2" in
		"/sbin/init")
			#echo "Entrou em: $INIT_2" #DEBUG
			TIPO_INIT="SYSTEMV"
			/sbin/init --version | grep -i -o upstart &> /dev/null && TIPO_INIT="UPSTART"
			;;
		"/lib/systemd/systemd"|"/usr/lib/systemd/systemd")
			#echo "Entrou em: $INIT_2"   #DEBUG
			TIPO_INIT="SYSTEMD"
			;;
		esac
		;;
	"/lib/systemd/systemd"|"/usr/lib/systemd/systemd")
		TIPO_INIT="SYSTEMD"
		;;
	"/sbin/upstart")
		TIPO_INIT="UPSTART"
		;;
	*)
		echo "[Erro] Não é nenhuma das alternativas"				
	esac
	
	export $TIPO_INIT
}
function getServicesEnabled()
{
    echo "$(status) Obtendo informações de serviços ativos no boot..."
	export TITULO="Serviços ativos no boot"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
    RESP=''
	# identificando o tipo de gerenciador de inicialização
	getInitManager
	#echo "TIPO_INIT: $TIPO_INIT"  # DEBUG
	
	case "$TIPO_PACOTE" in
        "DEB")
        			
			case "$TIPO_INIT" in
				SYSTEMV)
				;;
				SYSTEMD)
				;;
				UPSTART)
					RESP="$RESP <p class='info'> Upstart scripts em execução </p>"	
					RESP=$RESP$(initctl list | grep start 2>/dev/null)
					RESP=$(echo "$RESP"| tr '\n' ';'; echo)
					
				;;
			esac
			;;
        "RPM")
        	#RHEL antigos
			RESP=""
			RESP="$RESP <p class='info'>SystemV - Seviços ativos no boot</p>"	
            RESP="$RESP$(chkconfig --list 2>/dev/null| egrep "3:on|3:sim|5:on|5:sim";echo "<br/>")"
			
			INITTAB=$(cat /etc/inittab | grep -v "#" 2>/dev/null)
			if [ -n "$INITTAB" ];then
				RESP="$RESP <p class='info'>SystemV - /etc/inittab</p>"	
				RESP="$RESP $(cat /etc/inittab | grep -v "#" 2>/dev/null)"	
			fi
			
            #RESP=$RESP"SystemD - Defaul target: "$(systemctl get-default 2>/dev/null;echo "<br/>")
            RESP="$RESP <p class='info'> SystemD - Defaul target </p>"	
			RESP="$RESP $(systemctl get-default 2>/dev/null;echo "<br/>")"
			
			RESP=$RESP$(systemctl list-units --type=service 2>/dev/null)
            RESP=$(echo "$RESP"| tr '\n' ';'; echo)
            ;;    
    esac

    gera_log2 "$CONTROLE" "INFO" "Serviços ativo no boot" "$RESP"
    
}


function ocupacaoDiscos()
{
	echo "$(status) Avaliando a ocupação dos discos..."
	export TITULO="Discos - Ocupação de partiçõeos/volumes"	
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	
	
	DISCOS=$(df -Ph | grep ^/dev | awk '{print $1"("$6");"$2"/"$3";"$5}')
	#echo $DISCOS
	for i in ${DISCOS}; do
		OCUPADO=''
		OCUPADO=$(echo "$i" | cut -d";" -f3| sed 's/%//g')
		#echo "OCUPADO: $OCUPADO, LIMITE_ALERTA_OCUPACAO_DISCO: $LIMITE_ALERTA_OCUPACAO_DISCO"  # DEBUG
		if [ "$OCUPADO" -gt "$LIMITE_ALERTA_OCUPACAO_DISCO" ]; then
			#echo "entrou em falha"  #DEBUG
			STATUS_ALERTA='falha'
		else
			#echo "entrou em sucesso"  #DEBUG
			STATUS_ALERTA='sucesso'
		fi
		gera_log2 "$CONTROLE" "INFO" "Ocupação dos Discos" $(echo "<p class='$STATUS_ALERTA'>$i</p>")
	done	
}

function memoria_fisica()
{
	echo "$(status) Avaliando a ocupação da memória física..."
	export TITULO="Memória - Dados sobre a memória física"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	# em caso do comando não existir ou parametro inválido por conta de versão
	lshw -short -class memory &> /dev/null
	if  [ "$?" -ne 0 ];then
		gera_log2 "$CONTROLE" "FALHA" "Itens de Memória física" "Comando \"lshw\" não encontrado"
		return 1
		
	fi
	
 	MEMORIA=$(lshw -short -class memory | grep -v -E "cache|Device"| grep -v "=" | awk '{print $3,$4,$5,$6,$7,$8,$9,$10}')
#	MEMORIA=$(lshw -short -class memory | grep -v -E "cache|Device"| grep -v "=" | awk '{print "\"" $3,$4,$5,$6,$7,$8,$9,$10"\""}')
	
	#echo $DISCOS
	IFS_OLD=$IFS
	IFS=$'\n'
	for i in ${MEMORIA}; do
		gera_log2 "$CONTROLE" "INFO" "Itens de Memória física" "$i"
	done	
	#sudo lshw -short -class memory | grep -v cache
	IFS=$IFS_OLD
}

function memoria_ram()
{
	echo "$(status) Avaliando a ocupação da memória RAM..."
	export TITULO="Memória - Utilização de memória RAM"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	# em caso do comando não existir ou parametro inválido por conta de versão
	PARAM="-h"
	MEM_MSG="Memória RAM"
	free $PARAM &> /dev/null
	if  [ "$?" -ne 0 ];then
		export PARAM="-m"
		export MEM_MSG="Memória RAM (MB)"
	fi 
	
 	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1";"$2";"$3; else print $2";"$3";"$4}')
	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	MEMORIA=$(free "$PARAM" | egrep -v "^Swap|cache:" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Swap|cache:" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Swap|cache:" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	gera_log2 "$CONTROLE" "INFO" "$MEM_MSG" "\"$MEMORIA\""
}

function memoria_swap()
{
	echo "$(status) Avaliando a ocupação da memória SWAP..."
	export TITULO="Memória - Utilização de memória SWAP"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	# em caso do comando não existir ou parametro inválido por conta de versão
	PARAM="-h"
	MEM_MSG="Memória SWAP"
	free $PARAM &> /dev/null
	if  [ "$?" -ne 0 ];then
		export PARAM="-m"
		export MEM_MSG="Memória SWAP (MB)"
	fi 
	
 	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1";"$2";"$3; else print $2";"$3";"$4}')
	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	MEMORIA=$(free "$PARAM" | egrep -v "^Mem|cache:" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Mem|cache:" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Mem|cache:" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	gera_log2 "$CONTROLE" "INFO" "$MEM_MSG" "\"$MEMORIA\""
}


function search_nameserver()
{
	echo "$(status) Checando diretiva search - DNS client..."
	export TITULO="DNS - Consulta de diretivas"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	TEST1=$(cat /etc/resolv.conf | grep ^search | awk '{print $2}')

	if [ -n "$TEST1" ]; then
		gera_log2 "$CONTROLE" "SUCESSO" "Diretiva Search encontrado no resolv.conf" "$TEST1"
	else
		gera_log2 "$CONTROLE" "FALHA" "Diretiva Search não encontrado no resolv.conf"
	fi
}

function test_dns()
{
	echo "$(status) Checando serviço de DNS..."
	export TITULO="DNS - Teste de DNS"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	URL_REFERENCIA="suporteinformatica.com"
	IP_REFERENCIA="67.20.87.167"
	
	which nslookup &> /dev/null
	RESP="$?"
	
	if [ $RESP -eq 0 ];then
		# Só entra se o nslookup tiver instalado ou presente no path de comandos
		for i in ${1}; do
			IP_TEMP=$(nslookup $URL_REFERENCIA $i | grep Address | grep -v "#53"$ | awk '{print $2}')
			if [ "$IP_TEMP" = "$IP_REFERENCIA" ];then
				gera_log2 "$CONTROLE" "SUCESSO" "Nameservers resolve endereços corretamente" "$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
			else
				gera_log2 "$CONTROLE" "FALHA" "Nameservers não resolve endereços corretamente" "$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
			fi
		done
	else
		gera_log2 "$CONTROLE" "FALHA" "Não foi possivel utilizar a ferramenta nslookup"
	fi
}

function valid_nameserver()
{
	echo "$(status) Checando nameservers válidos do /etc/resolv.conf..."
	export TITULO="DNS - Validação de Nameservers"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	TEST1=$(cat /etc/resolv.conf | grep ^nameserver | awk '{print $2}')

	if [ -n "$TEST1" ]; then
# 		URL_REFERENCIA="suporteinformatica.com"
# 		IP_REFERENCIA="67.20.87.167"
# 		
# 		for i in ${TEST1}; do
# 			IP_TEMP=$(nslookup $URL_REFERENCIA $i | grep Address | grep -v "#53"$ | awk '{print $2}')
# 			if [ "$IP_TEMP" = "$IP_REFERENCIA" ];then
# 				gera_log "SUCCESS;Nameservers resolve endereços corretamente;$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
# 			else
# 				gera_log "FALHA;Nameservers não resolve endereços corretamente;$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
# 			fi
# 		done
		
		TOTAL=$(echo "$TEST1" | wc -l)
		NAMESERVER_LIST=$(echo "$TEST1" | tr '\n' ' ') 
		case $TOTAL in
			1)
				test_dns "${TEST1}"
				export TITULO="DNS - Validação de Nameservers"
				export FORMATO_HTML="SUBCATEGORIZADA"
				export CONTROLE="$FORMATO_HTML;$TITULO"
				
				gera_log2 "$CONTROLE" "ALERT" "Apenas 1 nameserver foi encontrado no resolv.conf" "$NAMESERVER_LIST"
				;;
			2) 	
				test_dns "${TEST1}"
				export TITULO="DNS - Validação de Nameservers"
				export FORMATO_HTML="SUBCATEGORIZADA"
				export CONTROLE="$FORMATO_HTML;$TITULO"
				
				gera_log2 "$CONTROLE" "INFO" "2 nameservers foram encontrado no resolv.conf" "$NAMESERVER_LIST"
				;;
			3) 	
				test_dns "${TEST1}"
				export TITULO="DNS - Validação de Nameservers"
				export FORMATO_HTML="SUBCATEGORIZADA"
				export CONTROLE="$FORMATO_HTML;$TITULO"
				
				gera_log2 "$CONTROLE" "INFO" "3 nameservers foram encontrado no resolv.conf" "$NAMESERVER_LIST"
				;;
			*)	
				test_dns "${TEST1}"
				export TITULO="DNS - Validação de Nameservers"
				export FORMATO_HTML="SUBCATEGORIZADA"
				export CONTROLE="$FORMATO_HTML;$TITULO"
				
				gera_log2 "$CONTROLE" "ALERT" "Apenas os 3 primeiros nameservers do resolv.conf serão utilizados" "Foram encontrados $TOTAL: $TEST1"
				;;
		esac
# 		
		
	else
		export TITULO="DNS - Validação de Nameservers"
		export FORMATO_HTML="SUBCATEGORIZADA"
		export CONTROLE="$FORMATO_HTML;$TITULO"
		
		gera_log2 "$CONTROLE" "FALHA" "Diretiva nameserver não encontrado no resolv.conf"
	fi
}

function consulteMyName()
{
	echo "$(status) Checando nome do servidor no DNS..."
	export TITULO="DNS - Valida Nome zona direta"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	# pode ter mais de um endereço
	MY_HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null)
	MY_ADDRERSS=$(ip a | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d"/" -f1)
	
	which nslookup &> /dev/null
	RESP="$?"
	
	if [ $RESP -eq 0 ];then
	
		#echo "MY_ADDRERSS $MY_ADDRERSS"
		for DNS in $(cat /etc/resolv.conf | grep nameserver | awk '{print $2}');do
			CONSULTA=$(nslookup "$MY_HOSTNAME" "$DNS" | tr '\n' ' ')
			#CONSULTA=$(nslookup "$MY_HOSTNAME" "$DNS" )
			RESULT="$?"
			#echo "CONSULTA $CONSULTA"
			if [ "$RESULT" -ne 0 ];then
				gera_log2 "$CONTROLE" "FALHA" "DNS não resolve para o nameserver: $DNS" "$CONSULTA"
			else
				ADDRERSS_DNS=$(echo "$CONSULTA" | grep Address | grep -v "#"  | awk '{print $2}')
				#echo "ADDRERSS_DNS $ADDRERSS_DNS"
				
				for ADDR in $MY_ADDRERSS; do
					if [ "$ADDRERSS_DNS" == "$ADDR" ];then
						gera_log2 "$CONTROLE" "SUCESSO" "Nameserver: $DNS resolve corretamente" "$CONSULTA"
					else	
						gera_log2 "$CONTROLE" "FALHA" "DNS: $DNS não resolve o Endereço: $MY_HOSTNAME" "$(echo $CONSULTA | tr ';' ' ')"					
					fi
				done	
			fi
		done
	else
		gera_log2 "$CONTROLE" "FALHA" "Não foi possivel utilizar a ferramenta nslookup"	
	fi	
}

function consultaIPreverso()
{
	echo "$(status) Checando IP do servidor no DNS reverso..."
	export TITULO="DNS - Valida Nome zona reversa"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	MY_HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null)
	# pode ter mais de um endereço
	MY_ADDRERSS=$(ip a | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}' | cut -d"/" -f1)
	
	which nslookup &> /dev/null
	RESP="$?"
	
	if [ $RESP -eq 0 ];then
		#echo "MY_ADDRERSS $MY_ADDRERSS"
		for DNS in $(cat /etc/resolv.conf | grep nameserver | awk '{print $2}');do
			for ADDR in $MY_ADDRERSS; do
				CONSULTA=$(nslookup "$ADDR" "$DNS" | tr '\n' ' ')
				RESULT="$?"
				
				if [ "$RESULT" -ne 0 ];then
					gera_log2 "$CONTROLE" "FALHA" "DNS não resolve para o nameserver: $DNS" "$CONSULTA"
				else
					NAME_DNS=$(echo "$CONSULTA" | grep Name | grep -v "#"  | awk '{print $2}')
					#echo "NAME_DNS $NAME_DNS"
					if [ "$NAME_DNS" == "$MY_HOSTNAME" ];then
						gera_log2 "$CONTROLE" "SUCESSO" "Nameserver: $DNS resolve corretamente $ADDR em $MY_HOSTNAME" "$CONSULTA"
					else	
						gera_log2 "$CONTROLE" "FALHA" "DNS: $DNS não resolve o Endereço: $ADDR" "$(echo $CONSULTA | tr ';' ' ')"					
					fi
				fi
			done	
		done
	else
		gera_log2 "$CONTROLE" "FALHA" "Não foi possivel utilizar a ferramenta nslookup"	
	fi	
}

function test_file () {
	#Permissão dos arquivos de senha do sistema local
	
	export TITULO="Arquivos - Teste de permissões especiais"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	if [ ! -e permissions.txt ]; then
		#Criando o arquivo de permissões para comparação caso ele não exista
		echo "$(status) Criando o arquivo de permissoes..."
		echo "/etc/passwd;root;root;-r--r--r--;" > permissions.txt
		echo "/etc/shadow;root;root;-r--------;" >> permissions.txt
		echo "/etc/group;root;root;-r--------;" >> permissions.txt
		echo "/etc/gshadow;root;root;-r--------;" >> permissions.txt
	fi
	
	for i in `cat permissions.txt`;do
		FILE=`echo $i | awk -F ';' '{print $1}'`
		USER1=`echo $i | awk -F ';' '{print $2}'`	
		GROUP1=`echo $i | awk -F ';' '{print $3}'`
		PERM=`echo $i | awk -F ';' '{print $4}'`
		
		echo "$(status) Checando permissões do arquivo $FILE"
		TEST1=$(/bin/ls -l $FILE | awk '{print $1}')

		if [ "$TEST1" == "$PERM" ]; then
			gera_log2 "$CONTROLE" "SUCESSO" "Permissões arquivos do sistema" "$FILE;$TEST1"
		else
			gera_log2 "$CONTROLE" "FALHA" "Permissões arquivos do sistema" "$FILE;$TEST1 (Correta: $PERM)"
		fi

		echo "$(status) Checando dono do arquivo $FILE"
		TEST1=$(/bin/ls -l $FILE | awk '{print $3}')

		if [ "$TEST1" = "$USER1" ]; then
            gera_log2 "$CONTROLE" "SUCESSO" "Proprietário do arquivo" "$FILE;$TEST1"
        else
            gera_log2 "$CONTROLE" "FALHA" "Proprietário do arquivo" "$FILE;$TEST1 (Correto: $USER1)"
        fi

        echo "$(status) Checando grupo dono do arquivo $FILE"
        TEST1=$(/bin/ls -l $FILE | awk '{print $4}')

        if [ "$TEST1" = "$GROUP1" ]; then
			gera_log2 "$CONTROLE" "SUCESSO" "Grupo proprietário do arquivo" "$FILE;$TEST1"
		else
			gera_log2 "$CONTROLE" "FALHA" "Grupo proprietário do arquivo" "$FILE;$TEST1 (Correto: $GROUP1)"
		fi
	done

	rm -f permissions.txt

}

function world_writable() {
	
	echo "$(status) Checando arquivos com permissão de escrita para outros..."
	export TITULO="Arquivos - Escrita para outros"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -type f -perm -0002 2> /dev/null | xargs -I '{}' ls -l '{}' |awk -v funcao="$CONTROLE" '{print funcao ";FALHA;Permissão de escrita outros usuários;"$9";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
}

function getUsers()
{
    echo "$(status) Obtendo relação de usuários do sistema..."
    export TITULO="Usuários - Relação de usuários"
    export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RES=$(cat /etc/passwd | sort -n -t":" -k3 | tr '\n' ';'; echo)
    gera_log2 "$CONTROLE" "INFO" "Lista de usuários" "\"$RES\""
}

function getUsersValidLogin()
{
    echo "$(status) Obtendo relação de usuários do sistema com terminal válido..."
    export TITULO="Usuários - Usuários com terminal"
    export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RES=$(cat /etc/passwd | egrep "/bin/bash|/bin/sh|/bin/ksh" | sort -n -t":" -k3 | tr '\n' ';'; echo)
    gera_log2 "$CONTROLE" "INFO" "Lista de usuários com acesso ao terminal" "\"$RES\""
}

function getRootUsers()
{
    echo "$(status) Obtendo relação de usuários root com UID 0..."
    export TITULO="Usuários - \"UID 0\" Usuários Root"
    export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RES=$(cat /etc/passwd | grep ":x:0:" | sort -n -t":" -k3 | tr '\n' ';'; echo)
    gera_log2 "$CONTROLE" "INFO" "Lista de usuários root" "\"$RES\""
}

function getSudoers()
{
    echo "$(status) Obtendo informações do sudo..."
    export TITULO="Usuários - Configuração do  sudo"
    export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RES=$(cat /etc/sudoers | grep -v "^#" | grep -v "^$"| tr '\n' ';'; echo)
    gera_log2 "$CONTROLE" "INFO" "Arquivo sudoers" "\"$RES\""
}

function getGroups()
{
	echo "$(status) Obtendo relação de grupos do sistema..."
	export TITULO="Grupos - Relação de Grupos"
    export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RES=$(cat /etc/group | sort -n -t":" -k3 | tr '\n' ';'; echo)
    gera_log2 "$CONTROLE" "INFO" "Lista de Grupos" "\"$RES\""
}


function nouser() 
{
	echo "$(status) Checando arquivos com proprietário desconhecido..."
	export TITULO="Arquivos - Proprietários desconhecidos"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -printf "%s %U %h/%f\n" 2> /dev/null | awk -v funcao="$CONTROLE" '{print funcao ";FALHA;Proprietário desconhecido;"$3" "$4" "$5" "$6" "$7";"$2";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
	

}
function df_nouser()
{
	echo "$(status) Checando ocupação dos arquivos com proprietário desconhecido..."
	export TITULO="Arquivos - Ocupação de aquivos de proprietários desconhecidos"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -printf "%s\n" 2> /dev/null| awk -v funcao="$CONTROLE" '{soma+=$1}END{printf funcao ";FALHA;Ocupação por arquivos com proprietário desconhecido; %f bytes\n",soma }' | xargs -I '{}' bash -c "gera_log3 '{}'"
}

function nogroup() 
{
	echo "$(status) Checando arquivos com grupo proprietário desconhecido..."
	export TITULO="Arquivos - Grupos desconhecidos"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup -printf "%s %g %h/%f\n" 2> /dev/null| awk -v funcao="$CONTROLE" '{print funcao ";FALHA;Grupo proprietário desconhecido;"$3" "$4" "$5" "$6" "$7";"$2";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
}

function df_nogroup()
{
	echo "$(status) Checando ocupação dos arquivos com grupo proprietário desconhecido..."
	export TITULO="Arquivos - Ocupação de aquivos de grupos desconhecidos"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup -printf "%s\n" 2> /dev/null | awk -v funcao="$CONTROLE" '{soma+=$1}END{printf funcao ";FALHA;Ocupação por arquivos com grupo proprietário desconhecido; %f bytes\n",soma }' | xargs -I '{}' bash -c "gera_log3 '{}'"
}


function nopasswd()
{
	echo "$(status) Checando se há usuários sem senha..."
	export TITULO="Usuários sem senha"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	cat /etc/shadow | awk -v funcao="$CONTROLE" -F: '($2 == "" ) {print funcao ";FALHA;Usuário sem senha;"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
}

function checkhome()
{
    echo "$(status) Checando permissões dos diretórios HOME de usuários válidos do /etc/passwd..."
	export TITULO="Arquivos - Permissões do HOME"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
    # Configurando em caso de utilização de SELinux
    if [ "$SELINUX" -eq 1 ]; then
    	PERMISSAO_IDEAL="drwx------."
    else 
    	PERMISSAO_IDEAL="drwx------"
    fi
        
	LISTA=$(egrep -v '(root|halt|sync|shutdown)' /etc/passwd| awk -F: '($7 != "/sbin/nologin") {print $1" "$3" "$6}')
    for i in $LISTA ; do
		#Obtendo os dados
		dir=`echo $i| cut -d" " -f3`
		uid=`echo $i| cut -d" " -f2`
		user=`echo $i| cut -d" " -f1`
		dirperm=`ls -ld $dir 2>/dev/null | cut -f1 -d" "`
		#echo "dirperm: $dirperm dir: $dir :uid $uid user: $user"   # debug
		if [ "$dirperm" != "$PERMISSAO_IDEAL" ]; then
			gera_log2 "$CONTROLE" "FALHA" "Permissao do diretorio Home" "Home: $dir; Permissão: $dirperm (Permissão correta: $PERMISSAO_IDEAL)"
		else
			gera_log2 "$CONTROLE" "SUCESSO" "Permissao do diretorio Home" "Home: $dir; Permissão: $dirperm (Permissão correta: $PERMISSAO_IDEAL)"	
		fi

		correto=`ls -ldn $dir 2>/dev/null | awk '{print $3}'`
		#if [ "$correto" -ne "$uid" ]; then
		if [ "$correto" != "$uid" ]; then
			gera_log2 "$CONTROLE" "FALHA" "Proprietario do diretorio Home" "Home: $dir;Usuário: $user: UID: $uid (UID Correto: $correto)"
		fi
	done
}

function getPackageList()
{
    echo "$(status) Obtendo relação de pacotes instalados no sistema..."
	export TITULO="Pacotes - Lista de pacotes instalados"
	export FORMATO_HTML="LISTASIMPLES"
    export CONTROLE="$FORMATO_HTML;$TITULO"
	
        
    case "$TIPO_PACOTE" in
        "DEB")
            PKG=\"$(dpkg -l | egrep -v "^\+|^\||^Desired" |  awk '{print $1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13" "$14" "$15" "$16" "$17" "$18" "$19" "$20}' | sort -t";" -k1| tr '\n' ';'; echo)\"
			#PKG=\"$(dpkg -l | egrep -v "^\+|^\||^Desired" |  awk '{print $1";"$2";"$3";"$4";"$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13" "$14" "$15" "$16" "$17" "$18") "$19" "$20}' | sort -t";" -k1| tr '\n' ';'; echo)\"
            #PKG=\"$(dpkg -l | egrep -v "^\+|^\||^Desired" |  awk '{print $1";"$2";"$3";"$4";"$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13" "$14" "$15" "$16" "$17" "$18") "$19" "$20}' | sort -t";" -k1)\"
            ;;
        "RPM")
            PKG=\"$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}-%{ARCH}-%{SUMMARY}\n'| sort| tr '\n' ';'; echo)\"
			#PKG=\"$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}-%{ARCH}-%{SUMMARY}\n'| tr '\n' ';'; echo)\"
            #PKG=\"$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}-%{ARCH}-%{SUMMARY}\n')\"
            ;;    
    esac

	gera_log2 "$CONTROLE" "INFO" "Pacotes do sistema" "$PKG"
}

function getRepoList()
{
	echo "$(status) Obtendo repositórios ativos..."
	export TITULO="Pacotes - Repositórios ativos"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	case "$TIPO_PACOTE" in
        "DEB")
            REPO=$(cat /etc/apt/sources.list | egrep -v "^#|^$" | tr '\n' ';'; echo)		
			gera_log2 "$CONTROLE" "INFO" "Lista de Repositórios" "$REPO"	
            ;;
        "RPM")
            REPO=$(yum repolist | grep status -A 500 | grep -v ^repolist| tr '\n' ';'; echo)		
			gera_log2 "$CONTROLE" "INFO" "Lista de Repositórios" "$REPO"	
            ;;    
    esac
	
			
}

function getRepolistRedHat()
{
	# apenas para RHEL
		
	if [ "$REDHAT" -eq 1 ];then
		echo "$(status) Obtendo repositórios Red Hat ativos..."
		export TITULO="Pacotes Red Hat - Subscrição ativa"
		export FORMATO_HTML="LISTASIMPLES"
		export CONTROLE="$FORMATO_HTML;$TITULO"
		
		REPO=$(subscription-manager list| tr '\n' ';'; echo)		
		gera_log2 "$CONTROLE" "INFO" "Subscrição Red Hat ativa" "$REPO"			
		
		#echo "$(status) Obtendo repositórios Red Hat ativos..."
		export TITULO="Pacotes Red Hat - Repositóris ativos"
		export FORMATO_HTML="LISTASIMPLES"
		export CONTROLE="$FORMATO_HTML;$TITULO"
				
		REPO=$(subscription-manager repos| tr '\n' ';'; echo)		
		gera_log2 "$CONTROLE" "INFO" "Repositórios ativos" "$REPO"			
		
		#echo "$(status) Obtendo repositórios Red Hat ativos..."
		export TITULO="Pacotes Red Hat - Versão subscription manager"
		export FORMATO_HTML="LISTASIMPLES"
		export CONTROLE="$FORMATO_HTML;$TITULO"
				
		REPO=$(subscription-manager version| tr '\n' ';'; echo)		
		gera_log2 "$CONTROLE" "INFO" "Versão do Red Hat subscription manager" "$REPO"			
		
	fi	
}

function AnaliseRepo()
{
	# apenas para RHEL
	echo "$(status) Analisando chaves gpg repositórios ativos..."
	export TITULO="Pacotes - Análise de GPG de repositórios"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	case "$TIPO_PACOTE" in
        "DEB")
            echo "Em construção..."
			#gera_log2 "$CONTROLE" "INFO" "Lista de Repositório" "$REPO"	
            ;;
        "RPM")
			FILES=$(ls /etc/yum.repos.d/)
			for file in $FILES; do
				IFSOLD="$IFS"
				IFS=$'\n'
				REPO=""
				CONT=1
				STATUS="SUCESSO"
				
				# echo "File: $file" #DEBUG
				
				# Testa se vai existir repositório ativo no arquivo. Caso exista mais de um, ele avalia todos.
				EXISTE_ATIVO=$(cat /etc/yum.repos.d/$file | egrep -v "^#|^$"| tr "\n" ";"| sed "s/\[/\n\[/g"| grep -v "enabled=0")
				
				if [ -n "$EXISTE_ATIVO" ];then
					#for i in $(cat /etc/yum.repos.d/$file | tr "\n" ";"| sed "s/\[/\n\[/g"| grep "enabled=1"); do 
					for LINE in $(cat /etc/yum.repos.d/$file | egrep -v "^#|^$"| tr "\n" ";"| sed "s/\[/\n\[/g"| grep -v "enabled=0"); do 
						#REPO="$REPO"$(echo -e "ARQUIVO: /etc/yum.repos.d/$file\n"; echo "$i" | egrep "\[|^name|enabled|gpgcheck|gpgkey" | tr '\n' ';'; echo)
						#if [ "$CONT" -eq 1 ]; then
						#	REPO="$REPO"$(echo -e "<b>ARQUIVO: /etc/yum.repos.d/$file</b><br/>\n")
						#fi
						#echo "Valor LINE: $LINE"  #DEBUG
						#REPO="$REPO"$(echo "$LINE" | egrep "\[|^name|gpgcheck|gpgkey" | tr '\n' ';'; echo )
						
						IFSOLD2="$IFS"
						IFS=";"
						
						REPO=""
						for REPOAVULSO in ${LINE}; do
							#echo "Valor REPOAVULSO: ${REPOAVULSO}"   #DEBUG
							
							REPO="$REPO"$(echo "$REPOAVULSO" | egrep "\[|^name|gpgcheck|gpgkey" | tr '\n' ';'; echo )
							CONT=$(($CONT+1))
							
							GPGCHECK=""
							GPGCHECK=$(echo "$REPO" | grep "gpgcheck=0")
							
							if [ -n "$GPGCHECK" ];then
								STATUS="FALHA"
							fi
							#echo "Valor de REPO: $REPO"  # DEBUG
							
						done
						if [ -n "$REPO" ]; then
							#echo "$REPO" #DEBUG
							gera_log2 "$CONTROLE" "$STATUS" "repo: etc/yum.repos.d/$file" "$REPO"
						else
							gera_log2 "$CONTROLE" "FALHA" "Não foi encontrado repositório ativo no arquivo: $file"
						fi
					done
				else
					gera_log2 "$CONTROLE" "FALHA" "Não foi encontrado repositório ativo no arquivo: $file"
				fi
				IFS="$IFSOLD"
				
			done

			
            ;;    
    esac
		
}

function getSummaryPackage2UpgradeCorretivo()
{
    echo "$(status) Obtendo sumário de atualizações corretivas..."
	export TITULO="Pacotes - Sumário de atualizações de segurança"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
    case "$TIPO_PACOTE" in
        "DEB")
            #apt list --upgradable 2> /dev/null
            #apt-get update && \
            PKG=\"$(apt-get -V upgrade --assume-no | grep "("| sed 's/[)(=>]//g' | awk '{print $1";"$2";"$3}'| tr '\n' ';'; echo)\"
            ;;
        "RPM")
            EXISTE=""
			yum updateinfo summary all &>/dev/null
			EXISTE="$?"
			#echo "EXISTE $EXISTE"
			if [ "$EXISTE" -ne 0 ];then
				ERRO="yum não suporta updateinfo!"
				EXISTE=""
				EXISTE=$(rpm -qa | egrep -o "yum-plugin-security|yum-security")
				#echo "EXISTE $EXISTE"
				if [ -z "$EXISTE" ];then
					ERRO="Nenhum formato de verificação de atualização de Segurança disponível (yum install -y yum-plugin-security || yum install -y yum-security)"
					gera_log2 "$CONTROLE" "FALHA" "O Yum não pode verificar atualizações de segurança (yum install -y yum-plugin-security || yum install -y yum-security)" "$ERRO"
				else
					case "$EXISTE" in
						yum-plugin-security)
							PKG=$(yum updateinfo summary all | egrep -v -i "\*" | tr '\n' ';'; echo)
							gera_log2 "$CONTROLE" "INFO" "Lista de pacotes corretivos" "$PKG"
						;;
						yum-security)
							PKG=$(yum list-security --security | egrep -v -i "updateinfo|Plugins|\*"| tr '\n' ';'; echo)
							gera_log2 "$CONTROLE" "INFO" "Lista de pacotes corretivos" "$PKG"
						;;
					esac
				fi
			else
				PKG=$(yum updateinfo summary all | egrep -v -i "\*"| tr '\n' ';'; echo)
				gera_log2 "$CONTROLE" "INFO" "Lista de pacotes corretivos" "$PKG"
			fi
	        ;;    
    esac      
}

function getPackage2UpgradeCorretivo()
{
    echo "$(status) Obtendo atualizações corretivas..."
	export TITULO="Pacotes - Lista de atualizações de Segurança"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
    case "$TIPO_PACOTE" in
        "DEB")
            #apt list --upgradable 2> /dev/null
            #apt-get update && \
            PKG=\"$(apt-get -V upgrade --assume-no | grep "("| sed 's/[)(=>]//g' | awk '{print $1";"$2";"$3}'| tr '\n' ';'; echo)\"
            ;;
        "RPM")
            EXISTE=""
			yum updateinfo list all &>/dev/null
			EXISTE="$?"
			#echo "EXISTE $EXISTE"
			if [ "$EXISTE" -ne 0 ];then
				ERRO="yum não suporta updateinfo!"
				EXISTE=""
				EXISTE=$(rpm -qa | egrep -o "yum-plugin-security|yum-security")
				#echo "EXISTE $EXISTE"
				if [ -z "$EXISTE" ];then
					ERRO="Nenhum formato de verificação de atualização de Segurança disponível (yum install -y yum-plugin-security || yum install -y yum-security)"
					gera_log2 "$CONTROLE" "FALHA" "O Yum não pode verificar atualizações de segurança (yum install -y yum-plugin-security || yum install -y yum-security)" "$ERRO"
				else
					case "$EXISTE" in
						yum-plugin-security)
							#PKG=$(yum updateinfo list all --security | egrep -v -i "updateinfo|Plugins"| sort -k2 | tr '\n' ';'; echo)
							PKG=$(yum --security check-update | egrep -v -i "updateinfo|Plugins|\*" | tr '\n' ';'; echo)
							gera_log2 "$CONTROLE" "INFO" "Lista de pacotes corretivos" "$PKG"
						;;
						yum-security)
							PKG=$(yum list-security --security | egrep -v -i "updateinfo|Plugins|\*"| tr '\n' ';'; echo)
							gera_log2 "$CONTROLE" "INFO" "Lista de pacotes corretivos" "$PKG"
						;;
					esac
				fi
			else
				#PKG=$(yum updateinfo list all --security | egrep -v -i "updateinfo|Plugins"| sort -k2 | tr '\n' ';'; echo)
				PKG=$(yum --security check-update | egrep -v -i "updateinfo|Plugins" | tr '\n' ';'; echo)
				gera_log2 "$CONTROLE" "INFO" "Lista de pacotes corretivos" "$PKG"
			fi
			
            ;;    
    esac    
}

function get_tmp_filesystem()
{
	echo "$(status) Analisando sistema de arquivo /tmp..."
	export TITULO="Filesystem - Teste do /tmp"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	TESTE="/tmp"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$CONTROLE" "FALHA" "Partição $TESTE não está em filesystem separado"
		return 1
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Partição $TESTE está em filesystem separado"
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	#OPT="rw nosuid nodev noexec relatime"
	#for i in $OPT; do
	for i in rw nosuid nodev noexec relatime; do
		RESULT=$(echo $PARTICAO | grep "$i")
		#echo "RESULT :$RESULT, Item: $i "
		if [ -z "$RESULT" ];then
			gera_log2 "$CONTROLE" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$CONTROLE" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done	
}

function get_var_tmp_filesystem()
{
	echo "$(status) Analisando sistema de arquivo /var/tmp..."
	export TITULO="Filesystem - Teste do /var/tmp"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	TESTE="/var/tmp"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$CONTROLE" "FALHA" "Partição $TESTE não está em filesystem separado"
		return 1 
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Partição $TESTE está em filesystem separado"
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	#OPT="rw nosuid nodev noexec relatime"
	for i in rw nosuid nodev noexec relatime; do
		RESULT=$(echo $PARTICAO | grep "$i")
		if [ -z "$RESULT" ];then
			gera_log2 "$CONTROLE" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$CONTROLE" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done
	
}

function get_var_log_filesystem()
{
	echo "$(status) Analisando sistema de arquivo /var/log..."
	export TITULO="Filesystem - Teste do /var/log"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	TESTE="/var/log"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$CONTROLE" "FALHA" "Partição $TESTE não está em filesystem separado"
		return 1
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Partição $TESTE está em filesystem separado"		
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	#OPT="rw nosuid nodev noexec relatime"
	for i in rw nosuid nodev noexec relatime; do
		RESULT=$(echo $PARTICAO | grep "$i")
		if [ -z "$RESULT" ];then
			gera_log2 "$CONTROLE" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$CONTROLE" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done
	
}

function get_home_filesystem()
{
	echo "$(status) Analisando sistema de arquivo /home..."
	export TITULO="Filesystem - Teste do /home"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	TESTE="/home"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$CONTROLE" "FALHA" "Partição $TESTE não está em filesystem separado"
		return 1
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Partição $TESTE está em filesystem separado"
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	#OPT="nodev"
	for i in nodev; do
		RESULT=$(echo $PARTICAO | grep "$i")
		if [ -z "$RESULT" ];then
			gera_log2 "$CONTROLE" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$CONTROLE" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done	
}


function get_partitions()
{
	echo "$(status) Analisando partições..."
	export TITULO="Filesystem - Configuração de partições"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=$(fdisk -l | egrep "^Disk /|^/dev"| tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$CONTROLE" "FALHA" "Não foi possivel acessar as partições"
		return 1 
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Lista de partições" "$RESP" 	
	fi	

}

function get_ResumePartitions()
{
	echo "$(status) Analisando resumo partições..."
	export TITULO="Filesystem - Resumo de partições"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	lsblk &> /dev/null
	EXISTE="$?"
	if [ "$EXISTE" -eq 0 ];then
		RESP=$(lsblk | tr '\n' ';'; echo)
		if [ -z "$RESP" ];then
			gera_log2 "$CONTROLE" "FALHA" "Não foi possivel acessar as partições"
			return 1 
		else
			gera_log2 "$CONTROLE" "SUCESSO" "Lista de partições" "$RESP" 	
		fi
	else
		gera_log2 "$CONTROLE" "FALHA" "Não possui o comando \"lsblk\" no sistema."  	
	fi	

}

function get_lvm()
{
	echo "$(status) Analisando PVs LVM..."
	export TITULO="Filesystem - LVM - Configurações de PVS"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=$(pvs 2> /dev/null | grep -v "Attr" | tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$CONTROLE" "FALHA" "Sistema não possui PVs"
		return 1 
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Lista de PVs" "$RESP" 	
	fi
	
	echo "$(status) Analisando VGs LVM..."
	export TITULO="Filesystem - LVM - Configurações de VGS"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=$(vgs| grep -v "Attr" | tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$CONTROLE" "FALHA" "Sistema não possui VGs"
		return 1 
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Lista de VGs" "$RESP" 	
	fi
	
	echo "$(status) Analisando LVs LVM..."
	export TITULO="Filesystem - LVM - Configurações de LVS"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=$(lvs| grep -v "Attr" | tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$CONTROLE" "FALHA" "Sistema não possui LVs"
		return 1 
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Lista de LVs" "$RESP" 	
	fi
}

function getFstab()
{
    echo "$(status) Analisando pontos de montagems persistentes..."
	export TITULO="Filesystem - Configurações de montagem persistente"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
   
    RESP=$(cat /etc/fstab | egrep -v "^#|^$" | tr '\n' ';'; echo)
    gera_log2 "$CONTROLE" "INFO" "Entradas do /etc/fstab" "$RESP"    
}

function VerificaMontagens()
{
    echo "$(status) Analisando pontos de montagens ativos..."
	export TITULO="Filesystem - Configurações de montagens ativas"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
   	MONTAGENS=$(mount | grep "^/dev")
    RESP=$(echo "$MONTAGENS"| tr '\n' ';'; echo)
    gera_log2 "$CONTROLE" "INFO" "Lista de Devices montados" "$RESP"
    
	echo "$(status) Analisando montagens persistentes..."
    export TITULO="Filesystem - Analisando montagens persistentes"
	export FORMATO_HTML="SUBCATEGORIZADA"
    export CONTROLE="$FORMATO_HTML;$TITULO"
	
	IFSOLD=$IFS
    IFS=$'\n'
    for m in $MONTAGENS;do
    	DEVICE=$(echo "$m" | awk '{print $1}')
    	DEV_PERS=""
    	DEV_PERS=$(cat /etc/fstab | grep "$DEVICE")
    	
    	if [ -z "$DEV_PERS" ];then
    		
			#Testando nome alternativo do mapper
			
			DEVICE_ALTERNATIVO=$(echo "$m" | awk '{print $1}' | sed 's/mapper\///g' | sed 's/-/\//g')
			DEV_PERS=""
			DEV_PERS=$(cat /etc/fstab | grep "$DEVICE_ALTERNATIVO")
			
			if [ -z "$DEV_PERS" ];then
    			echo "" > /dev/null
				#gera_log2 "$CONTROLE" "FALHA" "Device alternativo não persistente. Verifique" "$DEVICE_ALTERNATIVO nem o $UUID"
    		else
    			gera_log2 "$CONTROLE" "SUCESSO" "Device alternativo persistente" "$DEVICE: $DEVICE_ALTERNATIVO"
				continue				
    		fi
			
			# testando se o dispositivo está configurado com UUID
    		UUID=$(blkid "$DEVICE" |egrep -o "(UUID=).*([ ])*"|  awk '{print $1}'|awk -F"=" '{print $2}'| sed 's/\"//g')
    		# echo "UUID: $UUID"  # debug
    		DEV_PERS=$(cat /etc/fstab | grep "$UUID")
    		if [ -z "$DEV_PERS" ];then
    			gera_log2 "$CONTROLE" "FALHA" "Device não persistente. Verifique" "$DEVICE nem o $UUID"
    		else
    			gera_log2 "$CONTROLE" "SUCESSO" "Device persistente - UUID" "$DEVICE: $UUID"	
    		fi
    	else
    		gera_log2 "$CONTROLE" "SUCESSO" "Device persistente" "$DEVICE" 	
    	fi
    done
    IFS=$IFSOLD
}

function getDirOcupation()
{
	echo "$(status) Verificando ocupação de diretórios na raiz..."
	export TITULO="Filesystem - Ocupação de diretórios"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	RESP=""
	RESP=$(du -h --max-depth=1 / 2>/dev/null | sort -hr | tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$CONTROLE" "FALHA" "Não foi possivel acessar dados da Raiz"
		return 1 
	else
		gera_log2 "$CONTROLE" "SUCESSO" "Resumo de ocupação da raiz (ordenado por espaço)" "$RESP" 	
	fi
}

function getVMtools()
{
    echo "$(status) Analisando VMtools ativo..."
	export TITULO="VMWare - VMTools Instalado"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=""
    RESP=$(ps -ef | grep vmtools | grep -v grep | awk '{print $8}'| tr '\n' ' '; echo)
	#echo "Valor RESP: $RESP"  #debug
	if [ -n "$RESP" ];then
			PROCESSO_VMTools=$(ps -ef | grep vmtools | grep -v grep | tr '\n' ';'; echo)
			RESP="$RESP --version"
			#echo "RESP $RESP"
			VERSAO_VMtools=$(eval $RESP)
			#echo "VERSAO_VMtools: $VERSAO_VMtools"
			gera_log2 "$CONTROLE" "SUCESSO" "Processo(s) VMTools" "$PROCESSO_VMTools"
			gera_log2 "$CONTROLE" "SUCESSO" "Versão VMTools" "$VERSAO_VMtools"
	else
			gera_log2 "$CONTROLE" "FALHA" "VMtools Não está em execução" "$PROCESSO_VMTools"
	fi    
}

function getWebServer()
{
    echo "$(status) Analisando Servidores web..."
	export TITULO="Servidor Web - Identificando serviços"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=""
    RESP=$(ps -ef | egrep "http|apache|tomcat" | grep -v grep | awk '{print $8}' | uniq | tr '\n' ' '; echo)
	#echo "Valor RESP: $RESP"  #debug
	if [ -n "$RESP" ];then
			APP=$(echo "$RESP" | egrep -o "httpd|apache.*|tomcat.*")
			case "$APP" in
				httpd|apache|apache2) 
					gera_log2 "$CONTROLE" "SUCESSO" "Processo httpd" "$APP"
					RESULTADO=$(eval "$APP -V | tr '\n' ';'; echo")
					gera_log2 "$CONTROLE" "SUCESSO" "Versão httpd" "$RESULTADO"
				;;
				tomcat|tomcat6|tomcat7|tomcat8)
				;;
			esac
		
	else
		RESP=$(netstat -ant | awk '{print $4}' | egrep ":80|:443|:8082" | tr '\n' ';'; echo)	
		if [ -n "$RESP" ];then
			gera_log2 "$CONTROLE" "FALHA" "Existe um servidor Web desconhecido" "$RESP"
		else
			gera_log2 "$CONTROLE" "INFO" "Não foram encontradas instâncias de servidor Web" 
		fi
		
			
	fi    
}


function getCertificateWebServer()
{
    echo "$(status) Analisando Servidores web (Certificados SSL)..."
	export TITULO="Servidor Web - Identificando Certificados do Web Server"
	export FORMATO_HTML="SUBCATEGORIZADA"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=""
    RESP=$(ps -ef | egrep "http|apache|tomcat" | grep -v grep | awk '{print $8}' | uniq | tr '\n' ' '; echo)
	#echo "Valor Existe web: $RESP"  #debug
	if [ -n "$RESP" ];then
			APP=$(echo "$RESP" | egrep -o "httpd|apache.*|tomcat.*")
			#echo "Valor de app: $APP"  #debug
			case "$APP" in
				httpd|apache|apache2) 
					IFSOLD=$IFS
					IFS=$'\n'
					LISTA_CERT=$(grep -R "^SSLCertificateFile" /etc/httpd/* )
					#echo "LISTA_CERT: $LISTA_CERT"
					for CERT in $LISTA_CERT; do
						ARQUIVO=$(echo "$CERT" | awk '{print $NF}')
						ARQUIVO_FONTE=$(echo "$CERT" | awk '{print $1}')
						#DATA=$(date --date=$(openssl x509 -enddate -noout -in $ARQUIVO |cut -d"=" -f 2) --iso-8601)
						
						DATA=$(date --date=$(openssl x509 -enddate -noout -in $ARQUIVO |cut -d"=" -f 2) "+%m/%d/%Y")
						DATA_PRINT=$(date --date=$(openssl x509 -enddate -noout -in $ARQUIVO |cut -d"=" -f 2) "+%d-%m-%Y")
						
						#data em timestamp
						DATA_FIM=$(date --date="$DATA" "+%s")
						DATA_ATUAL=$(date  "+%s")
						#echo "DATA_FIM: $DATA_FIM, DATA_ATUAL: $DATA_ATUAL"
						
						STATUS="sucesso"
						if [ "$DATA_FIM" -lt  "$DATA_ATUAL" ];then
							STATUS="falha"
							MSG="Vencido:"
						else
							STATUS="sucesso"
							MSG="Ativo até:"	
						fi
						
						gera_log2 "$CONTROLE" "INFO" "Arquivo conf: $ARQUIVO_FONTE" "$ARQUIVO;<p class='$STATUS'>$MSG $DATA_PRINT</p>"
					done
					IFS=$IFSOLD
				
				;;
				tomcat|tomcat6|tomcat7|tomcat8)
				;;
				*)
					echo "[ERRO] Nenhum tipo de opção de servidor web foi encontrada"
				;;
			esac
		
	else
		RESP=$(netstat -ant | awk '{print $4}' | egrep ":80|:443|:8082" | tr '\n' ';'; echo)	
		if [ -n "$RESP" ];then
			gera_log2 "$CONTROLE" "FALHA" "Existe um servidor Web desconhecido" "$RESP"
		else
			gera_log2 "$CONTROLE" "INFO" "Não foram encontradas instâncias de servidor Web" 
		fi
		
			
	fi    
}

function getSSHConfig()
{
    echo "$(status) Obtendo informações do serviço de ssh..."
	export TITULO="SSH - Arquivo de configuração"
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESP=""
    RESP=$(less /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"| tr '\n' ';'; echo)
	if [ -n "$RESP" ];then
		gera_log2 "$CONTROLE" "SUCESSO" "Configurações do SSH" "$RESP"
		
	else

		gera_log2 "$CONTROLE" "FALHA" "Não foi possivel localizar o arquivo de configuração" "$RESP"
	fi    
}

function getVariaveisAmbiente()
{
	echo "$(status) Obtendo Variáveis de ambiente..."
	export TITULO="Informação do sistema - set"		
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESULTADO=$(set | tr '\n' ';'; echo)
	#gera_log2 "$CONTROLE" "INFO" "Variáveis de ambiebte - set" "$RESULTADO"
	
	export TITULO="Informação do sistema - env"		
	export FORMATO_HTML="LISTASIMPLES"
	export CONTROLE="$FORMATO_HTML;$TITULO"
	
	RESULTADO=$(set | tr '\n' ';'; echo)
	gera_log2 "$CONTROLE" "INFO" "Variáveis de ambiebte - env" "$RESULTADO"
	
	
}

# Tornando a função gera_log acessivel para qualquer sub-shell
export -f gera_log
export -f gera_log2
export -f gera_log3


## início do script, invocando as funções:
### Funções obrigatórias
isRoot
cabecalho
getLinuxVersion

getTimeZone
getConfereDateTime

getCpuInformation
getSelinux
getHosts
getRclocal
getCrontab
getLimits
getProcess
getProcessPerUser

### Usuários
getUsers
getUsersValidLogin
getRootUsers
getSudoers
getGroups

### Redes
getInternetAccess
getRoutes
getFirewalld
getIptables
getOpenPorts

### Testes de memoria
#memoria_fisica
#memoria_ram
#memoria_swap

### Testes de DNS
#search_nameserver
#valid_nameserver
#consulteMyName
#consultaIPreverso

### Teste de arquivos
#test_file
#world_writable
#nouser
#df_nouser
#nogroup
#df_nogroup
#nopasswd
#checkhome

### repositórios e pacotes
#getPackageList
#getSummaryPackage2UpgradeCorretivo
#getPackage2UpgradeCorretivo
#getRepoList
#getRepolistRedHat
#AnaliseRepo


### Teste de file sistems
#ocupacaoDiscos
#get_tmp_filesystem
#get_var_tmp_filesystem
#get_var_log_filesystem
#get_home_filesystem


### LVM
#get_ResumePartitions
#get_partitions
#get_lvm
#getFstab
#VerificaMontagens
#getDirOcupation

### Testes serviços
getServicesEnabled
getVMtools
getWebServer
getCertificateWebServer
getSSHConfig

#getVariaveisAmbiente

# função importada do gerador de Html
gerarRelatorio "$LOGFILE" "${IP_HOST}-${HOSTNAME_ATUAL}.html"
echo "$(status) Gerando relatório: ${IP_HOST}-${HOSTNAME_ATUAL}.html e LOG:  $LOGFILE"

### TODO
# 1) Verificar serviços em execução com usuários estranhos
# 3) configuração do sysctl

############################################################### 
