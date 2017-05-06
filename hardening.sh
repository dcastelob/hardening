#!/bin/bash

###############################################################

# Script de checagens de hardening; Givaldo Lins e Diego Oliveira; Suporte Informática; 2015#
# ver: 1.00.0005

###############################################################

# importação do script que gera o o relatório em html
source geradorRelatorioHtml.sh

# Parametros Globais

export VERSAO="1.05"
export LOGFILE="hardening-$(hostname)-$(date +"%x_%T").csv"
export SELINUX=1
export SILENCIOSO=1
export TIPO_PACOTE=""

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
	
	
	if [ "$SILENCIOSO" -eq 1 ];then
		echo "$(hostname);$ROTINA;$STATUS;$CATEGORIA;\"$MENSAGEM\"" >> $LOGFILE
	else
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
	export FUNCAO="CABECALHO"	
	echo "$(status) Obtendo informações do servidor..."
	gera_log2 "$FUNCAO" "INFO" "Data de Apuração" "$(date +"%x %T")"
	gera_log2 "$FUNCAO" "INFO" "Usuário executor do levantamento" "$(whoami)"
	gera_log2 "$FUNCAO" "INFO" "Funcionamento desde" "$(uptime -s)"
	export HOSTNAME_ATUAL=$(hostname -s)
	gera_log2 "$FUNCAO" "INFO" "Nome do computador" "$HOSTNAME_ATUAL"
	gera_log2 "$FUNCAO" "INFO" "Nome FQDN do computador" "$(hostname -f)"

	#gera_log2 "$FUNCAO" "INFO" "Sistema Operacional" "$(cat /etc/system-release)"

#	gera_log2 "$FUNCAO" "INFO" "Endereço IP do computador" "$(ip a | grep "inet "| awk '{print $2";"$7,$8";"}'| grep -v "127.0.0.1/8")"
	gera_log2 "$FUNCAO" "INFO" "Endereço IP do computador" "$(ip a | grep "inet "| awk '{print $2" ("$7,$8");"}'| grep -v "127.0.0.1/8"| tr '\n' ' '; echo)"
	gera_log2 "$FUNCAO" "INFO" "Versão do Kernel" "$(uname -r)"
	gera_log2 "$FUNCAO" "INFO" "Arquitetura" "$(arch)"	
}

function getLinuxVersion()
{
    echo "$(status) Obtendo informações sobre o sistema operacional..."
    export FUNCAO="CABECALHO"	
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
    
    gera_log2 "$FUNCAO" "INFO" "Sistema Operacional" "$VER"

}

function getKernel()
{
    echo "$(status) Obtendo dados do kernel..."
    export FUNCAO="VERSAO_KERNEL"
    #uname -a
    gera_log2 "$FUNCAO" "INFO" "Sistema Operacional" "$(uname -a)"
}

function getHosts()
{
	export FUNCAO="HOSTS_FILE"
	echo "$(status) Obtendo informação de hosts..."
	DADOS=$(getent hosts| tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Configuração de /etc/hosts" "$DADOS"
			
}

function getSelinux()
{
	export FUNCAO="01-SELINUX"
	echo "$(status) Obtendo informação sobre SELinux..."
	
	getenforce &>/dev/null
	if [ $? -ne 0 ];then
		gera_log2 "$FUNCAO" "INFO" "Sistema não utiliza SELinux" "$DADOS"
		return 1	
	fi
	
	DADOS=$(getenforce | tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "SELinux em modo" "$DADOS"
	
	DADOS=$(cat /etc/sysconfig/selinux | grep "^SELINUX=" | tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "SELinux em modo persistente" "$DADOS"
			
}

function getRclocal()
{
	
	export FUNCAO="RC.LOCAL"
	echo "$(status) Obtendo informação do /etc/rc.local..."
	DADOS=$(cat /etc/rc.local | grep -v "^#" | tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Configuração de /etc/rc.local" "$DADOS"
			
}

function getProcess()
{
	
	export FUNCAO="PROCESSOS"
	echo "$(status) Obtendo informação dos processos em execução..."
	DADOS=$(ps axo uname:20,group:20,pid,ppid,tty,vsz,time,stat,ucmd | tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Processos em execução" "$DADOS"
			
}

function getLimits()
{
	# apenas para RHEL
	export FUNCAO="LIMITES_SISTEMA"
	echo "$(status) Obtendo informação de limites..."
	DADOS=$(ulimit -a| tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Configuração atual dos pam_limits" "$DADOS"
	
	FILE="/etc/security/limits.conf"
	if [ -e "$FILE" ];then
		DADOS=$(cat $FILE|grep -v "^#"| tr '\n' ';'; echo)		
	fi
	export FUNCAO="LIMITS.CONF"
	gera_log2 "$FUNCAO" "INFO" "Configuração atual dos limits.conf" "$DADOS"
	
	
	
	export FUNCAO="LIMITS.D"
	echo "$(status) Obtendo informação de agendamentos em diretórios..."
	DADOS=$(for dir in /etc/security/limits.d;do 
				for file in $(ls $dir);do 
					echo -e "<strong>ARQUIVO:$dir/$file</strong><br/>";
					echo
					 
					cat $dir/$file | grep -v "^#" | grep -v "^$" ; 
				done; 
			done | tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Extras do /etc/security/limits.d.*" "$DADOS"	
			
}


function getRoutes()
{
	# apenas para RHEL
	export FUNCAO="ROTAS"
	echo "$(status) Obtendo informação de rotas..."
	DADOS=$(route -n| tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Rotas e gateways do sistema" "$DADOS"
			
}

function getCrontab()
{
	# apenas para RHEL
	export FUNCAO="AGENDAMENTOS"
	echo "$(status) Obtendo informação de agendamentos..."
	DADOS=$(cat /etc/crontab | grep -v ^# | grep -v ^$| tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Agendamentos do /etc/crontab" "$DADOS"

	export FUNCAO="CRONTAB_EXTRAS"
	echo "$(status) Obtendo informação de agendamentos em diretórios..."
	DADOS=$(for dir in /etc/cron.{d,daily,hourly,monthly,weekly};do 
				for file in $(ls $dir);do 
					echo -e "<strong>ARQUIVO:$dir/$file</strong><br/>";
					echo
					 
					cat $dir/$file | grep -v "^#" | grep -v "^$" ; 
				done; 
			done | tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Extras do /etc/cron.*" "$DADOS"
			
}

function getOpenPorts()
{
	echo "$(status) Obtendo lista de serviços ativos..."
	export FUNCAO="PORTAS_ABERTAS"		
	PORTAS=$(ss -putan4 | grep LISTEN | awk '{print $5"/"$1}'| awk -F":" '{print $2}')
	# echo $PORTAS   # debug
	for i in ${PORTAS}; do
		#cat /etc/services | grep " $i"| sed 's/#//g' | awk '{print $2"("$1");"$3,$4,$5,$6,$7,$8,$9}'
		gera_log2 "$FUNCAO" "INFO" "Portas de serviços em escuta" "$i;$(cat /etc/services | grep " $i"| sed 's/#//g' | awk '{print $2"("$1");"$3,$4,$5,$6,$7,$8,$9}')"
		
	done
	
}

function getServicesEnabled()
{
    export FUNCAO="SERVIÇOS_ATIVOS_NO_BOOT"
	echo "$(status) Obtendo informações de serviços ativos no boot..."
    DISTRO="$1"
    case "$DISTRO" in
        "DEB")
            #apt list --upgradable 2> /dev/null
            #apt-get update && \
            RESP=\"$(apt-get -V upgrade --assume-no | grep "("| sed 's/[)(=>]//g' | awk '{print $1";"$2";"$3}'| tr '\n' ';'; echo)\"
            ;;
        "RPM")
        	#RHEL antigos
            RESP=$(chkconfig --list 2>/dev/null;echo "<br/>")
            RESP=$RESP"Detaul target: "$(systemctl get-default;echo "<br/>")
            RESP=$RESP$(systemctl list-units --type=service)
            RESP=$(echo "$RESP"| tr '\n' ';'; echo)
            ;;    
    esac

    gera_log2 "$FUNCAO" "INFO" "Serviços ativo no boot" "$RESP"
    
}


function ocupacaoDiscos()
{
	echo "$(status) Avaliando a ocupação dos discos..."
	export FUNCAO="OCUPACAO_DISCOS"	
	DISCOS=$(df -h | grep ^/dev | awk '{print $1"("$6");"$2"/"$3";"$5}')
	#echo $DISCOS
	for i in ${DISCOS}; do
		gera_log2 "$FUNCAO" "INFO" "Ocupação dos Discos" "$i"
	done	
}

function memoria_fisica()
{
	echo "$(status) Avaliando a ocupação da memória física..."
	export FUNCAO="MEMORIA_FISICA"
	
	# em caso do comando não existir ou parametro inválido por conta de versão
	lshw -short -class memory &> /dev/null
	if  [ "$?" -ne 0 ];then
		gera_log2 "$FUNCAO" "FALHOU" "Itens de Memória física" "Comando lshw não encontrado"
		return 1
		
	fi
	
 	MEMORIA=$(lshw -short -class memory | grep -v -E "cache|Device"| grep -v "=" | awk '{print $3,$4,$5,$6,$7,$8,$9,$10}')
#	MEMORIA=$(lshw -short -class memory | grep -v -E "cache|Device"| grep -v "=" | awk '{print "\"" $3,$4,$5,$6,$7,$8,$9,$10"\""}')
	
	#echo $DISCOS
	IFS_OLD=$IFS
	IFS=$'\n'
	for i in ${MEMORIA}; do
		gera_log2 "$FUNCAO" "INFO" "Itens de Memória física" "$i"
	done	
	#sudo lshw -short -class memory | grep -v cache
	IFS=$IFS_OLD

}

function memoria_ram()
{
	echo "$(status) Avaliando a ocupação da memória RAM..."
	export FUNCAO="MEMORIA_RAM"
	
	# em caso do comando não existir ou parametro inválido por conta de versão
	PARAM="-h"
	free $PARAM &> /dev/null
	if  [ "$?" -ne 0 ];then
		export PARAM="-m"
	fi 
	
 	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1";"$2";"$3; else print $2";"$3";"$4}')
	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	MEMORIA=$(free "$PARAM" | egrep -v "^Swap|cache:" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Swap|cache:" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Swap|cache:" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	gera_log2 "$FUNCAO" "INFO" "Memória RAM" "\"$MEMORIA\""

}

function memoria_swap()
{
	echo "$(status) Avaliando a ocupação da memória SWAP..."
	export FUNCAO="MEMORIA_SWAP"
	
	# em caso do comando não existir ou parametro inválido por conta de versão
	PARAM="-h"
	free $PARAM &> /dev/null
	if  [ "$?" -ne 0 ];then
		export PARAM="-m"
	fi 
	
 	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1";"$2";"$3; else print $2";"$3";"$4}')
	#MEMORIA=$(free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free -h | grep -v "^Mem" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	MEMORIA=$(free "$PARAM" | egrep -v "^Mem|cache:" | awk '{ if (NR == 1)print $1":"; else print $2";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Mem|cache:" | awk '{ if (NR == 1)print $2":"; else print $3";"}'| tr '\n' ' '; free "$PARAM" | egrep -v "^Mem|cache:" | awk '{ if (NR == 1)print $3":"; else print $4";"}'| tr '\n' ' '; echo)
	gera_log2 "$FUNCAO" "INFO" "Memória SWAP" "\"$MEMORIA\""

}


function search_nameserver()
{
	export FUNCAO="NAME_SERVERS"
	echo "$(status) Checando diretiva search - DNS client..."
	TEST1=$(cat /etc/resolv.conf | grep ^search | awk '{print $2}')

	if [ -n "$TEST1" ]; then
		gera_log2 "$FUNCAO" "SUCESSO" "Diretiva Search encontrado no resolv.conf" "$TEST1"
	else
		gera_log2 "$FUNCAO" "FALHA" "Diretiva Search não encontrado no resolv.conf"
	fi
}

function test_dns()
{
	export FUNCAO="TESTE_DNS"
	URL_REFERENCIA="suporteinformatica.com"
		IP_REFERENCIA="67.20.87.167"
		
		for i in ${1}; do
			IP_TEMP=$(nslookup $URL_REFERENCIA $i | grep Address | grep -v "#53"$ | awk '{print $2}')
			if [ "$IP_TEMP" = "$IP_REFERENCIA" ];then
				gera_log2 "$FUNCAO" "SUCESSO" "Nameservers resolve endereços corretamente" "$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
			else
				gera_log2 "$FUNCAO" "FALHA" "Nameservers não resolve endereços corretamente" "$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
			fi
		done
}

function valid_nameserver()
{
	export FUNCAO="VALIDA_NAMESERVER"
	echo "$(status) Checando nameservers válidos do /etc/resolv.conf..."
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
				export FUNCAO="VALIDA_NAMESERVER"
				gera_log2 "$FUNCAO" "ALERT" "Apenas 1 nameserver foi encontrado no resolv.conf" "$NAMESERVER_LIST"
				;;
			2) 	
				test_dns "${TEST1}"
				export FUNCAO="VALIDA_NAMESERVER"
				gera_log2 "$FUNCAO" "INFO" "2 nameservers foram encontrado no resolv.conf" "$NAMESERVER_LIST"
				;;
			3) 	
				test_dns "${TEST1}"
				export FUNCAO="VALIDA_NAMESERVER"
				gera_log2 "$FUNCAO" "INFO" "3 nameservers foram encontrado no resolv.conf" "$NAMESERVER_LIST"
				;;
			*)	
				test_dns "${TEST1}"
				export FUNCAO="VALIDA_NAMESERVER"
				gera_log2 "$FUNCAO" "ALERT" "Apenas os 3 primeiros nameservers do resolv.conf serão utilizados" "Foram encontrados $TOTAL: $TEST1"
				;;
		esac
# 		
		
	else
		export FUNCAO="VALIDA_NAMESERVER"
		gera_log2 "$FUNCAO" "FALHA" "Diretiva nameserver não encontrado no resolv.conf"
	fi
}

function test_file () {
	#Permissão dos arquivos de senha do sistema local
	export FUNCAO="TESTA_PERMISSOES_ARQUIVOS_ESPECIAIS"
	
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
			gera_log2 "$FUNCAO" "SUCESSO" "Permissões arquivos do sistema" "$FILE;$TEST1"
		else
			gera_log2 "$FUNCAO" "FALHA" "Permissões arquivos do sistema" "$FILE;$TEST1 (Correta: $PERM)"
		fi

		echo "$(status) Checando dono do arquivo $FILE"
		TEST1=$(/bin/ls -l $FILE | awk '{print $3}')

		if [ "$TEST1" = "$USER1" ]; then
            gera_log2 "$FUNCAO" "SUCESSO" "Proprietário do arquivo" "$FILE;$TEST1"
        else
            gera_log2 "$FUNCAO" "FALHA" "Proprietário do arquivo" "$FILE;$TEST1 (Correto: $USER1)"
        fi

        echo "$(status) Checando grupo dono do arquivo $FILE"
        TEST1=$(/bin/ls -l $FILE | awk '{print $4}')

        if [ "$TEST1" = "$GROUP1" ]; then
			gera_log2 "$FUNCAO" "SUCESSO" "Grupo proprietário do arquivo" "$FILE;$TEST1"
		else
			gera_log2 "$FUNCAO" "FALHA" "Grupo proprietário do arquivo" "$FILE;$TEST1 (Correto: $GROUP1)"
		fi
done

rm -f permissions.txt

}

function world_writable() {
	export FUNCAO="ESCRITA_PARA_OUTROS"
	
	echo "$(status) Checando arquivos com permissão de escrita para outros..."
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -type f -perm -0002 2> /dev/null | xargs -I '{}' ls -l '{}' |awk -v funcao="$FUNCAO" '{print funcao ";FALHA;Permissão de escrita outros usuários;"$9";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"

}

function getUsers()
{
    echo "$(status) Obtendo relação de usuários do sistema..."
    export FUNCAO="RELACAO_USUARIOS"
    RES=$(cat /etc/passwd | sort -n -t":" -k3 | tr '\n' ';'; echo)
    gera_log2 "$FUNCAO" "INFO" "Lista de usuários" "\"$RES\""
}

function getGroups()
{
	echo "$(status) Obtendo relação de grupos do sistema..."
	export FUNCAO="RELACAO_GRUPOS"
    RES=$(cat /etc/group | sort -n -t":" -k3 | tr '\n' ';'; echo)
    gera_log2 "$FUNCAO" "INFO" "Lista de Grupos" "\"$RES\""
}


function nouser() 
{
	export FUNCAO="ARQUIVOS_PROPRIETARIO_DESCONHECIDO"
	echo "$(status) Checando arquivos com proprietário desconhecido..."
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -printf "%s %U %h/%f\n" 2> /dev/null | awk -v funcao="$FUNCAO" '{print funcao ";FALHA;Proprietário desconhecido;"$3" "$4" "$5" "$6" "$7";"$2";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
	

}
function df_nouser()
{
	export FUNCAO="OCUPACAO_ARQUIVOS_PROPRIETARIO_DESCONHECIDO"
	echo "$(status) Checando ocupação dos arquivos com proprietário desconhecido..."
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -printf "%s\n" 2> /dev/null| awk -v funcao="$FUNCAO" '{soma+=$1}END{printf funcao ";FALHA;Ocupação por arquivos com proprietário desconhecido; %f bytes\n",soma }' | xargs -I '{}' bash -c "gera_log3 '{}'"

}

function nogroup() 
{
	export FUNCAO="ARQUIVOS_GRUPO_DESCONHECIDO"
	echo "$(status) Checando arquivos com grupo proprietário desconhecido..."
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup -printf "%s %g %h/%f\n" 2> /dev/null| awk -v funcao="$FUNCAO" '{print funcao ";FALHA;Grupo proprietário desconhecido;"$3" "$4" "$5" "$6" "$7";"$2";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"

}

function df_nogroup()
{
	export FUNCAO="OCUPACAO_ARQUIVOS_GRUPO_DESCONHECIDO"
	echo "$(status) Checando ocupação dos arquivos com grupo proprietário desconhecido..."
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup -printf "%s\n" 2> /dev/null | awk -v funcao="$FUNCAO" '{soma+=$1}END{printf funcao ";FALHA;Ocupação por arquivos com grupo proprietário desconhecido; %f bytes\n",soma }' | xargs -I '{}' bash -c "gera_log3 '{}'"

}


function nopasswd(){
	export FUNCAO="USUARIOS_SEM_SENHA"
	echo "$(status) Checando se há usuários sem senha..."
	cat /etc/shadow | awk -v funcao="$FUNCAO" -F: '($2 == "" ) {print funcao ";FALHA;Usuário sem senha;"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
}

function checkhome(){
    export FUNCAO="PERMISSOES_HOME"
    # Configurando em caso de utilização de SELinux
    if [ "$SELINUX" -eq 1 ]; then
    	PERMISSAO_IDEAL="drwx------."
    else 
    	PERMISSAO_IDEAL="drwx------"
    fi
    
    echo "$(status) Checando permissões dos diretórios HOME de usuários válidos do /etc/passwd..."
	LISTA=$(egrep -v '(root|halt|sync|shutdown)' /etc/passwd| awk -F: '($7 != "/sbin/nologin") {print $1";"$3";"$6}')
    for i in "$LISTA" ; do
		#Obtendo os dados
		dir=`echo $i| cut -d";" -f3`
		uid=`echo $i| cut -d";" -f2`
		user=`echo $i| cut -d";" -f1`
		dirperm=`ls -ld $dir | cut -f1 -d" "`
		# echo $dirperm $dir $uid $user   # debug
		if [ "$dirperm" != "$PERMISSAO_IDEAL" ]; then
			gera_log2 "$FUNCAO" "FALHA" "Permissao do diretorio Home" "$dir;$dirperm (Correta: $PERMISSAO_IDEAL)"
		else
			gera_log2 "$FUNCAO" "SUCESSO" "Permissao do diretorio Home" "$dir;$dirperm (Correta: $PERMISSAO_IDEAL)"	
		fi

		correto=`ls -ldn $dir | awk '{print $3}'`
		if [ "$correto" -ne "$uid" ]; then
			gera_log2 "$FUNCAO" "FALHA" "Proprietario do diretorio Home" "$dir;$user: $uid (Correto: $correto)"
		fi
	done
}

function getPackageList()
{
    export FUNCAO="LISTA_PACOTES"
    echo "$(status) Obtendo relação de pacotes instalados no sistema..."
    DISTRO="$1"
    
    case "$DISTRO" in
        "DEB")
            PKG=\"$(dpkg -l | egrep -v "^\+|^\||^Desired" |  awk '{print $1";"$2";"$3";"$4";"$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13" "$14" "$15" "$16" "$17" "$18") "$19" "$20}' | sort -t";" -k1| tr '\n' ';'; echo)\"
            #PKG=\"$(dpkg -l | egrep -v "^\+|^\||^Desired" |  awk '{print $1";"$2";"$3";"$4";"$5" "$6" "$7" "$8" "$9" "$10" "$11" "$12" "$13" "$14" "$15" "$16" "$17" "$18") "$19" "$20}' | sort -t";" -k1)\"
            ;;
        "RPM")
            PKG=\"$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}-%{ARCH}-%{SUMMARY}\n'| tr '\n' ';'; echo)\"
            #PKG=\"$(rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}-%{ARCH}-%{SUMMARY}\n')\"
            ;;    
    esac

	gera_log2 "$FUNCAO" "INFO" "Pacotes do sistema" "$PKG"
}

function getRepoList()
{
	# apenas para RHEL
	export FUNCAO="REPOSITORIO_ATIVO"
	echo "$(status) Obtendo repositórios ativos..."
	REPO=$(yum repolist | grep status -A 500 | grep -v ^repolist| tr '\n' ';'; echo)		
	gera_log2 "$FUNCAO" "INFO" "Lista de Repositório" "$REPO"
			
}

function AnaliseRepo()
{
	# apenas para RHEL
	export FUNCAO="ANALISE_GPG_REPOSITORIO"
	echo "$(status) Analisando chaves gpg repositórios ativos..."
	
	
	FILES=$(ls /etc/yum.repos.d/)
	for file in $FILES; do
		IFSOLD="$IFS"
		IFS=";"
		REPO=""
		CONT=1
		STATUS="SUCESSO"
		for i in $(cat /etc/yum.repos.d/$file | tr "\n" ";"| sed "s/\[/\n\[/g"| grep "enabled=1"); do 
			#REPO="$REPO"$(echo -e "ARQUIVO: /etc/yum.repos.d/$file\n"; echo "$i" | egrep "\[|^name|enabled|gpgcheck|gpgkey" | tr '\n' ';'; echo)
			#if [ "$CONT" -eq 1 ]; then
			#	REPO="$REPO"$(echo -e "<b>ARQUIVO: /etc/yum.repos.d/$file</b><br/>\n")
			#fi
			REPO="$REPO"$(echo "$i" | egrep "\[|^name|gpgcheck|gpgkey" | tr '\n' ';'; echo )
			CONT=$(($CONT+1))
			
			GPGCHECK=""
			GPGCHECK=$(echo "$REPO" | grep "gpgcheck=0")
			
			if [ -n "$GPGCHECK" ];then
				STATUS="FALHA"
			fi
			
		done
		if [ -n "$REPO" ]; then
				#echo "$REPO"
				gera_log2 "$FUNCAO" "$STATUS" "repo: etc/yum.repos.d/$file" "$REPO"
		fi
		IFS="$IFSOLD"
		
		
	done

	# adicionando um enter após os dados
	#REPO="$REPO"$(echo '<br />')
	#gera_log2 "$FUNCAO" "INFO" "Analise dos Repositórios ativos" "$REPO"
			
}


function getPackage2UpgradeCorretivo()
{
    export FUNCAO="ATUALIZACOES"
	echo "$(status) Obtendo atualizações corretivas..."
    DISTRO="$1"
    case "$DISTRO" in
        "DEB")
            #apt list --upgradable 2> /dev/null
            #apt-get update && \
            PKG=\"$(apt-get -V upgrade --assume-no | grep "("| sed 's/[)(=>]//g' | awk '{print $1";"$2";"$3}'| tr '\n' ';'; echo)\"
            ;;
        "RPM")
            PKG=$(yum updateinfo list all | egrep -v -i "updateinfo|Plugins"| tr '\n' ';'; echo)
            ;;    
    esac
    gera_log2 "$FUNCAO" "INFO" "Lista de pacotes corretivos" "$PKG"
    
}

function get_tmp_filesystem()
{
	echo "$(status) Analizando sistema de arquivo /tmp..."
	export FUNCAO="TESTE_TMP"
	TESTE="/tmp"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$FUNCAO" "FALHA" "Partição $TESTE não está em fiesystem separado"
		return 1 
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	OPT="rw,nosuid,nodev,noexec,relatime"
	for i in ${OPT}; do
		RESULT=$(echo $PARTICAO | grep "$i")
		if [ -z "$RESULT" ];then
			gera_log2 "$FUNCAO" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$FUNCAO" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done	
}

function get_var_tmp_filesystem()
{
	echo "$(status) Analizando sistema de arquivo /var/tmp..."
	export FUNCAO="TESTE_VAR_TMP"
	TESTE="/var/tmp"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$FUNCAO" "FALHA" "Partição $TESTE não está em fiesystem separado"
		return 1 
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	OPT="rw,nosuid,nodev,noexec,relatime"
	for i in ${OPT}; do
		RESULT=$(echo $PARTICAO | grep "$i")
		if [ -z "$RESULT" ];then
			gera_log2 "$FUNCAO" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$FUNCAO" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done
	
}

function get_var_log_filesystem()
{
	echo "$(status) Analizando sistema de arquivo /var/log..."
	export FUNCAO="TESTE_VAR_LOG"
	TESTE="/var/log"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$FUNCAO" "FALHA" "Partição $TESTE não está em fiesystem separado"
		return 1 
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	OPT="rw,nosuid,nodev,noexec,relatime"
	for i in ${OPT}; do
		RESULT=$(echo $PARTICAO | grep "$i")
		if [ -z "$RESULT" ];then
			gera_log2 "$FUNCAO" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$FUNCAO" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done
	
}

function get_home_filesystem()
{
	echo "$(status) Analizando sistema de arquivo /home..."
	export FUNCAO="TESTE_HOME_TMP"
	TESTE="/home"
	PARTICAO=$(mount | grep "$TESTE")
	if [ -z "$PARTICAO" ];then
		gera_log2 "$FUNCAO" "FALHA" "Partição $TESTE não está em fiesystem separado"
		return 1 
	fi
		
	#OPT=$(mount | grep /home | egrep -o "([(]).([a-Z, =\)])*"| sed 's/)//g;s/(//g')
	OPT="nodev"
	for i in ${OPT}; do
		RESULT=$(echo $PARTICAO | grep "$i")
		if [ -z "$RESULT" ];then
			gera_log2 "$FUNCAO" "FALHA" "Diretorio: $TESTE não possui o atributo: $i" 
		else
			gera_log2 "$FUNCAO" "SUCESSO" "Diretorio: $TESTE possui o atributo: $i"  	
		fi		
	done	
}


function get_partitions()
{
	echo "$(status) Analizando partições..."
	export FUNCAO="PARTICOES_CONFIGURURACAO"
	RESP=$(fdisk -l | egrep "^Disk /|^/dev"| tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$FUNCAO" "FALHA" "Não foi possivel acessar as partições"
		return 1 
	else
		gera_log2 "$FUNCAO" "SUCESSO" "Lista de partições" "$RESP" 	
	fi	

}


function get_lvm()
{
	echo "$(status) Analizando PVs LVM..."
	export FUNCAO="LVM_CONFIGURURACAO"
	RESP=$(pvs| grep -v "Attr" | tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$FUNCAO" "FALHA" "Sistema não possui PVs"
		return 1 
	else
		gera_log2 "$FUNCAO" "SUCESSO" "Lista de PVs" "$RESP" 	
	fi
	
	echo "$(status) Analizando VGs LVM..."
	export FUNCAO="LVM_CONFIGURURACAO"
	RESP=$(vgs| grep -v "Attr" | tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$FUNCAO" "FALHA" "Sistema não possui VGs"
		return 1 
	else
		gera_log2 "$FUNCAO" "SUCESSO" "Lista de VGs" "$RESP" 	
	fi
	
	echo "$(status) Analizando LVs LVM..."
	export FUNCAO="LVM_CONFIGURURACAO"
	RESP=$(lvs| grep -v "Attr" | tr '\n' ';'; echo)
	if [ -z "$RESP" ];then
		gera_log2 "$FUNCAO" "FALHA" "Sistema não possui LVs"
		return 1 
	else
		gera_log2 "$FUNCAO" "SUCESSO" "Lista de LVs" "$RESP" 	
	fi

		

}

function getFstab()
{
    export FUNCAO="MONTAGEM_PERSISTENTE"
	echo "$(status) Analisando pontos de montagems persistentes..."
   
    RESP=$(cat /etc/fstab | egrep -v "^#|^$" | tr '\n' ';'; echo)
    gera_log2 "$FUNCAO" "INFO" "Entradas do /etc/fstab" "$RESP"
    
}

function VerificaMontagens()
{
    export FUNCAO="MONTAGENS_ATIVAS"
	echo "$(status) Analisando pontos de montagens ativos..."
   
   	MONTAGENS=$(mount | grep "^/dev")
    RESP=$(echo "$MONTAGENS"| tr '\n' ';'; echo)
    gera_log2 "$FUNCAO" "INFO" "Lista de pacotes corretivos" "$RESP"
    
    
    export FUNCAO="VERIFICACAO_DE_MONTAGENS"
    IFSOLD=$IFS
    IFS=$'\n'
    for m in $MONTAGENS;do
    	DEVICE=$(echo "$m" | awk '{print $1}')
    	DEV_PERS=""
    	DEV_PERS=$(cat /etc/fstab | grep "$DEVICE")
    	
    	if [ -z "$DEV_PERS" ];then
    		# testando se o dispositivo está configurado com UUID
    		UUID=$(blkid "$DEVICE" |egrep -o "(UUID=).*([ ])*"|  awk '{print $1}'|awk -F"=" '{print $2}'| sed 's/\"//g')
    		# echo "UUID: $UUID"  # debug
    		DEV_PERS=$(cat /etc/fstab | grep "$UUID")
    		if [ -z "$DEV_PERS" ];then
    			gera_log2 "$FUNCAO" "FALHA" "Device não persistente. Verifique" "$DEVICE nem o $UUID"
    		else
    			gera_log2 "$FUNCAO" "SUCESSO" "Device persistente - UUID" "$DEVICE: $UUID"	
    		fi
    	else
    		gera_log2 "$FUNCAO" "SUCESSO" "Device persistente" "$DEVICE" 	
    	fi
    done
    IFS=$IFSOLD
}


# Tornando a função gera_log acessivel para qualquer sub-shell
export -f gera_log
export -f gera_log2
export -f gera_log3


## início do script, invocando as funções:
isRoot

cabecalho
getLinuxVersion

#getSelinux
#getHosts
#getRclocal
#getRoutes
#getCrontab
#getLimits
#getProcess
#getUsers
#getGroups
#sgetOpenPorts
getServicesEnabled "$TIPO_PACOTE"
#ocupacaoDiscos
#memoria_fisica
#memoria_ram
#memoria_swap

#search_nameserver
#valid_nameserver
#test_file
#world_writable
#nouser
#df_nouser
#nogroup
#df_nogroup
#nopasswd
#checkhome

getPackageList "$TIPO_PACOTE"
getPackage2UpgradeCorretivo "$TIPO_PACOTE"
getRepoList
AnaliseRepo

## Teste de file sistems
get_tmp_filesystem
get_var_tmp_filesystem
get_var_log_filesystem
get_home_filesystem


#LVM
get_partitions
get_lvm
getFstab
VerificaMontagens

# função importada do gerador de Html
gerarRelatorio "$LOGFILE" "${HOSTNAME_ATUAL}.html"
echo "$(status) Gerando relatório: ${HOSTNAME_ATUAL}.html e LOG:  $LOGFILE"

### TODO
# 1) Verificar serviços em execução com usuários estranhos
# 2) Avaliar o firewall local da máquina
# 3) configuração do sysctl

############################################################### 
