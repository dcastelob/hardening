#!/bin/bash

###############################################################

# Script de checagens de hardening; Givaldo Lins e Diego Oliveira; Suporte Informática; 2015#
# ver: 1.00.0004

###############################################################

# Parametros Globais

export LOGFILE="hardening-$(hostname)-$(date +"%x_%T").csv"
export SELINUX=1
export SILENCIOSO=0


function isRoot()
{
	MyUID=$(id -u)
	MyUSER=$(getent passwd $MyUID | cut -d":" -f1)
	if [ "$MyUID" -ne "0" ];then
		echo "[ERROR] User $MyUSER not privileged. Use sudo $0"
		exit 1
	fi
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
		echo "$(hostname)\;$ROTINA;$STATUS;$CATEGORIA;\"$MENSAGEM\"" >> $LOGFILE
	else
		echo "$(hostname)\;$ROTINA;$STATUS;$CATEGORIA;\"$MENSAGEM\"" | tee -a $LOGFILE
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
	echo "[ INFO ] Obtendo informações do servidor..."
	gera_log2 "$FUNCAO" "INFO" "Data de Apuração" "$(date +"%x %T")"
	gera_log2 "$FUNCAO" "INFO" "Usuário executor do levantamento" "$(whoami)"
	gera_log2 "$FUNCAO" "INFO" "Nome do computador" "$(hostname -s)"
	gera_log2 "$FUNCAO" "INFO" "Nome FQDN do computador" "$(hostname -f)"
	gera_log2 "$FUNCAO" "INFO" "Endereço IP do computador" "$(ip a | grep "inet "| awk '{print $2";"$7,$8";"}'| grep -v "127.0.0.1/8")"
	gera_log2 "$FUNCAO" "INFO" "Versão do Kernel" "$(uname -r)"
	gera_log2 "$FUNCAO" "INFO" "Sistema Operacional" "$(cat /etc/system-release)"
}

function servico_ativos()
{
	export FUNCAO="SERVICOS_ATIVOS"		
	PORTAS=$(ss -putan4 | grep LISTEN | awk '{print $5"/"$1}'| awk -F":" '{print $2}')
	# echo $PORTAS   # debug
	for i in ${PORTAS}; do
		#cat /etc/services | grep " $i"| sed 's/#//g' | awk '{print $2"("$1");"$3,$4,$5,$6,$7,$8,$9}'
		gera_log2 "$FUNCAO" "INFO" "Portas de serviços em escuta" "$i;$(cat /etc/services | grep " $i"| sed 's/#//g' | awk '{print $2"("$1");"$3,$4,$5,$6,$7,$8,$9}')"
		
	done
	
}

function ocupacaoDiscos()
{
	export FUNCAO="OCUPACAO_DISCOS"	
	DISCOS=$(df -h | grep ^/dev | awk '{print $1"("$6");"$2";"$5}')
	#echo $DISCOS
	for i in ${DISCOS}; do
		gera_log2 "$FUNCAO" "INFO" "Ocupação dos Discos" "$i"
	done	
}

function memoria_fisica()
{
	export FUNCAO="MEMORIA_FISICA"
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


function search_nameserver()
{
	export FUNCAO="NAME_SERVERS"
	echo "[ INFO ] Checando diretiva search - DNS client..."
	TEST1=$(cat /etc/resolv.conf | grep ^search | awk '{print $2}')

	if [ -n "$TEST1" ]; then
		gera_log2 "$FUNCAO" "SUCCESS" "Diretiva Search encontrado no resolv.conf" "$TEST1"
	else
		gera_log2 "$FUNCAO" "FAILED" "Diretiva Search não encontrado no resolv.conf"
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
				gera_log2 "$FUNCAO" "SUCCESS" "Nameservers resolve endereços corretamente" "$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
			else
				gera_log2 "$FUNCAO" "FAILED" "Nameservers não resolve endereços corretamente" "$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
			fi
		done
}

function valid_nameserver()
{
	export FUNCAO="VALIDA_NAMESERVER"
	echo "[ INFO ] Checando nameservers válidos do /etc/resolv.conf..."
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
# 				gera_log "FAILED;Nameservers não resolve endereços corretamente;$i;Esperado: $IP_REFERENCIA, retornado: $IP_TEMP"
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
		gera_log2 "$FUNCAO" "FAILED" "Diretiva nameserver não encontrado no resolv.conf"
	fi
}

function test_file () {
	#Permissão dos arquivos de senha do sistema local
	export FUNCAO="TESTA_PERMISSOES_ARQUIVOS_ESPECIAIS"
	
	if [ ! -e permissions.txt ]; then
		#Criando o arquivo de permissões para comparação caso ele não exista
		echo "[ INFO ] Criando o arquivo de permissoes..."
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
		
		echo "[ INFO ] Checando permissões do arquivo $FILE"
		TEST1=$(/bin/ls -l $FILE | awk '{print $1}')

		if [ "$TEST1" == "$PERM" ]; then
			gera_log2 "$FUNCAO" "SUCCESS" "Permissões arquivos do sistema" "$FILE;$TEST1"
		else
			gera_log2 "$FUNCAO" "FAILED" "Permissões arquivos do sistema" "$FILE;$TEST1 (Correta: $PERM)"
		fi

		echo "[ INFO ] Checando dono do arquivo $FILE"
		TEST1=$(/bin/ls -l $FILE | awk '{print $3}')

		if [ "$TEST1" = "$USER1" ]; then
            gera_log2 "$FUNCAO" "SUCCESS" "Proprietário do arquivo" "$FILE;$TEST1"
        else
            gera_log2 "$FUNCAO" "FAILED" "Proprietário do arquivo" "$FILE;$TEST1 (Correto: $USER1)"
        fi

        echo "[ INFO ] Checando grupo dono do arquivo $FILE"
        TEST1=$(/bin/ls -l $FILE | awk '{print $4}')

        if [ "$TEST1" = "$GROUP1" ]; then
			gera_log2 "$FUNCAO" "SUCCESS" "Grupo proprietário do arquivo" "$FILE;$TEST1"
		else
			gera_log2 "$FUNCAO" "FAILED" "Grupo proprietário do arquivo" "$FILE;$TEST1 (Correto: $GROUP1)"
		fi
done
}

function world_writable() {
	export FUNCAO="ESCRITA_PARA_OUTROS"
	
	echo "[ INFO ] Checando arquivos com permissão de escrita para outros..."
#	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -type f -perm -0002 | xargs -I '{}' ls -l '{}' |awk '{print "FAILED;Permissão de escrita outros usuários;"$9";"$1}' | xargs -I '{}' bash -c "gera_log2 $FUNCAO 'ALERT' '{}'"
	
	#MSG="\'Permissão de escrita outros usuários\'"
	#MSG="Permissao_escrita_outros_usuarios"
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -type f -perm -0002 | xargs -I '{}' ls -l '{}' |awk -v funcao="$FUNCAO" -v msg="$MSG" '{print funcao" FAILED " msg" "$9";"$1}' | xargs -I '{}' bash -c "gera_log2 '{}'"
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -type f -perm -0002 2> /dev/null | xargs -I '{}' ls -l '{}' |awk -v funcao="$FUNCAO" '{print funcao ";FAILED;Permissão de escrita outros usuários;"$9";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"

}

function ls_sem_total()
{
	ls -l $1 | grep -v ^total
}

function nouser() {
	export FUNCAO="ARQUIVOS_PROPRIETARIO_DESCONHECIDO"
	echo "[ INFO ] Checando arquivos com proprietário desconhecido..."
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser | xargs -I '{}' ls -l '{}' |awk '{print "FAILED;Proprietário desconhecido;"$9";"$1}' | xargs -I '{}' bash -c "gera_log '{}'"
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser | xargs -I '{}' ls -l '{}' | grep -v ^total |awk '{print "FAILED;Proprietário desconhecido;"$9$10$11$12";"$3}' | xargs -I '{}' bash -c "gera_log '{}'"
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser |xargs -I '{}' echo '{}' | sed 's/ /\\ /g' | xargs -I '{}' ls -l '{}' | grep -v ^total |awk '{print "FAILED;Proprietário desconhecido;"$9$10$11$12";"$3}' | xargs -I '{}' bash -c "gera_log '{}'"
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser | awk '{print "FAILED;Proprietário desconhecido;"$1" "$2" "$3" "$4" "$5" "$6}' | xargs -I '{}' bash -c "gera_log '{}'"
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -print0 | xargs -0 ls -l | grep -v ^total | grep -v ^$| grep -v :$  #|awk '{print "FAILED;Proprietário desconhecido;"$9" "$10" "$11" "$12";"$3}' | xargs -0  bash -c "gera_log "
	#ARQUIVOS=$(df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser) #| sed 's/ /\\ /g' ) 
	#ARQUIVOS=$(find /home -xdev -nouser -printf "%h/%f\n"| sed 's/ /\\ /g' 2>/dev/null)
	
	
	
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -printf "%s %U %h/%f\n"| awk '{print "FAILED;Proprietário desconhecido;"$3" "$4" "$5" "$6" "$7";"$2";"$1}' | xargs -I '{}' bash -c "gera_log2 $FUNCAO 'ALERT' '{}'"
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -printf "%s %U %h/%f\n" 2> /dev/null | awk -v funcao="$FUNCAO" '{print funcao ";FAILED;Proprietário desconhecido;"$3" "$4" "$5" "$6" "$7";"$2";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
	

}
function df_nouser()
{
	export FUNCAO="OCUPACAO_ARQUIVOS_PROPRIETARIO_DESCONHECIDO"
	echo "[ INFO ] Checando ocupação dos arquivos com proprietário desconhecido..."
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nouser -printf "%s\n" 2> /dev/null| awk -v funcao="$FUNCAO" '{soma+=$1}END{printf funcao ";FAILED;Ocupação por arquivos com proprietário desconhecido; %f bytes\n",soma }' | xargs -I '{}' bash -c "gera_log3 '{}'"

}

function nogroup() 
{
	export FUNCAO="ARQUIVOS_GRUPO_DESCONHECIDO"
	echo "[ INFO ] Checando arquivos com grupo proprietário desconhecido..."
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup | xargs -I '{}' ls -l '{}' |awk '{print "FAILED;O arquivo "$9" tem grupo proprieta rio desconhecido;"$4}' | xargs -I '{}' bash -c "gera_log '{}'"
	#df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup | xargs -I '{}' ls -l '{}' |awk '{print "FAILED;Grupo proprietario desconhecido;"$9";"$1}' | xargs -I '{}' bash -c "gera_log '{}'"
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup -printf "%s %g %h/%f\n" 2> /dev/null| awk -v funcao="$FUNCAO" '{print funcao ";FAILED;Grupo proprietário desconhecido;"$3" "$4" "$5" "$6" "$7";"$2";"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"

}

function df_nogroup()
{
	export FUNCAO="OCUPACAO_ARQUIVOS_GRUPO_DESCONHECIDO"
	echo "[ INFO ] Checando ocupação dos arquivos com grupo proprietário desconhecido..."
	
	df --local -P | awk {'if (NR!=1) print $6'}| xargs -I '{}' find '{}' -xdev -nogroup -printf "%s\n" 2> /dev/null | awk -v funcao="$FUNCAO" '{soma+=$1}END{printf funcao ";FAILED;Ocupação por arquivos com grupo proprietário desconhecido; %f bytes\n",soma }' | xargs -I '{}' bash -c "gera_log3 '{}'"

}


function nopasswd(){
	export FUNCAO="USUARIOS_SEM_SENHA"
	echo "[ INFO ] Checando se há usuários sem senha..."
	cat /etc/shadow | awk -v funcao="$FUNCAO" -F: '($2 == "" ) {print funcao ";FAILED;Usuário sem senha;"$1}' | xargs -I '{}' bash -c "gera_log3 '{}'"
}

function checkhome(){
    export FUNCAO="PERMISSOES_HOME"
    # Configurando em caso de utilização de SELinux
    if [ "$SELINUX" -eq 1 ]; then
    	PERMISSAO_IDEAL="drwx------."
    else 
    	PERMISSAO_IDEAL="drwx------"
    fi
    
    echo "[ INFO ] Checando se as permissões dos diretórios HOME de todos os usuários válidos do /etc/passwd..."
	LISTA=$(egrep -v '(root|halt|sync|shutdown)' /etc/passwd| awk -F: '($7 != "/sbin/nologin") {print $1";"$3";"$6}')
    for i in "$LISTA" ; do
		#Obtendo os dados
		dir=`echo $i| cut -d";" -f3`
		uid=`echo $i| cut -d";" -f2`
		user=`echo $i| cut -d";" -f1`
		dirperm=`ls -ld $dir | cut -f1 -d" "`
		# echo $dirperm $dir $uid $user   # debug
		if [ "$dirperm" != "$PERMISSAO_IDEAL" ]; then
			gera_log2 "$FUNCAO" "FAILED" "Permissao do diretorio Home" "$dir;$dirperm (Correta: $PERMISSAO_IDEAL)"
		else
			gera_log2 "$FUNCAO" "SUCESS" "Permissao do diretorio Home" "$dir;$dirperm (Correta: $PERMISSAO_IDEAL)"	
		fi

		correto=`ls -ldn $dir | awk '{print $3}'`
		if [ "$correto" -ne "$uid" ]; then
			gera_log2 "$FUNCAO" "FAILED" "Proprietario do diretorio Home" "$dir;$user: $uid (Correto: $correto)"
		fi
	done
}
#Tornando a função gera_log acessivel para qualquer sub-shell
export -f gera_log
export -f gera_log2
export -f gera_log3


## início do script, invocando as funções:
isRoot

cabecalho

servico_ativos
ocupacaoDiscos
memoria_fisica

search_nameserver
valid_nameserver
test_file
world_writable
nouser
df_nouser
nogroup
df_nogroup
nopasswd
checkhome

############################################################### 
