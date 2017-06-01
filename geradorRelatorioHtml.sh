#!/bin/bash
# gerador de html

#RELATORIO=relatorio.html  

function header()
{
	echo "<html>"
	echo '<meta charset="utf-8"/>'
	echo "<head>"	
	echo '<style type="text/css">' 
	echo '	.tg  {border-collapse:collapse;border-spacing:0;;width:90%;}'
	echo '	.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}'
	#echo '	.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}'
	echo '	.tg th{border-style:solid;border-width:1px;overflow:hidden;word-break:normal;font-family:Courier;text-align: justify; font-size:14px;line-height: 1.0;}'
	echo '	.tg .tg-yw4l{vertical-align:top}'
	#echo ' td_cmd {font-family:monospace, Courier;font-size:14px;text-align: justify;}'
	echo ' td_cmd {font-family:monospace, ti92pluspc;font-size:14px;text-align: justify;}'
	echo '  p {margin: 0;}'
	echo '  .falha {color: red;}'
	echo '  .sucesso {color: green;}'
	echo '  .info {color: blue;}'
	echo '  .DivCentral { width:90%; height:80%; position:absolute; left:10% }'
	echo '</style>'
	echo "</head>"
	echo "<div class='DivCentral'>"
}


function footer()
{
	echo "</div>"
	echo "</html>"
}

function h1()
{
	echo "<h1>$1</h1>"
}

function h2()
{
	echo "<h2>$1</h2>"
}

function h3()
{
	echo "<h3>$1</h3>"
}

function linha()
{
	DADOS="$1"
	DADOS=$(echo $DADOS | sed 's/"//g'| sed 's/; /;/g')
	#echo "Dados: $DADOS"
	IFS=$'\n'
	for linha in $DADOS; do
		#echo "Linha: $linha"   # debug
		OLD_IFS=$IFS
		IFS=$'\n;'
		echo "<tr>"
		for coluna in $linha; do
			echo "	<th>$coluna</th>"
		done
		IFS="$OLD_IFS"
		#IFS=$' \t\n'
		echo "</tr>"
	done
	
	  
}

function lista()
{
	DADOS="$1"
	DADOS=$(echo "$DADOS" | sed 's/"//g'| sed 's/; /;/g')
	#echo "Dados: $DADOS"
	IFS=$'\n'
	for linha in $DADOS; do
		#echo "Linha: $linha"   # debug
		OLD_IFS=$IFS
		IFS=$'\n;'
		
		for coluna in $linha; do
			echo "<tr>"
			echo "	<th>$coluna</th>"
			echo "</tr>"
		done
		IFS="$OLD_IFS"
		#IFS=$' \t\n'
		
	done
	
	  
}

function listaSubcategoria()
{
	DADOS="$1"
	DADOS=$(echo "$DADOS" | sed 's/"//g'| sed 's/; /;/g')
	#DADOS=$(echo $DADOS | sed 's/"//g')
	#echo -e "Dados: $DADOS"
	IFS=$'\n'
	for linha in $DADOS; do
		#echo -e "Linha: $linha"   # debug
		OLD_IFS=$IFS
		#IFS=$'\n;'
		
		echo "<tr>"
		IFS=$';'
		for coluna in $linha; do
			
			echo "	<th>$coluna</th>"
			
		done
		echo "</tr>"
		IFS="$OLD_IFS"
		#IFS=$' \t\n'
		
	done
	
	  
}

function lista_simples()
{
	DADOS="$1"
	
	#DADOS=$(echo "$DADOS" | sed 's/"//g'| tr ';' '\n' )
	DADOS=$(echo "$DADOS" | sed 's/"//g' )
	#echo "Dados: $DADOS"
	IFS=';'
	CONT=1
#	for pkg in $DADOS; do
#		if [ "$CONT" -ne 1 ];then
#			PKGs=$PKGs$(echo "<p class='td_cmd'>$pkg</p>")
#		fi
#		CONT=$(($CONT+1))	
#	done
	PKGs=$PKGs$(echo "<p class='td_cmd'>")
	for pkg in $DADOS; do
		if [ "$CONT" -ne 1 ];then
			PKGs=$PKGs$(echo "$pkg<br/>")
		fi
		CONT=$(($CONT+1))	
	done
	PKGs=$PKGs$(echo "</p>")

#	PKG=$(echo "$DADOS"| xargs
#		if [ "$CONT" -ne 1 ];then
#			echo "<p class='td_cmd'>{}</p>"
#		fi
#		CONT=$(($CONT+1))
#	)		
		
#	PKGs=$(echo "$DADOS"| xargs -I '{}' echo "<p class='td_cmd'>{}</p>")		

	
	#echo "Pkg: $PKGs"
	echo "<tr>"
	#echo "	<th>$DADOS</th>"
	echo "	<th>$PKGs</th>"
	echo "</tr>"
}

function tabela()
{
	CONTEUDO="$1"
	echo '<table class="tg">'
#	echo '<table>'
	echo "$CONTEUDO"
	echo '</table>'
	
}

function getData()
{
	ARQUIVO="$1"
	FILTRO="$2"
	CAMPO="$3"
	
	cat "$ARQUIVO" | egrep -i "$FILTRO" | cut -d";" -f"$CAMPO" 
	#cat "$ARQUIVO" | xargs -i echo {} | egrep -i "$FILTRO" | cut -d";" -f"$CAMPO"
	
}

function geraTabela()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"

	DADO_FILTRADO=$(getData "$FONTE_DADOS" "$CAMPO" "4-100000")

	CONTEUDO_TABELA=$(linha "$DADO_FILTRADO")
	tabela "$CONTEUDO_TABELA" >> "$RELATORIO"
}

function geraLista()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"

	DADO_FILTRADO=$(getData "$FONTE_DADOS" "$CAMPO" "4-100000")

	CONTEUDO_TABELA=$(lista "$DADO_FILTRADO")
	tabela "$CONTEUDO_TABELA" >> "$RELATORIO"
}

function geraListaSubcategorizada()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"

	DADO_FILTRADO="$(getData "$FONTE_DADOS" "$CAMPO" "4-100000")"
	CONTEUDO_TABELA=$(listaSubcategoria "$DADO_FILTRADO")
	tabela "$CONTEUDO_TABELA" >> "$RELATORIO"
}

function geraListaSimples()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"
	#getData "$FONTE_DADOS" "$CAMPO" "4-100"
	DADO_FILTRADO=$(getData "$FONTE_DADOS" "$CAMPO" "4-100000")
	#echo "DADO_FILTRADO $DADO_FILTRADO"  >> "$RELATORIO"
	CONTEUDO_TABELA=$(lista_simples "$DADO_FILTRADO")
	tabela "$CONTEUDO_TABELA" >> "$RELATORIO"
}


function gerarRelatorio()
{
	if [ -z "$1" ];then
		FONTE_DADOS="teste.csv"
	else 
		FONTE_DADOS="$1"	
	fi
	
	if [ -z "$2" ];then
		RELATORIO="relatorio.html"
	else 
		RELATORIO="$2"	
	fi
	
	#FONTE_DADOS="teste.csv"

	# Coletando as subcategorias
	#CATEGORIAS=$(cat "$FONTE_DADOS" | cut -d";" -f2 | uniq)
	CATEGORIAS=$(cat "$FONTE_DADOS" | cut -d";" -f2,3 | uniq)
	
	#CATEGORIAS=$(cat "$FONTE_DADOS" | cut -d";" -f2,3,4 | uniq)
	#CATEGORIA_UNICA=$(echo "$CATEGORIA"| uniq )

	echo > "$RELATORIO"
	header >> "$RELATORIO"
	h1 "RESUMO DA MAQUINA" >> "$RELATORIO"
	h3 "Fonte dos dados: $1" >> "$RELATORIO"
	h3 "Relatório gerado: $2" >> "$RELATORIO"

	IFS_OLD=$IFS
	IFS=$'\n'


	for ITEM in $CATEGORIAS; do
	
	#	STATUS=$(echo $ITEM| cut -d";" -f1)
	#	SUB_CATEGORIA=$(echo $ITEM| cut -d";" -f3)
		
		# Categoria vem apenas com 2 campos selecionados na fonte de dados
		FORMATO_HTML=$(echo $ITEM| cut -d";" -f1)
		CATEGORIA=$(echo $ITEM| cut -d";" -f2)
	
		
		###echo "FORMATO_HTML: $FORMATO_HTML, CATEGORIA: $CATEGORIA"
		# Escolhedo o tipo de foramtação de dados o resultado será gerado no html
		case "$FORMATO_HTML" in
		
			

			#"LISTA_PACOTES"|"ATUALIZACOES_SEGURANÇA"|"SUMARIO_ATUALIZACOES"|"REPOSITORIO_ATIVO"|"RELACAO_USUARIOS"|"RELACAO_GRUPOS"|"HOSTS_FILE"|"ROTAS"|"AGENDAMENTOS"|"CRONTAB_EXTRAS"|"LIMITES_SISTEMA"|"LIMITS.CONF"|"LIMITS.D"|"RC.LOCAL"|"PROCESSOS"|"PARTICOES_CONFIGURURACAO"|"MONTAGEM_PERSISTENTE"|"MONTAGENS_ATIVAS"|"SERVIÇOS_ATIVOS_NO_BOOT"|"OCUPACAO_DIRETORIOS")
			"LISTASIMPLES")
							geraListaSimples "$CATEGORIA"
							;;
			"LISTAPADRAO")
							geraLista "$CATEGORIA"
							;;				
			#"CABECALHO"|"PORTAS_ABERTAS"|"OCUPACAO_DISCOS"|"MEMORIA_FISICA"|"MEMORIA_SWAP"|"MEMORIA_RAM"|"TESTA_PERMISSOES_ARQUIVOS_ESPECIAIS"|"ARQUIVOS_PROPRIETARIO_DESCONHECIDO"|"ARQUIVOS_GRUPO_DESCONHECIDO"|"ESCRITA_PARA_OUTROS"|"PERMISSOES_HOME"|"TESTE_DNS"|"01-SELINUX"|"TESTE_TMP"|"TESTE_VAR_TMP"|"TESTE_VAR_LOG"|"TESTE_HOME_TMP"|"LVM_CONFIGURACAO"|"ANALISE_GPG_REPOSITORIO"|"VERIFICACAO_DE_MONTAGENS"|"VERIFICA_VMTOOLS"|"VALIDA_NOME_NO_DNS_DIRETO"|"VALIDA_NOME_NO_DNS_REVERSO")
			"SUBCATEGORIZADA")	
							geraListaSubcategorizada "$CATEGORIA"
							;;
			*) 
							geraTabela 	"$CATEGORIA"
							;;
		esac
	done

	#DADO_FILTRADO=$(getData "$FONTE_DADOS" "Endereço IP do computador" "4-100")

	######CONTEUDO_TABELA=$(linha "$(cat teste.csv| cut -d";" -f4-100)")
	#CONTEUDO_TABELA=$(linha "$DADO_FILTRADO")
	#tabela "$CONTEUDO_TABELA" >> "$RELATORIO"

	##geraTabela 	"Endereço IP do computador"
	##geraTabela 	"Funcionamento desde"

	footer >> "$RELATORIO"
	
}

# ######
# Inicio do relatório

gerarRelatorio "$1" "$2"


