#!/bin/bash
# gerador de html

RELATORIO=relatorio.html

function header()
{
	echo "<html>"
	echo '<meta charset="utf-8"/>'
	echo '<style type="text/css">' 
	echo '	.tg  {border-collapse:collapse;border-spacing:0;;width:70%;}'
	echo '	.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}'
	#echo '	.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;}'
	echo '	.tg th{border-style:solid;border-width:1px;overflow:hidden;word-break:normal;font-family:monospace, Courier;text-align: justify; font-size:12px;line-height: 0.8;}'
	echo '	.tg .tg-yw4l{vertical-align:top}'
	echo ' td_cmd {font-family:monospace, Courier;font-size:14px;text-align: justify;}'
	echo '</style>'
}


function footer()
{
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
	for pkg in $DADOS; do
		if [ "$CONT" -ne 1 ];then
			PKGs=$PKGs$(echo "<p class='td_cmd'>$pkg</p>")
		fi
		CONT=$(($CONT+1))	
	done
	
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
	
}

function geraTabela()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"

	DADO_FILTRADO=$(getData "$FONTE_DADOS" "$CAMPO" "4-100")

	CONTEUDO_TABELA=$(linha "$DADO_FILTRADO")
	tabela "$CONTEUDO_TABELA" >> "$RELATORIO"
}

function geraLista()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"

	DADO_FILTRADO=$(getData "$FONTE_DADOS" "$CAMPO" "4-100")

	CONTEUDO_TABELA=$(lista "$DADO_FILTRADO")
	tabela "$CONTEUDO_TABELA" >> "$RELATORIO"
}

function geraListaSubcategorizada()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"

	DADO_FILTRADO="$(getData "$FONTE_DADOS" "$CAMPO" "3-100")"
	CONTEUDO_TABELA=$(listaSubcategoria "$DADO_FILTRADO")
	tabela "$CONTEUDO_TABELA" >> "$RELATORIO"
}

function geraListaSimples()
{
	CAMPO="$1"
	h2 "$CAMPO" >> "$RELATORIO"

	DADO_FILTRADO=$(getData "$FONTE_DADOS" "$CAMPO" "4-100")

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
	CATEGORIAS=$(cat "$FONTE_DADOS" | cut -d";" -f2 | uniq)
	#CATEGORIAS=$(cat "$FONTE_DADOS" | cut -d";" -f2,3,4 | uniq)
	#CATEGORIA_UNICA=$(echo "$CATEGORIA"| uniq )

	echo > "$RELATORIO"
	header >> "$RELATORIO"
	h1 "RESUMO DA MAQUINA" >> "$RELATORIO"
	h2 "Fonte dos dados: $1" >> "$RELATORIO"
	h2 "Relatório gerado: $2" >> "$RELATORIO"

	IFS_OLD=$IFS
	IFS=$'\n'


	for ITEM in $CATEGORIAS; do
	#	CATEGORIA=$(echo $ITEM| cut -d";" -f1)
	#	STATUS=$(echo $ITEM| cut -d";" -f1)
	#	SUB_CATEGORIA=$(echo $ITEM| cut -d";" -f3)
	
		CATEGORIA="$ITEM"
		case "$CATEGORIA" in


			"LISTA_PACOTES"|"ATUALIZACOES"|"REPOSITORIO_ATIVO"|"RELACAO_USUARIOS"|RELACAO_GRUPOS)
							geraListaSimples "$CATEGORIA"
							;;
			asasa)
							geraLista "$CATEGORIA"
							;;				
			"CABECALHO"|"SERVICOS_ATIVOS"|"OCUPACAO_DISCOS"|"MEMORIA_FISICA"|"MEMORIA_SWAP"|"TESTA_PERMISSOES_ARQUIVOS_ESPECIAIS"|"ESCRITA_PARA_OUTROS"|"PERMISSOES_HOME"|"TESTE_DNS")
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


