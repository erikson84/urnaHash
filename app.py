from shiny import App, render, ui, types
from pathlib import Path
import asn1tools
import binascii
import hashlib
import zipfile
import asyncio

ASSINATURA = """
ModuloAssinaturaResultado DEFINITIONS IMPLICIT TAGS ::= BEGIN

EXPORTS ALL;

-- TIPOS
DataHoraJE ::= GeneralString(SIZE(15))  -- Data e hora utilizada pela Justiça Eleitoral no formato YYYYMMDDThhmmss.

-- ENUMS
--Tipos de algoritmos de assinatura (cepesc é o algoritmo padrão (ainda não há previsão de uso dos demais)).
AlgoritmoAssinatura ::= ENUMERATED {
    rsa(1),
    ecdsa(2),
    cepesc(3)
}

-- Tipos de algoritmos de hash (Todos os algoritmos devem ser suportados, mas sha512 é o padrão).
AlgoritmoHash ::= ENUMERATED {
    sha1(1),
    sha256(2),
    sha384(3),
    sha512(4)
}

-- Tipos de modelos de urna eletrônica.
ModeloUrna ::= ENUMERATED {
    ue2009(9),  -- Urna modelo 2009.
    ue2010(10), -- Urna modelo 2010.
    ue2011(11), -- Urna modelo 2011.
    ue2013(13), -- Urna modelo 2013.
    ue2015(15), -- Urna modelo 2015.
    ue2020(20)  -- Urna modelo 2020.
}

-- ENVELOPE
-- Entidade que engloba a lista de assinaturas utilizadas para assinar os arquivos para manter a integridade e segurança dos dados.
EntidadeAssinatura ::= SEQUENCE {
    dataHoraCriacao         DataHoraJE,                         -- Data e Hora da criacao do arquivo.
    versao                  INTEGER (2..99999999),              -- Versao do protocolo (Alterações devem gerar novo valor. Nas eleições de 2012 foi utilizado o enumerado de valor 1, a partir de 2014 utilizar o valor 2).
    autoAssinado            AutoAssinaturaDigital,              -- Informações da auto assinatura digital.
    conteudoAutoAssinado    OCTET STRING,                       -- Conteúdo da assinatura do próprio arquivo.
    certificadoDigital      OCTET STRING OPTIONAL,              -- Certificado digital da urna eletrônica.
    conjuntoChave           GeneralString(SIZE(1..15)) OPTIONAL -- Identificador do conjunto de chaves usado para assinar o pacote.
}

-- Entidade responsável por gerar o arquivo de assinatura de todos os arquivos de resultados da urna.
-- Podendo ter dois tipos de assinatura (Hardware (HW) e Software (SW)).
-- Esses arquivos são informados na Mídia de Resultado quando a urna eletrônica é encerrada.
EntidadeAssinaturaResultado ::= SEQUENCE {
    modeloUrna      ModeloUrna,         -- Modelo da urna eletrônica.
    assinaturaSW    EntidadeAssinatura, -- Assinatura realizada via software (normalmente CEPESC).
    assinaturaHW    EntidadeAssinatura  -- Assinatura realizada via hardware de segurança da urna eletrônica.
}

-- Demais SEQUENCES
-- Informações do algoritmo de hash.
-- Informações do algoritmo de assinatura .
AlgoritmoAssinaturaInfo ::= SEQUENCE {
    algoritmo   AlgoritmoAssinatura,    -- Tipo do algoritmo de assinatura.
    bits        INTEGER                 -- Tamanho da assinatura.
}

AlgoritmoHashInfo ::= SEQUENCE {
    algoritmo AlgoritmoHash -- Tipo do algoritmo de hash.
}

-- Informações dos arquivos assinados.
Assinatura ::= SEQUENCE {
    arquivosAssinados SEQUENCE OF AssinaturaArquivo -- Lista com Informações dos arquivos assinados.
}

--Informações do arquivo e da assinatura.
AssinaturaArquivo ::= SEQUENCE {
    nomeArquivo GeneralString,      -- Nome do arquivo.
    assinatura  AssinaturaDigital   -- Assinatura digital do arquivo.
}

-- Informações da assinatura digital
AssinaturaDigital ::= SEQUENCE {
    tamanho     INTEGER,        -- Tamanho da assinatura.
    hash        OCTET STRING,   -- Hash da assinatura (Deve ser calculado uma única vez e ser utilizado também para o cálculo da assinatura).
    assinatura  OCTET STRING    -- Assinatura (Gerado/verificado a partir do hash acima).
}

-- Informações da auto assinatura digital.
AutoAssinaturaDigital ::= SEQUENCE {
    usuario             DescritorChave,             -- Nome do usuário (Geralmente uma seção) que realizou a assinatura do arquivo.
    algoritmoHash       AlgoritmoHashInfo,          -- Algoritmo de hash utilizado para realizar a assinatura (Será o mesmo para as assinaturas de arquivos).
    algoritmoAssinatura AlgoritmoAssinaturaInfo,    -- Algoritmo utilizado para realizar a assinatura (Será o mesmo para as assinaturas de arquivos).
    assinatura          AssinaturaDigital           -- Informações da assinatura digital.
}

-- Identificador com informações da assinatura.
DescritorChave ::= SEQUENCE {
    nomeUsuario GeneralString,  -- Nome do usuário (Geralmente uma seção) que realizou a assinatura no arquivo.
    serial      INTEGER         -- Data em que foi gerado o conjunto de chaves.
}

END

"""

conv = asn1tools.compile_string(ASSINATURA, codec='ber', numeric_enums=True)

def hashFile(file):
    sha = hashlib.sha512()
    sha.update(file)
    digest = sha.digest()
    return digest

def extract_hash(assinatura, arquivo):
    envelope_encoded = bytearray(assinatura)
    envelope_decoded = conv.decode("EntidadeAssinaturaResultado", envelope_encoded)
    entidade_assinatura = envelope_decoded['assinaturaHW']
    assinaturas_encoded = entidade_assinatura["conteudoAutoAssinado"]
    assinaturas_decoded = conv.decode("Assinatura", assinaturas_encoded)
    if arquivo == "log":
        resumo = assinaturas_decoded['arquivosAssinados'][10]['assinatura']['hash']
    elif arquivo == "bu":
        resumo = assinaturas_decoded['arquivosAssinados'][0]['assinatura']['hash']
    else:
        resumo = "Opção inválida"
    
    return resumo

def build_output(hash_original, hash_arquivo):
    if hash_original == hash_arquivo:
        color = "green"
    else:
        color = "red"

    out = "<p><strong>Hash da assinatura da urna</strong></p>" + \
    "<p style='color:" + color + "'>" + \
    binascii.hexlify(hash_original).decode('ascii') + "</p>" + \
    "<p><strong>Hash do arquivo apresentado</strong></p>" + \
    "<p style='color:" + color + "'>" + \
    binascii.hexlify(hash_arquivo).decode('ascii') + "</p>"

    return out
        


app_ui = ui.page_fluid(
    ui.tags.head(
        ui.tags.title("urnaHash"),
        ui.tags.style(ui.HTML(
            """
            html {
                margin-left: 10%;
                margin-right: 10%;
                background: #0f172a;
                padding: 0;
                word-wrap: break-word;
            }

            .container-fluid {
                display: flex;
                flex-direction: column;
                padding: 0;
            }

            h1, h2, h3, h4 {
                margin: 0;
                padding: 0;
            }

            #titles {
                background: #5b21b6;
                padding: 20px;
                color: #eff6ff;
                border-radius: 40px 40px 0 0;
            }

            header {
                background: #0f172a;
            }

            #exp {
                background: #0284c7;
                color: #eff6ff;
                padding: 40px 40px 10px 40px;
                border-radius: 40px 40px 0 0;
            }
            #expBack {
                background: #5b21b6;
            }
            a {
                color: #312e81;
            }

            #mainDiv {
                background: #0284c7;

            }

            main {
                border-radius: 40px 40px 0 0;
                background: white;
                padding: 40px;
            }
            p {
                margin-top: 0.5rem;
                margin-bottom: 0.5rem;
            }
            """
        ))
    ),
    ui.tags.header(
        ui.tags.div(
            ui.h1("UrnaHash", style='text-align: center'),
            ui.h2("Aplicativo para comparação dos hashes gerados pelas Urnas Eletrônicas", style='text-align: center'),
            id="titles",
        ),
        ui.tags.div(
            ui.tags.div(
                ui.HTML("""
                <h4 onclick='(function(){const lista = document.getElementById("guia");
                                        if (lista.style.display=="block") {
                                            lista.style.display="none";
                                            } else {
                                            lista.style.display="block";
                                            }
                                            })();' style="cursor: pointer; text-decoration: underline;">Guia rápido</h4>
                <ol id="guia" style="display: none">
                <li>Ir ao site dos <a href="https://resultados.tse.jus.br/">Resultados das Eleições 2022 no TSE, em "Dados de Urna"<a>
                <li>Escolher Estado, Município, Zona e Seção Eleitoral</li>
                <li>Fazer download dos arquivos de Boletim de Urna (.bu), Log de Urna (.zip) e Todos os Arquivos (.zip), que contém as assinaturas da urna</li>
                <li>Carregar cada arquivo em seu campo específico abaixo</li>
                <li>Verificar se os <i>hashes</i> são iguais (em verde) ou diferem (em vermelho)</li>
                <li>Opcional: teste o mesmo arquivo de assinaturas com Boletins de Urna e Log de Urna de outras seções para verificar o que acontece</li>
                </ol>
                <p> Este aplicativo compara os <i>hashes</i> do arquivo de assinaturas gerado pelas urnas eletrônicas com o arquivo de Boletim de Urna e Log de Urna disponibilizados pelo TSE.</p>
                <p> Quando os <i>hashes</i> do arquivo de assinaturas e dos demais arquivos são compatíveis, o resultado é apresentado em <span style="color: green">verde</span>; caso contrário, em <span style="color: red">vermelho</span>.</p>
                <p><strong> <i>Hashes</i> são como impressões digitais de arquivos, se os <i>hashes</i> dos arquivos de Boletim de Urna e Log de Urna
                são iguais aos do registrado no arquivo de assinaturas da urna, ambos só podem ser provenientes daquele urna específica.</strong></p>"""),
            ui.tags.p(ui.tags.a("MANUAL DE USO DETALHADO", href="manual.html")),
            ui.HTML("<p><strong>Aviso legal</strong>: Essa ferramenta não tem qualquer vinculação com o TSE ou partidos políticos e deve ser empregada apenas para fins educacionais.</p>"),
            id="exp"),
            
        id="expBack"),
    ),
    ui.tags.div(
        ui.tags.main(
        ui.layout_sidebar(
        ui.panel_sidebar(
            ui.input_file("fileSign", "Escolha um arquivo ZIP com assinaturas da UE (.zip)", accept=".zip", button_label='Escolher...', placeholder='Nenhum arquivo selecionado'),
            ui.input_file("fileLog", "Escolha um arquivo ZIP com Log de Urna (.zip)", accept='.zip', button_label='Escolher...', placeholder='Nenhum arquivo selecionado'),
            ui.input_file("fileBU", "Escolha um arquivo de Boletim de Urna (.bu)", accept='.bu', button_label='Escolher...', placeholder='Nenhum arquivo selecionado'),
            width=4,
            ),
        ui.panel_main(
            ui.output_ui("contents"),
                ),
            ),
        ),
    id="mainDiv"),
)


def server(input, output, session):
    @output
    @render.ui
    async def contents():
        if input.fileBU() is None or input.fileSign() is None or input.fileLog() is None:
            return "Por favor, escolha um arquivo de assinaturas, de log de urna e de boletim de urna."
        bu: list[types.FileInfo] = input.fileBU()
        log: list[types.FileInfo] = input.fileLog()
        sign: list[types.FileInfo] = input.fileSign()
        
        with zipfile.ZipFile(sign[0]['datapath'], mode='r') as zip:
            for f in zip.namelist():
                if f.endswith(".vscmr"):
                    with zip.open(f, 'r') as file:
                        fil = file.read()
                        originalLog = extract_hash(fil, "log")
                        originalBU = extract_hash(fil, "bu")
        
        with zipfile.ZipFile(log[0]['datapath'], mode='r') as zip:
            for f in zip.namelist():
                if f.endswith(".logjez"):
                    with zip.open(f, 'r') as file:
                        currentLog = hashFile(file.read())

        with open(bu[0]['datapath'], 'rb') as file:
            currentBU = hashFile(file.read())
        
        await asyncio.sleep(1)

        return ui.HTML("<h3>Hashes do Log de Urna</h3>" +
            build_output(originalLog, currentLog) + 
            "<h3>Hashes do Boletim de Urna</h3>" + 
            build_output(originalBU, currentBU)
            )


app = App(app_ui, server, static_assets=Path(__file__).parent / 'www')
