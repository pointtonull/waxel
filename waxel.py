#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from optparse import OptionParser
import os
import re
import sys

APP_NAME = "waxel"
LOG_FILE = os.path.expanduser("~/.%s.log" % APP_NAME)
CONFIG_FILES = [os.path.expanduser("~/.%s" % APP_NAME),
    os.path.expanduser("~/%s.ini" % APP_NAME)]
VERBOSE = 20


def get_options():
    "
    Parse the arguments
    "
    # Instance the parser and define the usage message
    optparser = OptionParser(usage="
    %prog [-vqdsc]", version="%prog .2")

"Inicio:"

optparser.add_option( "-V", "--version", help=("muestra la versión de Wget "
    "y sale."), action="store", dest=" version ")
optparser.add_option("-h" , "--help", help=("muestra esta ayuda."),
    action="store", dest="help")
optparser.add_option("-b", "--background", help=("irse a segundo plano"
    "después de empezar."), action="store", dest="background")
optparser.add_option("-e", "--execute=COMMAND", help=("ejecuta una orden"
    "estilo `.wgetrc'."), action="store", dest="execute")

"Ficheros de registro y de entrada:"
optparser.add_option("-o", "--output-file=FICHERO", help=("registrar mensajes"
    "en FICHERO."), action="store", dest="output-file")
optparser.add_option("-a", "--append-output=FILE", help=("anexar mensajes a"
    " FILE."), action="store", dest="append-output")
optparser.add_option("-d", "--debug", help=("saca montones de información "
    "para depuración."), action="store", dest="debug")
optparser.add_option("-q", "--quiet", help=("silencioso (sin texto de salida)"
    "."), action="store", dest="quiet")
optparser.add_option("-v", "--verbose", help=("sé verboso (es el método por "
    "defecto)."), action="store", dest="verbose")
optparser.add_option("-nv", "--no-verbose", help=("desactiva modo verboso, "
    "sin ser silencioso."), action="store", dest="no-verbose")

optparser.add_option(
"-i"
,
"--input-file=FILE"
, help=(
"descarga URLs encontradas en fichero (FILE) local o externo."
), action="store", dest="
")

optparser.add_option(
"-F"
,
"--force-html"
, help=(
"trata el fichero de entrada como HTML."
), action="store", dest="
")

optparser.add_option(
"-B"
,
"--base=URL"
, help=(
"resuelve enlaces HTML del fichero-de-entrada (-i -F) relativos a la URL."
), action="store", dest="
")

optparser.add_option(
"",
"--config=FILE"
, help=(
"Specify config file to use."
), action="store", dest="
")

"Descarga:"

optparser.add_option(
"-t"
,
"--tries=NÚMERO"
, help=(
"define número de intentos a NÚMERO (0 es sin limite)."
), action="store", dest="
")

optparser.add_option(
"",
"--retry-connrefused"
, help=(
"reintente incluso si la conexión es rechazada."
), action="store", dest="
")

optparser.add_option(
"-O"
,
"--output-document=FILE"
, help=(
"escriba documentos al fichero FILE."
), action="store", dest="
")

optparser.add_option(
"-nc"
,
"--no-clobber"
, help=(
"skip downloads that would download to existing files (overwriting them)."
), action="store", dest="
")

optparser.add_option(
"-c"
,
"--continue"
, help=(
"continuar una descarga parcial de un fichero."
), action="store", dest="
")

optparser.add_option(
"",
"--progress=TYPE"
, help=(
"seleccione tipo de indicador de progreso."
), action="store", dest="
")

optparser.add_option(
"-N"
,
"--timestamping"
, help=(
"no re-recuperar ficheros a menos que sean más nuevos que la versión local."
), action="store", dest="
")

optparser.add_option(
"",
"--no-use-server-timestamps"
, help=(
"no poner la hora/fecha del fichero local a la que tenga el del servidor."
), action="store", dest="
")

optparser.add_option(
"-S"
,
"--server-response"
, help=(
"mostrar la respuesta del servidor."
), action="store", dest="
")

optparser.add_option(
"",
"--spider"
, help=(
"(araña) no descargar nada."
), action="store", dest="
")
optparser.add_option(
"-T"
,
"--timeout=SEGUNDOS"
, help=(
"poner todos los valores de temporización a SEGUNDOS."
), action="store", dest="
")

optparser.add_option(
"",
"--dns-timeout=SEGS"
, help=(
"definir la temporización de la búsqueda DNS a SEGS."
), action="store", dest="
")

optparser.add_option(
"",
"--connect-timeout=SEGS"
, help=(
"definir la temporización de conexión a SEGS."
), action="store", dest="
")

optparser.add_option(
"",
"--read-timeout=SEGS"
, help=(
"definir la temporización de lectura a SEGS."
), action="store", dest="
")

optparser.add_option(
"-w"
,
"--wait=SEGUNDOS"
, help=(
"espera tantos SEGUNDOS entre reintentos."
), action="store", dest="
")

optparser.add_option(
"",
"--waitretry=SEGUNDOS"
, help=(
"espera 1..SEGUNDOS entre reintentos de una descarga."
), action="store", dest="
")

optparser.add_option(
"",
"--random-wait"
, help=(
"espera entre 0.5*WAIT...1.5*WAIT segs. entre descargas."
), action="store", dest="
")

optparser.add_option(
"",
"--no-proxy"
, help=(
"explícitamente desconecta el proxy."
), action="store", dest="
")

optparser.add_option(
"-Q"
,
"--quota=NÚMERO"
, help=(
"define la cuota de descarga a NÚMERO."
), action="store", dest="
")

optparser.add_option(
""
,
"--bind-address=DIRECCIÓN"
, help=(
"bind a DIRECCIÓN (nombredeequipo o IP) en equipo local."
), action="store", dest="
")

optparser.add_option(
""
,
"--limit-rate=VELOCIDAD"
, help=(
"limita velocidad de descarga a VELOCIDAD."
), action="store", dest="
")

optparser.add_option(
""
,
"--no-dns-cache"
, help=(
"desactiva búsquedas en tampón DNS."
), action="store", dest="
")

optparser.add_option(
""
,
"--restrict-file-names=OS"
, help=(
"restringe caracteres en nombres de ficheros a los que el SO permita."
), action="store", dest="
")

optparser.add_option(
""
,
"--ignore-case"
, help=(
"ignorar mayús/minúsculas al encajar ficheros/directorios."
), action="store", dest="
")

optparser.add_option(
"-4"
,
"--inet4-only"
, help=(
"conectar sólo a direcciones IPv4."
), action="store", dest="
")

optparser.add_option(
"-6"
,
"--inet6-only"
, help=(
"conectar sólo a direcciones IPv6."
), action="store", dest="
")

optparser.add_option(
""
,
"--prefer-family=FAMILY"
, help=(
"conectar primero a direcciones de la familia especificada, bien IPv6, IPv4, o ninguna."
), action="store", dest="
")

optparser.add_option(
""
,
"--user=USUARIO"
, help=(
"poner el usuario de ambos ftp y http a USUARIO."
), action="store", dest="
")

optparser.add_option(
""
,
"--password=CONTRASEÑA"
, help=(
"poner la contraseña de ambos ftp y http a CONTRASEÑA."
), action="store", dest="
")

optparser.add_option(
""
,
"--ask-password"
, help=(
"pedir las contraseñas."
), action="store", dest="
")

optparser.add_option(
""
,
"--no-iri"
, help=(
"desactivar soporte IRI."
), action="store", dest="
")

optparser.add_option(
""
,
"--local-encoding=ENC"
, help=(
"usar ccodificación ENC como la codificación local para IRIs."
), action="store", dest="
")

optparser.add_option(
""
,
"--remote-encoding=ENC"
, help=(
"usar ENC como la codificación remota por defecto."
), action="store", dest="
")

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--unlink"
"remove file before clobber."

"Directorios:"

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-nd"
"--no-directories"
"no crear directorios."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-x"
"--force-directories"
"forzar la creación de directorios."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-nH"
"--no-host-directories"
"no crear directorios del anfitrión."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--protocol-directories"
"use nombre de protocolo en los directorios."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-P"
"--directory-prefix=PREFIX"
"grabar los ficheros en PREFIX/..."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--cut-dirs=NÚMERO"
"ignorar NÚMERO de componentes de directorio remoto."

"Opciones HTTP:"

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--http-user=USUARIO"
"poner el usuario http a USUARIO."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--http-password=PASS"
"poner la contraseña http a PASS."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--no-cache"
"no permitir los datos en tampón del servidor."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--default-page=NAME"
"Cambiar el nombre de página por defecto (suele ser `index.html'.)."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-E"
"--adjust-extension"
"grabe documentos HTML/CSS con las extensiones correctas."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--ignore-length"
"ignorar campo `Content-Length' en cabeceras ."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--header=STRING"
"insertar STRING entre las cabeceras."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--max-redirect"
"máximo de redirecciones permitidas por página."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--proxy-user=USUARIO"
"poner USUARIO como nombre de usuario del proxy."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--proxy-password=PASS"
"poner PASS como contraseña del proxy."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--referer=URL"
"incluir cabecera `Referer: URL' en petición HTTP."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--save-headers"
"grabar las cabeceras HTTP a fichero."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-U"
"--user-agent=AGENTE"
"identificarse como AGENTE en vez de Wget/VERSIÓN."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--no-http-keep-alive"
"desactivar HTTP keep-alive (conexiones persistentes)."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--no-cookies"
"no usar "cookies"."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--load-cookies=FICHERO"
"cargar las "cookies" desde FICHERO antes de la sesión."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--save-cookies=FICHERO"
"grabar las "cookies" a FICHERO después de la sesión."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--keep-session-cookies"
"cargar y grabar las "cookies" de sesión (no-permanentes)."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--post-data=STRING"
"usar el método POST; enviar STRING como los datos."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--post-file=FICHERO"
"usar el método POST; envía el contenido de FICHERO."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--content-disposition"
"cumplir con la cabecera Content-Disposition cuando se elige nombre de ficheros locales (EXPERIMENTAL)."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--auth-no-challenge"
"enviar información de autenticicación básica HTTP sin antes esperar al desafío del servidor."

"Opciones HTTPS (SSL/TLS):"

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--secure-protocol=PR"
"elegir protocolo seguro entre auto, SSLv2, SSLv3, y TLSv1."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--no-check-certificate"
"no validar el certificado del servidor."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--certificate=FILE"
"fichero de certificado del cliente."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--certificate-type=TYPE"
"tipo de certificado de cliente, PEM o DER."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--private-key=FILE"
"fichero de llave privada."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--private-key-type=TYPE"
"tipo de llave privada, PEM o DER."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--ca-certificate=FILE"
"fichero con la agrupación de CAs."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--ca-directory=DIR"
"directorio donde se guarda la lista "hash" de CAs."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--random-file=FILE"
"fichero con datos aleatorios como semilla de SSL PRNG."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--egd-file=FICHERO"
"fichero que denomina el conector EGD con datos aleatorios."

"Opciones FTP:"

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--ftp-user=USUARIO"
"poner USUARIO como el usuario de ftp."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--ftp-password=PASS"
"poner PASS como contraseña ftp."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--no-remove-listing"
"no eliminar los ficheros `.listing'."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--no-glob"
"desactivar generación de nombres de fichero del FTP (globbing)."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--no-passive-ftp"
"desactivar el modo "pasivo" de transferencia."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--retr-symlinks"
"en modo recursivo, bajar los ficheros enlazados (no los directorios)."

"Bajada recursiva:"

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-r"
"--recursive"
"especificar descarga recursiva."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-l"
"--level=NUMBER"
"máxima profundidad de recursión (inf o 0 para infinita)."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--delete-after"
"borrar los ficheros localmente después de descargarlos."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-k"
"--convert-links"
"hacer que los enlaces en el HTML o CSS descargado apunte a ficheros locales."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-K"
"--backup-converted"
"antes de convertir el fichero X, salvaguardarlo como X.orig."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-m"
"--mirror"
"atajo para -N -r -l inf --no-remove-listing."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-p"
"--page-requisites"
"bajar todas las imágenes, etc. que se necesitan para mostrar la página HTML."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--strict-comments"
"activar manejo stricto (SGML) de los comentarios en HTML."

"Aceptar/rechazar recursivamente:"

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-A"
"--accept=LIST"
"lista separada por comas de extensiones aceptadas."
optparser.add_option(
,
, help=(
), action="store", dest="
")
"-R"
"--reject=LIST"
"lista separada por comas de extensiones rechazadas."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-D"
"--domains=LIST"
"lista separada por comas de dominios aceptados."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--exclude-domains=LIST"
"lista separada por comas de dominios rechazados."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--follow-ftp"
"seguir los enlaces a FTP de los documentos HTML."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--follow-tags=LIST"
"lista separada por comas de etiquetas HTML a seguir."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--ignore-tags=LIST"
"lista separada por comas de etiquetas HTML a ignorar."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-H"
"--span-hosts"
"ir a equipos extraños en el recorrido recursivo."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-L"
"--relative"
"sólo seguir enlaces relativos."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-I"
"--include-directories=LIST"
"lista de directorios permitidos."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"--trust-server-names"
"use the name specified by the redirection"
"url last component."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-X"
"--exclude-directories=LIST"

optparser.add_option(
,
, help=(
), action="store", dest="
")
"lista de directorios excluídos."

optparser.add_option(
,
, help=(
), action="store", dest="
")
"-np"
"--no-parent"
"no ascender al directorio padre."

    # Define the options and the actions of each one
    optparser.add_option("-s", "--section", help=("Process only the given "
        "section"), action="store", dest="section")
    optparser.add_option("-c", "--config", help=("Uses the given conf file "
        "inteast of the default"), action="store", dest="conffile")
    optparser.add_option("-l", "--log", help=("Uses the given log file "
        "inteast of the default"), action="store", dest="logfile")
    optparser.add_option("-v", "--verbose", action="count", dest="verbose",
        help="Increment verbosity")
    optparser.add_option("-q", "--quiet", action="count", dest="quiet",
        help="Decrement verbosity")

    # Define the default options
    optparser.set_defaults(verbose=0, quiet=0, logfile=LOG_FILE,
        conffile=)

    # Process the options
    options, args = optparser.parse_args()
    return options, args


def main(options, args):
    "The main routine"
    # Read the config values from the config files
    config = get_config(options.conffile)
    processfeed = Processfeed(config)
    processfeed.process_all_actions()


if __name__ == "__main__":
    # == Reading the options of the execution ==
    options, args = get_options()

    VERBOSE = (options.quiet - options.verbose) * 10 + 30
    format_str = "%(message)s"
    logging.basicConfig(format=format_str, level=VERBOSE)
    logger = logging.getLogger()

    DEBUG = ident(logger.debug) # For developers
    MOREINFO = ident(logger.info) # Plus info
    INFO = ident(logger.warning) # Default
    WARNING = ident(logger.error) # Non critical errors
    ERROR = ident(logger.critical) # Critical (will break)

    DEBUG("get_options::options: %s" % options)
    DEBUG("get_options::args: %s" % args)

    DEBUG("Verbose level: %s" % VERBOSE)
    exit(main(options, args))
