#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from ConfigParser import SafeConfigParser
from optparse import OptionParser
import logging
import os
import re
import sys

APP_NAME = "waxel"
LOG_FILE = os.path.expanduser("~/.%s.log" % APP_NAME)
CONFIG_FILES = [os.path.expanduser("~/.%s" % APP_NAME),
    os.path.expanduser("~/%s.ini" % APP_NAME)]
VERBOSE = 20

"""
Know issues:
    + NEVER will implement boggus parts from wget interface like:
        - two chars shorts options: -nc, -nv, -nb, -nH, -np
"""

def get_depth():
    """
    Returns the current recursion level. Nice to look and debug
    """
    def exist_frame(number):
        """
        True if frame number exists
        """
        try:
            if sys._getframe(number):
                return True
        except ValueError:
            return False

    maxn = 1
    minn = 0

    while exist_frame(maxn):
        minn = maxn
        maxn *= 2

    middle = (minn + maxn) / 2

    while minn < middle:
        if exist_frame(middle):
            minn = middle
        else:
            maxn = middle

        middle = (minn + maxn) / 2

    return max(minn - 4, 0)

def ident(func, identation="  "):
    """
    Decorates func to add identation prior arg[0]
    """
    def decorated(message, *args, **kwargs):
        newmessage = "%s%s" % (identation * (get_depth() - 1), message)
        return func(newmessage, *args, **kwargs)
    return decorated

def get_config(conf_file=None):
    """
    Read config files
    """
    config = SafeConfigParser(None)
    read_from = conf_file or CONFIG_FILES
    files = config.read(read_from)
    DEBUG("get_config::readed %s" % files)

    return config

def get_options():
    """
    Parse the arguments
    """
    # Instance the parser and define the usage message
    optparser = OptionParser(usage="""
    %prog [-vqdsc]""")

    "Inicio:"
    optparser.add_option( "-V", "--version", help=("muestra la versión de Wget "
        "y sale."), action="store_true", dest="version ")
    optparser.add_option("-b", "--background", help=("irse a segundo plano"
        "después de empezar."), action="store_true", dest="background")
    optparser.add_option("-e", "--execute", help=("ejecuta una orden"
        "estilo `.wgetrc'."), action="store", dest="execute")

    "Ficheros de registro y de entrada:"
    optparser.add_option("-o", "--output-file", help=("registrar mensajes"
        "en FICHERO."), action="store", dest="output-file")
    optparser.add_option("-a", "--append-output", help=("anexar mensajes a"
        " FILE."), action="store", dest="append-output")
    optparser.add_option("-d", "--debug", help=("saca montones de información "
        "para depuración."), action="store_true", dest="debug")
    optparser.add_option("-q", "--quiet", help=("silencioso (sin texto de "
        "salida)."), action="store_true", dest="quiet")
    optparser.add_option("-v", "--verbose", help=("sé verboso (es el método "
        "por defecto)."), action="store_true", dest="verbose")
    optparser.add_option("--no-verbose", help=("desactiva modo verboso, "
        "sin ser silencioso."), action="store_true", dest="no-verbose")
    optparser.add_option("-i", "--input-file", help=("descarga URLs "
        "encontradas en fichero (FILE) local o externo."), action="store",
        dest="input-file")
    optparser.add_option("-F", "--force-html", help=("trata el fichero de "
        "entrada como HTML."), action="store_true", dest="force-html")
    optparser.add_option("-B", "--base", help=("resuelve enlaces HTML del "
        "fichero-de-entrada (-i -F) relativos a la URL."), action="store",
        dest="base")
    optparser.add_option("", "--config" , help=("Specify config file to use."),
        action="store_true", dest="config")

    "Descarga:"
    optparser.add_option("-t", "--tries", help=("define número de intentos a "
        "NÚMERO (0 es sin limite)."), action="store", type="int", dest="tries")
    optparser.add_option("", "--retry-connrefused", help=("reintente incluso si"
        " la conexión es rechazada."), action="store_true",
        dest="retry-connrefused")
    optparser.add_option("-O", "--output-document", help=("escriba documentos "
        "al fichero FILE."), action="store", dest="output-document")
    optparser.add_option("--no-clobber", help=("skip downloads that "
        "would download to existing files (overwriting them)."),
        action="store_true", dest="no-clobber")
    optparser.add_option("-c", "--continue", help=("continuar una descarga "
        "parcial de un fichero."), action="store_true", dest="continue")
    optparser.add_option("", "--progress", help=("seleccione tipo de indicador "
        "de progreso."), action="store", dest="progress")
    optparser.add_option("-N", "--timestamping", help=("no re-recuperar "
        "ficheros a menos que sean más nuevos que la versión local."),
        action="store_true", dest="timestamping")
    optparser.add_option("", "--no-use-server-timestamps", help=("no poner la "
        "hora/fecha del fichero local a la que tenga el del servidor."), 
        action="store_true", dest="no-use-server-timestamps")
    optparser.add_option("-S", "--server-response", help=("mostrar la "
        "respuesta del servidor."), action="store_true", dest="server-response")
    optparser.add_option("", "--spider", help=("(araña) no descargar nada."),
        action="store_true", dest="spider")
    optparser.add_option("-T", "--timeout", help=("poner todos los valores de "
        "temporización a SEGUNDOS."), action="store", type="int", 
        dest="timeout")
    optparser.add_option("", "--dns-timeout", help=("definir la temporización "
        "de la búsqueda DNS a SEGS."), action="store", type="int",
        dest="dns-timeout")
    optparser.add_option("", "--connect-timeout", help=("definir la "
        "temporización de conexión a SEGS."), action="store", type="int",
        dest="connect-timeout")
    optparser.add_option("", "--read-timeout", help=("definir la temporización"
        " de lectura a SEGS."), action="store", type="int", dest="read-timeout")
    optparser.add_option("-w", "--wait", help=("espera tantos SEGUNDOS entre "
        "reintentos."), action="store", type="int", dest="wait")
    optparser.add_option("", "--waitretry", help=("espera 1..SEGUNDOS entre "
        "reintentos de una descarga."), action="store", type="int",
        dest="waitretry")
    optparser.add_option("", "--random-wait", help=("espera entre 0.5*WAIT...1"
        ".5*WAIT segs. entre descargas."), action="store_true",
        dest="random-wait")
    optparser.add_option("", "--no-proxy", help=("explícitamente desconecta el "
        "proxy."), action="store_true", dest="no-proxy")
    optparser.add_option("-Q", "--quota", help=("define la cuota de descarga a "
        "NÚMERO."), action="store", type="int", dest="quota")
    optparser.add_option("", "--bind-address", help=("bind a DIRECCIÓN "
        "(nombredeequipo o IP) en equipo local."), action="store",
        dest="bind-address")
    optparser.add_option("", "--limit-rate", help=("limita velocidad de "
        "descarga a VELOCIDAD."), action="store", dest="limit-rate")
    optparser.add_option("", "--no-dns-cache", help=("desactiva búsquedas en "
        "tampón DNS."), action="store_true", dest="no-dns-cache")
    optparser.add_option("", "--restrict-file-names", help=("restringe "
        "caracteres en nombres de ficheros a los que el SO permita."),
        action="store_true", dest="restrict-file-names")
    optparser.add_option("", "--ignore-case", help=("ignorar mayús/minúsculas "
        "al encajar ficheros/directorios."), action="store_true",
        dest="ignore-case")
    optparser.add_option("-4", "--inet4-only", help=("conectar sólo a "
        "direcciones IPv4."), action="store_true", dest="inet4-only")
    optparser.add_option("-6", "--inet6-only", help=("conectar sólo a "
        "direcciones IPv6."), action="store_true", dest="inet6-only")
    optparser.add_option("", "--prefer-family", help=("conectar primero a "
        "direcciones de la familia especificada, bien IPv6, IPv4, o ninguna."),
        action="store", dest="prefer-family")
    optparser.add_option("", "--user", help=("poner el usuario de ambos ftp y "
        "http a USUARIO."), action="store", dest="user")
    optparser.add_option("", "--password", help=("poner la contraseña de "
        "ambos ftp y http a CONTRASEÑA."), action="store", dest="password")
    optparser.add_option("", "--ask-password", help=("pedir las contraseñas."),
        action="store_true", dest="ask-password")
    optparser.add_option("", "--no-iri", help=("desactivar soporte IRI."),
        action="store_true", dest="no-iri")
    optparser.add_option("", "--local-encoding", help=("usar ccodificación ENC "
        "como la codificación local para IRIs."), action="store",
        dest="local-encoding")
    optparser.add_option("", "--remote-encoding", help=("usar ENC como la "
        "codificación remota por defecto."), action="store",
        dest="remote-encoding")
    optparser.add_option("", "--unlink", help=("remove file before clobber."),
        action="store_true", dest="unlink")

    "Directorios:"
    optparser.add_option("--no-directories", help=("no crear "
        "directorios."), action="store_true", dest="no-directories")
    optparser.add_option("-x", "--force-directories", help=("forzar la "
        "creación de directorios."), action="store_true",
        dest="force-directories")
    optparser.add_option("--no-host-directories", help=("no crear "
        "directorios del anfitrión."), action="store_true",
        dest="no-host-directories")
    optparser.add_option("", "--protocol-directories", help=("use nombre de "
        "protocolo en los directorios."), action="store_true",
        dest="protocol-directories")
    optparser.add_option("-P", "--directory-prefix", help=("grabar los "
        "ficheros en PREFIX/..."), action="store", dest="directory-prefix")
    optparser.add_option("", "--cut-dirs", help=("ignorar NÚMERO de "
        "componentes de directorio remoto."), action="store", type="int",
        dest="cut-dirs")

    "Opciones HTTP:"
    optparser.add_option("", "--http-user", help=("poner el usuario http a "
        "USUARIO."), action="store", dest="http-user")
    optparser.add_option("", "--http-password", help=("poner la contraseña "
        "http a PASS."), action="store", dest="http-password")
    optparser.add_option("", "--no-cache", help=("no permitir los datos en "    
        "tampón del servidor."), action="store_true", dest="no-cache")
    optparser.add_option("", "--default-page", help=("Cambiar el nombre de "
        "página por defecto (suele ser `index.html'.)."), action="store",
        dest="default-page")
    optparser.add_option("-E", "--adjust-extension", help=("grabe documentos "
        "HTML/CSS con las extensiones correctas."), action="store_true",
        dest="adjust-extension")
    optparser.add_option("", "--ignore-length", help=("ignorar campo "
        "`Content-Length' en cabeceras ."), action="store_true",
        dest="ignore-length")
    optparser.add_option("", "--header", help=("insertar STRING entre las "
        "cabeceras."), action="store", dest="header")
    optparser.add_option("", "--max-redirect", help=("máximo de redirecciones "
        "permitidas por página."), action="store", type="int",
        dest="max-redirect")
    optparser.add_option("", "--proxy-user", help=("poner USUARIO como nombre "
        "de usuario del proxy."), action="store", dest="proxy-user")
    optparser.add_option("", "--proxy-password", help=("poner PASS como "
        "contraseña del proxy."), action="store", dest="proxy-password")
    optparser.add_option("", "--referer", help=("incluir cabecera `Referer: "
        "URL' en petición HTTP."), action="store", dest="referer")
    optparser.add_option("", "--save-headers", help=("grabar las cabeceras "
        "HTTP a fichero."), action="store_true", dest="save-headers")
    optparser.add_option("-U", "--user-agent", help=("identificarse como "
        "AGENTE en vez de Wget/VERSIÓN."), action="store", dest="user-agent")
    optparser.add_option("", "--no-http-keep-alive", help=("desactivar HTTP "
        "keep-alive (conexiones persistentes)."), action="store_true", 
        dest="no-http-keep-alive")
    optparser.add_option("", "--no-cookies", help=("""no usar "cookies"."""),
        action="store_true", dest="no-cookies")
    optparser.add_option("", "--load-cookies", help=('cargar las "cookies"'
        " desde FICHERO antes de la sesión."), action="store",
        dest="load-cookies")
    optparser.add_option("", "--save-cookies", help=("""grabar las "cookies" a"
        "FICHERO después de la sesión."""), action="store", dest="save-cookies")
    optparser.add_option("", "--keep-session-cookies", help=("cargar y "
        'grabar las "cookies" de sesión (no-permanentes).'),
        action="store_true", dest="keep-session-cookies")
    optparser.add_option("", "--post-data", help=("usar el método POST; enviar "
        "STRING como los datos."), action="store", dest="post-data")
    optparser.add_option("", "--post-file", help=("usar el método POST; envía "
        "el contenido de FICHERO."), action="store", dest="post-file")
    optparser.add_option("", "--content-disposition", help=("cumplir con la "
        "cabecera Content-Disposition cuando se elige nombre de ficheros "
        "locales (EXPERIMENTAL)."), action="store_true",
        dest="content-disposition")
    optparser.add_option("", "--auth-no-challenge", help=("enviar información "
        "de autenticicación básica HTTP sin antes esperar al desafío del "
        "servidor."), action="store_true", dest="auth-no-challenge")

    "Opciones HTTPS (SSL/TLS):"
    optparser.add_option("", "--secure-protocol", help=("elegir protocolo "
        "seguro entre auto, SSLv2, SSLv3, y TLSv1."), action="store",
        dest="secure-protocol")
    optparser.add_option("", "--no-check-certificate", help=("no validar el "
        "certificado del servidor."), action="store_true",
        dest="no-check-certificate")
    optparser.add_option("", "--certificate", help=("fichero de certificado "
        "del cliente."), action="store", dest="certificate")
    optparser.add_option("", "--certificate-type", help=("tipo de "
        "certificado de cliente, PEM o DER."), action="store",
        dest="certificate-type")
    optparser.add_option("", "--private-key", help=("fichero de llave "
        "privada."), action="store", dest="private-key")
    optparser.add_option("", "--private-key-type", help=("tipo de llave "
        "privada, PEM o DER."), action="store", dest="private-key-type")
    optparser.add_option("", "--ca-certificate", help=("fichero con la "
        "agrupación de CAs."), action="store", dest="ca-certificate")
    optparser.add_option("", "--ca-directory", help=("directorio donde se "
        """guarda la lista "hash" de CAs."""), action="store",
        dest="ca-directory")
    optparser.add_option("", "--random-file", help=("fichero con datos "
        "aleatorios como semilla de SSL PRNG."), action="store",
        dest="random-file")
    optparser.add_option("", "--egd-file", help=("fichero que denomina el "
        "conector EGD con datos aleatorios."), action="store", dest="egd-file")

    "Opciones FTP:"
    optparser.add_option("", "--ftp-user", help=("poner USUARIO como el "
        "usuario de ftp."), action="store", dest="ftp-user")
    optparser.add_option("", "--ftp-password", help=("poner PASS como "
        "contraseña ftp."), action="store", dest="ftp-password")
    optparser.add_option("", "--no-remove-listing", help=("no eliminar los "
        "ficheros `.listing'."), action="store_true", dest="no-remove-listing")
    optparser.add_option("", "--no-glob" , help=("desactivar generación de "
        "nombres de fichero del FTP (globbing)."), action="store_true",
        dest="no-glob")
    optparser.add_option("", "--no-passive-ftp", help=("desactivar el modo "
        '"pasivo" de transferencia.'), action="store_true",
        dest="no-passive-ftp")
    optparser.add_option("", "--retr-symlinks", help=("en modo recursivo, "
        "bajar los ficheros enlazados (no los directorios)."),
        action="store_true", dest="retr-symlinks")

    "Bajada recursiva:"
    optparser.add_option("-r", "--recursive", help=("especificar descarga "
        "recursiva."), action="store_true", dest="recursive")
    optparser.add_option("-l", "--level", help=("máxima profundidad de "
        "recursión (inf o 0 para infinita)."), action="store", dest="level")
    optparser.add_option("", "--delete-after", help=("borrar los ficheros "
        "localmente después de descargarlos."), action="store_true",
        dest="delete-after")
    optparser.add_option("-k", "--convert-links", help=("hacer que los "
        "enlaces en el HTML o CSS descargado apunte a ficheros locales."),
        action="store_true", dest="convert-links")
    optparser.add_option("-K", "--backup-converted", help=("antes de convertir "
        "el fichero X, salvaguardarlo como X.orig."), action="store_true", 
        dest="backup-converted")
    optparser.add_option("-m", "--mirror", help=("atajo para -N -r -l inf "
        "--no-remove-listing."), action="store_true", dest="mirror")
    optparser.add_option("-p", "--page-requisites", help=("bajar todas las "
        "imágenes, etc. que se necesitan para mostrar la página HTML."),
        action="store_true", dest="page-requisites")
    optparser.add_option("", "--strict-comments", help=("activar manejo "
        "stricto (SGML) de los comentarios en HTML."), action="store_true",
        dest="strict-comments")

    "Aceptar/rechazar recursivamente:"
    optparser.add_option("-A", "--accept", help=("lista separada por comas de "
        "extensiones aceptadas."), action="store", dest="accept")
    optparser.add_option("-R", "--reject", help=("lista separada por comas de "
        "extensiones rechazadas."), action="store", dest="reject")
    optparser.add_option("-D", "--domains", help=("lista separada por comas "
        "de dominios aceptados."), action="store", dest="domains")
    optparser.add_option("", "--exclude-domains", help=("lista separada por "
        "comas de dominios rechazados."), action="store",
        dest="exclude-domains")
    optparser.add_option("", "--follow-ftp", help=("seguir los enlaces a FTP "
        "de los documentos HTML."), action="store_true", dest="follow-ftp")
    optparser.add_option("", "--follow-tags", help=("lista separada por "
        "comas de etiquetas HTML a seguir."), action="store",
        dest="follow-tags")
    optparser.add_option("", "--ignore-tags", help=("lista separada por comas "
        "de etiquetas HTML a ignorar."), action="store", dest="ignore-tags")
    optparser.add_option("-H", "--span-hosts", help=("ir a equipos extraños en "
        "el recorrido recursivo."), action="store_true", dest="span-hosts")
    optparser.add_option("-L", "--relative", help=("sólo seguir enlaces "
        "relativos."), action="store_true", dest="relative")
    optparser.add_option("-I", "--include-directories", help=("lista de "
        "directorios permitidos."), action="store", dest="include-directories")
    optparser.add_option("", "--trust-server-names", help=("use the name "
        "specified by the redirection url last component."),
        action="store_true", dest="trust-server-names")
    optparser.add_option("-X", "--exclude-directories", help=("lista de "
        "directorios excluídos."), action="store", dest="exclude-directories")
    optparser.add_option("--no-parent", help=("no ascender al "
        "directorio padre."), action="store_true", dest="no-parent")

    # Define the default options
    optparser.set_defaults(verbose=0, quiet=0, logfile=LOG_FILE,
        conffile="")

    # Process the options
    options, args = optparser.parse_args()
    return options, args


class Parser:
    def __init__(self):
        pass

def main(options, args):
    "The main routine"
    # Read the config values from the config files
    config = get_config(options.conffile)
    parser = Parser()


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
