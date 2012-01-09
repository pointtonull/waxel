#!/usr/bin/env python
#-*- coding: UTF-8 -*-

from ConfigParser import SafeConfigParser
from argparse import ArgumentParser
from subprocess import call
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
    argparser = ArgumentParser()

    "Inicio:"
    argparser.add_argument( "-V", "--version", help=("muestra la versión de "
        "Wget y sale."), action="store_true", dest="version ")
    argparser.add_argument("-b", "--background", help=("irse a segundo plano"
        "después de empezar."), action="store_true", dest="background")
    argparser.add_argument("-e", "--execute", help=("ejecuta una orden"
        "estilo `.wgetrc'."), action="store", dest="execute")

    "Ficheros de registro y de entrada:"
    argparser.add_argument("-o", "--output-file", help=("registrar mensajes"
        "en FICHERO."), action="store", dest="output-file")
    argparser.add_argument("-a", "--append-output", help=("anexar mensajes a"
        " FILE."), action="store", dest="append-output")
    argparser.add_argument("-d", "--debug", help=("saca montones de información"
        " para depuración."), action="store_true", dest="debug")
    argparser.add_argument("-q", "--quiet", help=("silencioso (sin texto de "
        "salida)."), action="store_true", dest="quiet")
    argparser.add_argument("-v", "--verbose", help=("sé verboso (es el método "
        "por defecto)."), action="store_true", dest="verbose")
    argparser.add_argument("--no-verbose", help=("desactiva modo verboso, "
        "sin ser silencioso."), action="store_true", dest="no-verbose")
    argparser.add_argument("-i", "--input-file", help=("descarga URLs "
        "encontradas en fichero (FILE) local o externo."), action="store",
        dest="input-file")
    argparser.add_argument("-F", "--force-html", help=("trata el fichero de "
        "entrada como HTML."), action="store_true", dest="force-html")
    argparser.add_argument("-B", "--base", help=("resuelve enlaces HTML del "
        "fichero-de-entrada (-i -F) relativos a la URL."), action="store",
        dest="base")
    argparser.add_argument("--config" , help=("Specify config file to use."),
        action="store_true", dest="config")

    "Descarga:"
    argparser.add_argument("-t", "--tries", help=("define número de intentos a "
        "NÚMERO (0 es sin limite)."), action="store", type=int, dest="tries")
    argparser.add_argument("--retry-connrefused", help=("reintente incluso si"
        " la conexión es rechazada."), action="store_true",
        dest="retry-connrefused")
    argparser.add_argument("-O", "--output-document", help=("escriba documentos"
        " al fichero FILE."), action="store", dest="output-document")
    argparser.add_argument("--no-clobber", help=("skip downloads that "
        "would download to existing files (overwriting them)."),
        action="store_true", dest="no-clobber")
    argparser.add_argument("-c", "--continue", help=("continuar una descarga "
        "parcial de un fichero."), action="store_true", dest="continue")
    argparser.add_argument("--progress", help=("seleccione tipo de indicador "
        "de progreso."), action="store", dest="progress")
    argparser.add_argument("-N", "--timestamping", help=("no re-recuperar "
        "ficheros a menos que sean más nuevos que la versión local."),
        action="store_true", dest="timestamping")
    argparser.add_argument("--no-use-server-timestamps", help=("no poner la "
        "hora/fecha del fichero local a la que tenga el del servidor."), 
        action="store_true", dest="no-use-server-timestamps")
    argparser.add_argument("-S", "--server-response", help=("mostrar la "
        "respuesta del servidor."), action="store_true", dest="server-response")
    argparser.add_argument("--spider", help=("(araña) no descargar nada."),
        action="store_true", dest="spider")
    argparser.add_argument("-T", "--timeout", help=("poner todos los valores de"
        " temporización a SEGUNDOS."), action="store", type=int, 
        dest="timeout")
    argparser.add_argument("--dns-timeout", help=("definir la temporización "
        "de la búsqueda DNS a SEGS."), action="store", type=int,
        dest="dns-timeout")
    argparser.add_argument("--connect-timeout", help=("definir la "
        "temporización de conexión a SEGS."), action="store", type=int,
        dest="connect-timeout")
    argparser.add_argument("--read-timeout", help=("definir la temporización"
        " de lectura a SEGS."), action="store", type=int, dest="read-timeout")
    argparser.add_argument("-w", "--wait", help=("espera tantos SEGUNDOS entre "
        "reintentos."), action="store", type=int, dest="wait")
    argparser.add_argument("--waitretry", help=("espera 1..SEGUNDOS entre "
        "reintentos de una descarga."), action="store", type=int,
        dest="waitretry")
    argparser.add_argument("--random-wait", help=("espera entre 0.5*WAIT...1"
        ".5*WAIT segs. entre descargas."), action="store_true",
        dest="random-wait")
    argparser.add_argument("--no-proxy", help=("explícitamente desconecta el "
        "proxy."), action="store_true", dest="no-proxy")
    argparser.add_argument("-Q", "--quota", help=("define la cuota de descarga "
        "a NÚMERO."), action="store", type=int, dest="quota")
    argparser.add_argument("--bind-address", help=("bind a DIRECCIÓN "
        "(nombredeequipo o IP) en equipo local."), action="store",
        dest="bind-address")
    argparser.add_argument("--limit-rate", help=("limita velocidad de "
        "descarga a VELOCIDAD."), action="store", dest="limit-rate")
    argparser.add_argument("--no-dns-cache", help=("desactiva búsquedas en "
        "tampón DNS."), action="store_true", dest="no-dns-cache")
    argparser.add_argument("--restrict-file-names", help=("restringe "
        "caracteres en nombres de ficheros a los que el SO permita."),
        action="store_true", dest="restrict-file-names")
    argparser.add_argument("--ignore-case", help=("ignorar mayús/minúsculas "
        "al encajar ficheros/directorios."), action="store_true",
        dest="ignore-case")
    argparser.add_argument("-4", "--inet4-only", help=("conectar sólo a "
        "direcciones IPv4."), action="store_true", dest="inet4-only")
    argparser.add_argument("-6", "--inet6-only", help=("conectar sólo a "
        "direcciones IPv6."), action="store_true", dest="inet6-only")
    argparser.add_argument("--prefer-family", help=("conectar primero a "
        "direcciones de la familia especificada, bien IPv6, IPv4, o ninguna."),
        action="store", dest="prefer-family")
    argparser.add_argument("--user", help=("poner el usuario de ambos ftp y "
        "http a USUARIO."), action="store", dest="user")
    argparser.add_argument("--password", help=("poner la contraseña de "
        "ambos ftp y http a CONTRASEÑA."), action="store", dest="password")
    argparser.add_argument("--ask-password", help=("pedir las contraseñas."),
        action="store_true", dest="ask-password")
    argparser.add_argument("--no-iri", help=("desactivar soporte IRI."),
        action="store_true", dest="no-iri")
    argparser.add_argument("--local-encoding", help=("usar ccodificación ENC "
        "como la codificación local para IRIs."), action="store",
        dest="local-encoding")
    argparser.add_argument("--remote-encoding", help=("usar ENC como la "
        "codificación remota por defecto."), action="store",
        dest="remote-encoding")
    argparser.add_argument("--unlink", help=("remove file before clobber."),
        action="store_true", dest="unlink")

    "Directorios:"
    argparser.add_argument("--no-directories", help=("no crear "
        "directorios."), action="store_true", dest="no-directories")
    argparser.add_argument("-x", "--force-directories", help=("forzar la "
        "creación de directorios."), action="store_true",
        dest="force-directories")
    argparser.add_argument("--no-host-directories", help=("no crear "
        "directorios del anfitrión."), action="store_true",
        dest="no-host-directories")
    argparser.add_argument("--protocol-directories", help=("use nombre de "
        "protocolo en los directorios."), action="store_true",
        dest="protocol-directories")
    argparser.add_argument("-P", "--directory-prefix", help=("grabar los "
        "ficheros en PREFIX/..."), action="store", dest="directory-prefix")
    argparser.add_argument("--cut-dirs", help=("ignorar NÚMERO de "
        "componentes de directorio remoto."), action="store", type=int,
        dest="cut-dirs")

    "Opciones HTTP:"
    argparser.add_argument("--http-user", help=("poner el usuario http a "
        "USUARIO."), action="store", dest="http-user")
    argparser.add_argument("--http-password", help=("poner la contraseña "
        "http a PASS."), action="store", dest="http-password")
    argparser.add_argument("--no-cache", help=("no permitir los datos en "    
        "tampón del servidor."), action="store_true", dest="no-cache")
    argparser.add_argument("--default-page", help=("Cambiar el nombre de "
        "página por defecto (suele ser `index.html'.)."), action="store",
        dest="default-page")
    argparser.add_argument("-E", "--adjust-extension", help=("grabe documentos "
        "HTML/CSS con las extensiones correctas."), action="store_true",
        dest="adjust-extension")
    argparser.add_argument("--ignore-length", help=("ignorar campo "
        "`Content-Length' en cabeceras ."), action="store_true",
        dest="ignore-length")
    argparser.add_argument("--header", help=("insertar STRING entre las "
        "cabeceras."), action="append", dest="header")
    argparser.add_argument("--max-redirect", help=("máximo de redirecciones "
        "permitidas por página."), action="store", type=int,
        dest="max-redirect")
    argparser.add_argument("--proxy-user", help=("poner USUARIO como nombre "
        "de usuario del proxy."), action="store", dest="proxy-user")
    argparser.add_argument("--proxy-password", help=("poner PASS como "
        "contraseña del proxy."), action="store", dest="proxy-password")
    argparser.add_argument("--referer", help=("incluir cabecera `Referer: "
        "URL' en petición HTTP."), action="store", dest="referer")
    argparser.add_argument("--save-headers", help=("grabar las cabeceras "
        "HTTP a fichero."), action="store_true", dest="save-headers")
    argparser.add_argument("-U", "--user-agent", help=("identificarse como "
        "AGENTE en vez de Wget/VERSIÓN."), action="store", dest="user-agent")
    argparser.add_argument("--no-http-keep-alive", help=("desactivar HTTP "
        "keep-alive (conexiones persistentes)."), action="store_true", 
        dest="no-http-keep-alive")
    argparser.add_argument("--no-cookies", help=("""no usar "cookies"."""),
        action="store_true", dest="no-cookies")
    argparser.add_argument("--load-cookies", help=('cargar las "cookies"'
        " desde FICHERO antes de la sesión."), action="store",
        dest="load-cookies")
    argparser.add_argument("--save-cookies", help=("""grabar las "cookies" a"
        "FICHERO después de la sesión."""), action="store", dest="save-cookies")
    argparser.add_argument("--keep-session-cookies", help=("cargar y "
        'grabar las "cookies" de sesión (no-permanentes).'),
        action="store_true", dest="keep-session-cookies")
    argparser.add_argument("--post-data", help=("usar el método POST; enviar "
        "STRING como los datos."), action="store", dest="post-data")
    argparser.add_argument("--post-file", help=("usar el método POST; envía "
        "el contenido de FICHERO."), action="store", dest="post-file")
    argparser.add_argument("--content-disposition", help=("cumplir con la "
        "cabecera Content-Disposition cuando se elige nombre de ficheros "
        "locales (EXPERIMENTAL)."), action="store_true",
        dest="content-disposition")
    argparser.add_argument("--auth-no-challenge", help=("enviar información "
        "de autenticicación básica HTTP sin antes esperar al desafío del "
        "servidor."), action="store_true", dest="auth-no-challenge")

    "Opciones HTTPS (SSL/TLS):"
    argparser.add_argument("--secure-protocol", help=("elegir protocolo "
        "seguro entre auto, SSLv2, SSLv3, y TLSv1."), action="store",
        dest="secure-protocol")
    argparser.add_argument("--no-check-certificate", help=("no validar el "
        "certificado del servidor."), action="store_true",
        dest="no-check-certificate")
    argparser.add_argument("--certificate", help=("fichero de certificado "
        "del cliente."), action="store", dest="certificate")
    argparser.add_argument("--certificate-type", help=("tipo de "
        "certificado de cliente, PEM o DER."), action="store",
        dest="certificate-type")
    argparser.add_argument("--private-key", help=("fichero de llave "
        "privada."), action="store", dest="private-key")
    argparser.add_argument("--private-key-type", help=("tipo de llave "
        "privada, PEM o DER."), action="store", dest="private-key-type")
    argparser.add_argument("--ca-certificate", help=("fichero con la "
        "agrupación de CAs."), action="store", dest="ca-certificate")
    argparser.add_argument("--ca-directory", help=("directorio donde se "
        """guarda la lista "hash" de CAs."""), action="store",
        dest="ca-directory")
    argparser.add_argument("--random-file", help=("fichero con datos "
        "aleatorios como semilla de SSL PRNG."), action="store",
        dest="random-file")
    argparser.add_argument("--egd-file", help=("fichero que denomina el "
        "conector EGD con datos aleatorios."), action="store", dest="egd-file")

    "Opciones FTP:"
    argparser.add_argument("--ftp-user", help=("poner USUARIO como el "
        "usuario de ftp."), action="store", dest="ftp-user")
    argparser.add_argument("--ftp-password", help=("poner PASS como "
        "contraseña ftp."), action="store", dest="ftp-password")
    argparser.add_argument("--no-remove-listing", help=("no eliminar los "
        "ficheros `.listing'."), action="store_true", dest="no-remove-listing")
    argparser.add_argument("--no-glob" , help=("desactivar generación de "
        "nombres de fichero del FTP (globbing)."), action="store_true",
        dest="no-glob")
    argparser.add_argument("--no-passive-ftp", help=("desactivar el modo "
        '"pasivo" de transferencia.'), action="store_true",
        dest="no-passive-ftp")
    argparser.add_argument("--retr-symlinks", help=("en modo recursivo, "
        "bajar los ficheros enlazados (no los directorios)."),
        action="store_true", dest="retr-symlinks")

    "Bajada recursiva:"
    argparser.add_argument("-r", "--recursive", help=("especificar descarga "
        "recursiva."), action="store_true", dest="recursive")
    argparser.add_argument("-l", "--level", help=("máxima profundidad de "
        "recursión (inf o 0 para infinita)."), action="store", dest="level")
    argparser.add_argument("--delete-after", help=("borrar los ficheros "
        "localmente después de descargarlos."), action="store_true",
        dest="delete-after")
    argparser.add_argument("-k", "--convert-links", help=("hacer que los "
        "enlaces en el HTML o CSS descargado apunte a ficheros locales."),
        action="store_true", dest="convert-links")
    argparser.add_argument("-K", "--backup-converted", help=("antes de "
        "convertir el fichero X, salvaguardarlo como X.orig."),
        action="store_true", dest="backup-converted")
    argparser.add_argument("-m", "--mirror", help=("atajo para -N -r -l inf "
        "--no-remove-listing."), action="store_true", dest="mirror")
    argparser.add_argument("-p", "--page-requisites", help=("bajar todas las "
        "imágenes, etc. que se necesitan para mostrar la página HTML."),
        action="store_true", dest="page-requisites")
    argparser.add_argument("--strict-comments", help=("activar manejo "
        "stricto (SGML) de los comentarios en HTML."), action="store_true",
        dest="strict-comments")

    "Aceptar/rechazar recursivamente:"
    argparser.add_argument("-A", "--accept", help=("lista separada por comas de"
        " extensiones aceptadas."), action="store", dest="accept")
    argparser.add_argument("-R", "--reject", help=("lista separada por comas de"
        " extensiones rechazadas."), action="store", dest="reject")
    argparser.add_argument("-D", "--domains", help=("lista separada por comas "
        "de dominios aceptados."), action="store", dest="domains")
    argparser.add_argument("--exclude-domains", help=("lista separada por "
        "comas de dominios rechazados."), action="store",
        dest="exclude-domains")
    argparser.add_argument("--follow-ftp", help=("seguir los enlaces a FTP "
        "de los documentos HTML."), action="store_true", dest="follow-ftp")
    argparser.add_argument("--follow-tags", help=("lista separada por "
        "comas de etiquetas HTML a seguir."), action="store",
        dest="follow-tags")
    argparser.add_argument("--ignore-tags", help=("lista separada por comas "
        "de etiquetas HTML a ignorar."), action="store", dest="ignore-tags")
    argparser.add_argument("-H", "--span-hosts", help=("ir a equipos extraños "
        "en el recorrido recursivo."), action="store_true", dest="span-hosts")
    argparser.add_argument("-L", "--relative", help=("sólo seguir enlaces "
        "relativos."), action="store_true", dest="relative")
    argparser.add_argument("-I", "--include-directories", help=("lista de "
        "directorios permitidos."), action="store", dest="include-directories")
    argparser.add_argument("--trust-server-names", help=("use the name "
        "specified by the redirection url last component."),
        action="store_true", dest="trust-server-names")
    argparser.add_argument("-X", "--exclude-directories", help=("lista de "
        "directorios excluídos."), action="store", dest="exclude-directories")
    argparser.add_argument("--no-parent", help=("no ascender al "
        "directorio padre."), action="store_true", dest="no-parent")
    
    argparser.add_argument("URL", help=("la dirección a descargar"),
        nargs='*')

    # Define the default options
    argparser.set_defaults(verbose=0, quiet=0, logfile=LOG_FILE,
        conffile="")

    # Process the options
    options = argparser.parse_args()
    return options


def get_paths(command):
    """
    return a list of the abspath to executables of <command> except this file
    """
    my_path = os.path.realpath(__file__)
    paths = (os.path.realpath(os.path.join(path, command))
        for path in os.environ["PATH"].split(":")
            if os.path.exists(os.path.join(path, command)))
    paths = [path for path in paths if path != my_path]
    return paths


def write(text, destination):
    """
    Shortcut to append text to destination and flush that
    """
    DEBUG("""write::writing "%s" to %s""" % (text, destination))
    fileo = open(destination, "a")
    fileo.write("%s\n" % text.encode("UTF-8", "replace"))
    fileo.close()


class Parser:
    def __init__(self, options):
        self.options = options

    def get_cmd(self):
        return [""]

    def run_cmd(self):
        error = call(self.get_cmd())
        return error


class Axel(Parser):
    def __init__(self, options):
        Parser.__init__(self, options)
     
        self.waxel_args = []
        for option, value in vars(self.options).iteritems():
            DEBUG("OPTION: %s, %s" % (option, value))
            if value not in (None, False):
                self.parse_option(option, value)        

    def parse_option(self, option, value):
        rules = {
            }
        if option in rules:
            rules[option](value)
        else:
            LOG("Axel: parse_option: Error: no implementado %s %s" % (option,
                value))
            raise NotImplementedError(option)

    def get_cmd(self):
        executable = get_paths("axel")[0]
        cmd = [executable] + self.axel_args
        return cmd


class Wget(Parser):
    def get_cmd(self):
        executable = get_paths("wget")[0]
        cmd = [executable] + sys.argv[1:]
        return cmd


def main(options):
    "The main routine"
    # Read the config values from the config files
    config = get_config(options.conffile)
    try:
        error = Axel(options).run_cmd()
    except NotImplementedError:
        error = Wget(options).run_cmd()
    return error



if __name__ == "__main__":
    # == Reading the options of the execution ==
    options = get_options()

    VERBOSE = (options.quiet - options.verbose) * 10 + 30
    format_str = "%(message)s"
    logging.basicConfig(format=format_str, level=VERBOSE)
    logger = logging.getLogger()

    DEBUG = ident(logger.debug) # For developers
    MOREINFO = ident(logger.info) # Plus info
    INFO = ident(logger.warning) # Default
    WARNING = ident(logger.error) # Non critical errors
    ERROR = ident(logger.critical) # Critical (will break)
    LOG = lambda string: write(string, LOG_FILE)

    DEBUG("get_options::options: %s" % options)

    DEBUG("Verbose level: %s" % VERBOSE)
    exit(main(options))
