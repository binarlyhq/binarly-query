#!/usr/bin/env python
import os
import sys
import json
import datetime
import argparse
import glob


try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

try:
    from colorama import init, Fore, Style
except ImportError:
    print(
        "Error importing colorama. Please make sure you have it (pip install colorama)"
    )
    sys.exit(-1)

try:
    from BinarlyAPIv1 import BinarlyAPI, hex_pattern, ascii_pattern, wide_pattern
except ImportError:
    print(
        "Error importing BinarlyAPI. You can find it here https://github.com/binarlyhq/binarly-sdk"
    )
    sys.exit(-1)

BINOBJ = None
APIKEYFILENAME = 'apikey.txt'
APIKEYPATH = os.path.join(os.path.dirname(__file__), APIKEYFILENAME)

APIKEY = ''

ARGPARSER = argparse.ArgumentParser(
    description='Binarly API Query', fromfile_prefix_chars="@")
ARGPARSER.add_argument("--key", "-k", help="Binarly APIKey", default='')
ARGPARSER.add_argument(
    "--server", "-s", help="Set Binarly API endpoint", default='www.binar.ly')

ARGPARSER.add_argument(
    "--usehttp",
    "-u",
    help="Use HTTP instead of HTTPS when communicating. By default HTTPS is used.",
    action="store_true")

ARGPARSER.add_argument(
    "--pretty-print",
    "-p",
    help="Display results in a nicely formated table (Requires tabulate python module)",
    action="store_true"
)

ARG_SUBPARSERS = ARGPARSER.add_subparsers(help='commands', dest='commands')

SEARCH_PARSER = ARG_SUBPARSERS.add_parser(
    'search', help="Search arbitrary hex patterns")
SEARCH_PARSER.add_argument("hex", type=str, nargs='*', default=[])
SEARCH_PARSER.add_argument(
    "-a", type=str, nargs='*', help="ASCII string to search", default=[])
SEARCH_PARSER.add_argument(
    "-w", type=str, nargs='*', help="WIDE string to search", default=[])
SEARCH_PARSER.add_argument(
    "--limit",
    type=int,
    default=20,
    help="Limit the number of results returned. If 0 only statistics are returned")
SEARCH_PARSER.add_argument(
    "--exact", action='store_true', help="Validate search results")

HUNT_PARSER = ARG_SUBPARSERS.add_parser(
    'hunt', help='Hunt for files using YARA rules')
HUNT_PARSER.add_argument('yarafile', type=str)

SIGN_PARSER = ARG_SUBPARSERS.add_parser('sign', help="Generate IOC on samples")
SIGN_PARSER.add_argument(
    "files",
    type=str,
    nargs='+',
    help="Files/Hashes (md5/sha1/sha256) to send to signer")

SIGN_PARSER.add_argument(
    "--patternCount",
    "-c",
    type=int,
    default=3,
    help="Specify the number of fragments in a generated rule",
    dest='fragcount')
SIGN_PARSER.add_argument(
    "--strategy",
    "-s",
    type=str,
    choices=['none', 'strict'],
    help="Specify if the signature should be extracted from full file (none) or a subset (strict)",
    default='none')
SIGN_PARSER.add_argument(
    "--cluster",
    help="Treat files as a cluster in order to minimize the number of generated signatures",
    action='store_true')
SIGN_PARSER.add_argument(
    "--other",
    nargs='*',
    help="Specify additional options to send, in the form of a tuple (key, value)",
    default=[],
    action='store')

SIGN_PARSER.add_argument(
    "--u", type=bool, help='Upload file(s) if missing', default=True)
SIGN_PARSER.add_argument(
    "--yara",
    help='Dump generated YARA signatures to screen',
    default=False,
    action="store_true")

CLASSIFY_PARSER = ARG_SUBPARSERS.add_parser(
    'classify', help="Classify samples using Machine Learning")
CLASSIFY_PARSER.add_argument("files", type=str, nargs='+')
CLASSIFY_PARSER.add_argument(
    "-u", type=bool, help='Upload file(s) if missing', default=True)

FILEINFO_PARSER = ARG_SUBPARSERS.add_parser(
    'metadata', help="Retrieve file metadata")
FILEINFO_PARSER.add_argument(
    "filehash",
    type=str,
    help="File hash (md5/sha1/sha256) to retrieve metadata")

USAGE_PARSER = ARG_SUBPARSERS.add_parser('demo', help="Show usage examples")

LABEL_COLOR = {
    'clean': Style.BRIGHT + Fore.GREEN,
    'malware': Style.BRIGHT + Fore.RED,
    'pua': Style.BRIGHT + Fore.YELLOW,
    'unknown': Style.BRIGHT + Fore.CYAN,
    'suspicious': Style.BRIGHT + Fore.MAGENTA
}


def dump(obj, nested_level=0, output=sys.stdout):
    spacing = '   '
    if isinstance(obj, dict):
        print >> output, '%s{' % ((nested_level) * spacing)
        for key, value in obj.items():
            if hasattr(value, '__iter__'):
                print >> output, '%s%s:' % ((nested_level + 1) * spacing, key)
                dump(value, nested_level + 1, output)
            else:
                print >> output, '%s%s: %s' % ((nested_level + 1) * spacing,
                                               key, value)
        print >> output, '%s}' % (nested_level * spacing)
    elif isinstance(obj, list):
        print >> output, '%s[' % (nested_level * spacing)
        for value in obj:
            if hasattr(value, '__iter__'):
                dump(value, nested_level + 1, output)
            else:
                print >> output, '%s%s' % ((nested_level + 1) * spacing, value)
        print >> output, '%s]' % ((nested_level) * spacing)
    else:
        print >> output, '%s%s' % (nested_level * spacing, obj)


def smart_size(size):
    if not isinstance(size, int):
        try:
            size = int(size)
        except:
            return size

    if size >= 1024 * 1024 * 1024:
        return "{0:.2f}GB".format(float(size) / (1024 * 1024 * 1024))
    elif size >= 1024 * 1024:
        return "{0:.2f}MB".format(float(size) / (1024 * 1024))
    elif size > 1024:
        return "{0:.2f}KB".format(float(size) / 1024)
    else:
        return "{0}B".format(size)


def get_filelist(dirname):
    return [x for x in glob.glob(os.path.join(dirname, '*'))
            if os.path.isfile(x)]


def color_row(row):
    color = Fore.WHITE
    label = "."
    if u'label' in row:
        color = LABEL_COLOR.get(row[u'label'], Fore.WHITE)
        label = row[u'label']
        row[u'label'] = "%s%s%s"%(color, label, Style.RESET_ALL)

    row['family'] = "%s%s%s"%(color, row.get('family', "."), Style.RESET_ALL)
    row['size'] = smart_size(row.get(u'size', "."))
    return row

def show_row(row):
    row = color_row(row)
    print " ".join(["%s%s%s:%s"%(Style.NORMAL, x.capitalize(), Style.BRIGHT, y) for (x, y) in row.items()])


def show_results(results, pretty_print):
    if pretty_print:
        [color_row(x) for x in results]
        print tabulate(results, headers="keys", tablefmt="grid", stralign="right")
    else:
        print("-" * 100)
        for val in results:
            show_row(val)


def show_stats(stats):
    print(
        "Found {0} results : {1}{2} clean {3}{4} malware {5}{6} PUA {7}{8} unknown {9}{10} suspicious".
        format(stats['total_count'], LABEL_COLOR['clean'],
               stats['clean_count'], LABEL_COLOR['malware'],
               stats['malware_count'], LABEL_COLOR['pua'], stats['pua_count'],
               LABEL_COLOR['unknown'], stats['unknown_count'],
               LABEL_COLOR['suspicious'], stats['suspicious_count']))


def process_search(options):
    search_query = []
    for val in options.hex:
        search_query.append(hex_pattern(val.replace(' ', '')))
    for val in options.a:
        search_query.append(ascii_pattern(val))
    for val in options.w:
        search_query.append(wide_pattern(val))

    result = BINOBJ.search(
        search_query, limit=options.limit, exact=options.exact)
    if 'error' in result:
        print(Style.BRIGHT + Fore.RED + result['error']['message'])
        return

    if 'stats' in result:
        show_stats(result['stats'])

    if len(result['results']) == 0:
        return
    
    print("Showing top {0} results:".format(options.limit))
    show_results(result['results'], pretty_print=options.pretty_print)


def process_classify(options):
    if os.path.exists(options.files[0]):
        filelist = options.files
        if os.path.isdir(options.files[0]):
            filelist = get_filelist(filelist[0])

        result = BINOBJ.classify_files(
            filelist, upload_missing=options.u, status_callback=my_callback)
    else:
        result = BINOBJ.classify_hashes(options.files)

    if 'error' in result or result['status'] != 'done':
        print(Style.BRIGHT + Fore.RED + "Request failed")
    else:
        print("Classification Results:")

    reqid = result.get('results', None)
    if reqid is None:
        # the request failed before any files could be analyzed
        print(Style.BRIGHT + Fore.RED +
              "Fail reason: {0} (error code={1})".format(
                  result['error']['message'], result['error']['code']))
        return
    
    classify_data = []
    for key, value in result['results'].iteritems():
        status = Style.RESET_ALL + Fore.GREEN + "OK" + Style.RESET_ALL
        if 'error' in value:
            status = Fore.RED + value['error']['message'] + Style.RESET_ALL
        row = {'SHA1':key, 'label': value.get('label', '.'), 'family': value.get('family', '.'), 'Status':status}
        
        classify_data.append(row)

    if options.pretty_print:
        show_results(classify_data, pretty_print=options.pretty_print)
    else:
        print("-" * 100)
        for row in classify_data:
            show_row(row)
    return


def process_hunt(options):
    result = BINOBJ.yara_hunt(options.yarafile, my_callback)
    if 'error' in result or result['status'] != 'done':
        print(Style.BRIGHT + Fore.RED + "Request failed.")
        print(Style.BRIGHT + Fore.RED +
              "Fail reason: {0} (error code={1})".format(
                  result['error']['message'], result['error']['code']))
        return

    if 'stats' in result:
        show_stats(result['stats'])
    
    if len(result['results']) > 0:
        show_results(result['results'], pretty_print=options.pretty_print)


def my_callback(response):
    print("{0} : Request status = {1:<10}".format(
        datetime.datetime.now(), response.get('status', None)))


def process_sign(options):
    sign_options = {'strategy': options.strategy,
                    'frag_count': options.fragcount,
                    'cluster': options.cluster}

    if os.path.exists(options.files[0]):
        filelist = options.files
        if os.path.isdir(options.files[0]):
            filelist = get_filelist(filelist[0])

        result = BINOBJ.gen_ioc_files(
            filelist,
            options=sign_options,
            upload_missing=options.u,
            status_callback=my_callback)
    else:
        result = BINOBJ.gen_ioc_hashes(
            options.files, status_callback=my_callback)

    if 'error' in result or result['status'] != 'done':
        print(Style.BRIGHT + Fore.RED + "Request failed.")
    else:
        print("Generated {0} signature(s) in {1:d}s".format(
            len(result.get('signatures', [])),
            result['stats']['time_ms'] / 1000))

    reqid = result.get('reqid', None)
    if reqid is None:
        # the request failed before any files could be analyzed
        print(Style.BRIGHT + Fore.RED +
              "Fail reason: {0} (error code={1})".format(
                  result['error']['message'], result['error']['code']))
        return

    yara_signatures = []
    for idx, signature in enumerate(result.get('signatures', [])):
        sig_info = BINOBJ.get_request(signature['info'])
        with open("auto_{0}_{1}.json".format(reqid, idx), mode="w") as sigfile:
            sigfile.write(json.dumps(sig_info))

        yarasig = BINOBJ.get_request(signature['yarasig'])
        yara_signatures.append(yarasig)

        with open("auto_{0}.yar".format(reqid), mode="a") as sigfile:
            sigfile.write(yarasig)

        print(
            "Sig #{0} - detects {1} indexed files from family: {2}{3}".format(
                idx, len(sig_info.get('samples', [])),
                LABEL_COLOR[sig_info.get('label', "malware")],
                sig_info.get('family', "N/A")))

    print("Signing results:")
    for filehash, info in result['results'].iteritems():
        status = Fore.GREEN + 'Signed'
        if info['status'] != 'signed':
            status = Fore.RED + "Failed ({0})".format(info['error']['message'])

        print("Hash:{0}{1}{2} Status:{3}".format(Style.BRIGHT, filehash,
                                                 Style.RESET_ALL, status))

    if len(yara_signatures) > 0:
        print("\nPlease check {0} file for generated signature(s).".format(
            "auto_{0}.yar".format(reqid)))

    if options.yara:
        print "YARA Rules:"
        for rule in yara_signatures:
            print rule
    return


def process_metadata(options):
    result = BINOBJ.get_metadata(options.filehash)
    if 'error' in result:
        print(Style.BRIGHT + Fore.RED + result['error']['message'])
        return

    dump(result[options.filehash])


def process_demo(options):
    return


def read_apikey(filepath=APIKEYPATH):
    global APIKEY

    if not os.path.exists(filepath):
        return False

    with open(filepath, 'r') as fhandle:
        APIKEY = fhandle.readline()

    APIKEY = APIKEY.strip()
    return True


def init_api(options):
    global BINOBJ, APIKEY

    APIKEY = options.key
    if len(APIKEY) == 0 and read_apikey() is False:
        raise RuntimeError(
            "You need to provide an API access key. Register at https://binar.ly in order to receive one")

    BINOBJ = BinarlyAPI(
        server=options.server,
        api_key=APIKEY,
        use_http=options.usehttp,
        project="BinarlyPyQuery")
    return


def main(options):
    if options.pretty_print and not HAS_TABULATE:
        print Style.BRIGHT + Fore.RED + "Pretty printing requires tabulate python module. (pip install tabulate)"
        return
    
    init_api(options)
    cmd = options.commands
    if cmd == 'search':
        return process_search(options)
    elif cmd == 'hunt':
        return process_hunt(options)
    elif cmd == 'sign':
        return process_sign(options)
    elif cmd == 'classify':
        return process_classify(options)
    elif cmd == 'metadata':
        return process_metadata(options)
    elif cmd == 'demo':
        return process_demo(options)
    else:
        print("Unknown command {0}".format(cmd))


if __name__ == "__main__":
    init(autoreset=True)
    main(ARGPARSER.parse_args())
