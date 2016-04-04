import os
import sys
import json
import datetime
import argparse
import glob
try:
    from colorama import init, Fore, Back, Style
except ImportError:
    print("Error importing colorama. Please make sure you have it (pip install colorama)")
    sys.exit(-1)

try:
    from BinarlyAPIv1 import BinarlyAPI, hex_pattern, ascii_pattern, wide_pattern, build_query
except ImportError:
    print("Error importing BinarlyAPI. You can find it here https://github.com/binarlyhq/binarly-sdk")
    sys.exit(-1)

BINOBJ = None
APIKEYFILENAME = 'apikey.txt'
APIKEYPATH     = os.path.join(os.path.dirname(__file__), APIKEYFILENAME)

APIKEY = ''

parser = argparse.ArgumentParser(description='Binarly API Query')
parser.add_argument("--key", "-k", help="Binarly APIKey", default='')
parser.add_argument("--usehttp", "-u", help="Use HTTP instead of HTTPS when communicating. By default HTTPS is used.", action="store_true")
subparsers = parser.add_subparsers(help='commands', dest='commands')

search = subparsers.add_parser('search', help="Search arbitrary hex patterns")
search.add_argument("hex", type=str, nargs='*', default=[])
search.add_argument("-a", type=str, nargs='*', help="ASCII string to search", default=[])
search.add_argument("-w", type=str, nargs='*', help="WIDE string to search", default=[])
search.add_argument("--limit", type=int, default=20, help="Limit the number of results returned. If 0 only statistics are returned")
search.add_argument("--exact", action='store_true', help="Validate search results")

hunt = subparsers.add_parser('hunt', help='Hunt for files using YARA rules')
hunt.add_argument('yarafile', type=str)

sign = subparsers.add_parser('sign', help="Generate IOC on samples")
sign.add_argument("files", type=str, nargs='+', help="Files/Hashes (md5/sha1/sha256) to send to signer")
sign.add_argument("--patternCount", "-c", type=int, default=3, help="Specify the number of fragments in a generated rule", dest='fragcount')
sign.add_argument("--strategy", "-s", type=str, choices=['none','strict'], help="Specify if the signature should be extracted from full file (none) or a subset (strict)", default='none')
sign.add_argument("--cluster", help="Treat files as a cluster in order to minimize the number of generated signatures", action='store_true')
sign.add_argument("--other", nargs='*', help="Specify additional options to send, in the form of a tuple (key, value)", default=[], action='store')

sign.add_argument("--u", type=bool, help='Upload file(s) if missing', default=True)
sign.add_argument("--yara", help='Dump generated YARA signatures to screen', default=False, action="store_true")

classify = subparsers.add_parser('classify', help="Classify samples using Machine Learning")
classify.add_argument("files", type=str, nargs='+')
classify.add_argument("-u", type=bool, help='Upload file(s) if missing', default=True)

fileinfo = subparsers.add_parser('metadata', help="Retrieve file metadata")
fileinfo.add_argument("filehash", type=str, help="File hash (md5/sha1/sha256) to retrieve metadata")

usage = subparsers.add_parser('demo', help="Show usage examples")

LABEL_COLOR = {
    'clean':Style.BRIGHT + Fore.GREEN,
    'malware':Style.BRIGHT + Fore.RED,
    'pua':Style.BRIGHT + Fore.YELLOW,
    'unknown':Style.BRIGHT + Fore.CYAN,
    'suspicious':Style.BRIGHT + Fore.MAGENTA
}

def dump(obj, nested_level=0, output=sys.stdout):
    spacing = '   '
    if isinstance(obj,dict):
        print >> output, '%s{' % ((nested_level) * spacing)
        for k, v in obj.items():
            if hasattr(v, '__iter__'):
                print >> output, '%s%s:' % ((nested_level + 1) * spacing, k)
                dump(v, nested_level + 1, output)
            else:
                print >> output, '%s%s: %s' % ((nested_level + 1) * spacing, k, v)
        print >> output, '%s}' % (nested_level * spacing)
    elif isinstance(obj,list):
        print >> output, '%s[' % ((nested_level) * spacing)
        for v in obj:
            if hasattr(v, '__iter__'):
                dump(v, nested_level + 1, output)
            else:
                print >> output, '%s%s' % ((nested_level + 1) * spacing, v)
        print >> output, '%s]' % ((nested_level) * spacing)
    else:
        print >> output, '%s%s' % (nested_level * spacing, obj)

def smart_size(size):
    if not isinstance(size,int):
        return size

    if size >= 1024*1024*1024:
        return "{0:.2f} GB".format(float(size)/(1024*1024*1024))
    elif size >= 1024*1024:
        return "{0:.2f}MB".format(float(size)/(1024*1024))
    elif size > 1024:
        return "{0:.2f} KB".format(float(size)/1024)
    else:
        return "{0:B}".format(size)

def get_filelist(dirname):
    return [x for x in glob.glob(os.path.join(dirname, '*')) if os.path.isfile(x)]

def show_row(val):
    color = Fore.WHITE
    label = None
    if val.has_key(u'label'):
        color = LABEL_COLOR.get(val['label'], Fore.WHITE)
        label = val[u'label']

    size = smart_size(val.get(u'size', "N/A"))
    print("SHA1:{0}{1}{2} Label:{3}{4:11}{2} Family:{3}{5:10} {2}Size:{0}{6}{7}".format(\
        Style.BRIGHT, val['sha1'],
        Style.RESET_ALL, color, label.title(),
        val.get(u'family', "N/A").title(),
        Style.BRIGHT + Fore.WHITE, size))

def show_results(results):
    print("-"*100)
    for val in results:
        show_row(val)

def show_stats(stats):
    print("Found {0} results : {1}{2} clean {3}{4} malware {5}{6} PUA {7}{8} unknown {9}{10} suspicious".format(\
        stats['total_count'],\
        LABEL_COLOR['clean'], stats['clean_count'],\
        LABEL_COLOR['malware'], stats['malware_count'],\
        LABEL_COLOR['pua'], stats['pua_count'],\
        LABEL_COLOR['unknown'], stats['unknown_count'],
        LABEL_COLOR['suspicious'], stats['suspicious_count']\
        )
    )

def process_search(args):
    search_query = []
    for val in args.hex:
        search_query.append(hex_pattern(val.replace(' ', '')))
    for val in args.a:
        search_query.append(ascii_pattern(val))
    for val in args.w:
        search_query.append(wide_pattern(val))

    result = BINOBJ.search(search_query, limit=args.limit, exact=args.exact)
    if result.has_key('error'):
        print(Style.BRIGHT + Fore.RED + result['error']['message'])
        return

    if result.has_key('stats'):
        show_stats(result['stats'])

    if len(result['results']) == 0:
        return
    print("Showing top {0} results:".format(args.limit))

    show_results(result['results'])

def process_classify(args):
    if os.path.exists(args.files[0]):
        filelist = args.files
        if os.path.isdir(args.files[0]):
            filelist = get_filelist(filelist[0])

        result = BINOBJ.classify_files(filelist, upload_missing=args.u, status_callback=my_callback)
    else:
        result = BINOBJ.classify_hashes(args.files)

    if 'error' in result or result['status'] != 'done':
        print(Style.BRIGHT + Fore.RED + "Request failed:")
    else:
        print("Classification Results:")

    print("-"*100)
    for key,value in result['results'].iteritems():
        if 'error' in value:
            print("SHA1:{0}{1}{2} Error:{3}{4}".format(Style.BRIGHT + Fore.WHITE, key, Style.RESET_ALL, Style.BRIGHT + Fore.RED, value['error']['message']))
        else:
            show_row({'sha1':key, 'label':value.get('label', 'N/A'), 'family':value.get('family', 'N/A')})
    return


def process_hunt(args):
    result = BINOBJ.yara_hunt(args.yarafile, my_callback)
    if result.has_key('stats'):
        show_stats(result['stats'])
    show_results(result['results'])

def my_callback(response):
    print("{0} : Request status = {1:<10}".format(datetime.datetime.now(), response.get('status', None)))

def process_sign(args):
    sign_options = {'strategy' : args.strategy, 'frag_count':args.fragcount, 'cluster':args.cluster}
    if os.path.exists(args.files[0]):
        filelist = args.files
        if os.path.isdir(args.files[0]):
            filelist = get_filelist(filelist[0])

        result = BINOBJ.gen_ioc_files(filelist, options=sign_options, upload_missing=args.u, status_callback=my_callback)
    else:
        result = BINOBJ.gen_ioc_hashes(args.files, status_callback=my_callback)

    if 'error' in result or result['status'] != 'done':
        print(Style.BRIGHT + Fore.RED + "Request failed")
    else:
        print("Generated {0} signature(s) in {1:d}s".format(len(result.get('signatures',[])), result['stats']['time_ms']/1000))

    reqid = result['reqid']

    yara_signatures = []
    for idx,signature in enumerate(result.get('signatures', [])):
        sig_info = BINOBJ.get_request(signature['info'])
        with open("auto_{0}_{1}.json".format(reqid, idx), mode="w") as sigfile:
            sigfile.write(json.dumps(sig_info))

        yarasig = BINOBJ.get_request(signature['yarasig'])
        yara_signatures.append(yarasig)

        with open("auto_{0}.yar".format(reqid), mode="a") as sigfile:
            sigfile.write(yarasig)

        print("Sig #{0} - detects {1} indexed files from family: {2}{3}".format(idx,
                                                                                len(sig_info.get('samples', [])),
                                                                                LABEL_COLOR[sig_info.get('label', "malware")],
                                                                                sig_info.get('family', "N/A")))

    print("Signing results:")
    for filehash,info in result['results'].iteritems():
        status = Fore.GREEN + 'Signed'
        if info['status'] != 'signed':
            status = Fore.RED + "Failed ({0})".format(info['error']['message'])

        print("Hash:{0}{1}{2} Status:{3}".format(Style.BRIGHT + Fore.WHITE, filehash, Style.RESET_ALL, status))

    if len(yara_signatures) > 0:
        print("\nPlease check {0} file for generated signature(s).".format("auto_{0}.yar".format(reqid)))
        
    if args.yara:
        print "YARA Rules:"
        for rule in yara_signatures:
            print rule
    return

def process_metadata(args):
    result = BINOBJ.get_metadata(args.filehash)
    if result.has_key('error'):
        print(Style.BRIGHT + Fore.RED + result['error']['message'])
        return

    dump(result[args.filehash])

def process_demo(args):
    return

def read_apikey(filepath=APIKEYPATH):
    global APIKEY

    if not os.path.exists(filepath):
        return False

    with open(filepath, 'r') as f:
        APIKEY = f.readline()

    APIKEY = APIKEY.strip()
    return True

def init_api(args):
    global BINOBJ, APIKEY

    APIKEY = args.key
    if len(APIKEY) == 0 and read_apikey() == False:
        raise RuntimeError("You need to provide an API access key. Register at https://binar.ly in order to receive one")

    BINOBJ = BinarlyAPI(api_key=APIKEY, use_http=args.usehttp, project="BinarlyPyQuery")
    return

def main(args):
    init_api(args)
    cmd = args.commands
    if cmd == 'search':
        return process_search(args)
    elif cmd == 'hunt':
        return process_hunt(args)
    elif cmd == 'sign':
        return process_sign(args)
    elif cmd == 'classify':
        return process_classify(args)
    elif cmd == 'metadata':
        return process_metadata(args)
    elif cmd == 'demo':
        return process_demo(args)
    else:
        print("Unknown command {0}".format(cmd))

if __name__ == "__main__":
    init(autoreset=True)
    args = parser.parse_args()
    main(args)
