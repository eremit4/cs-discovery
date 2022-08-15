import ssl
from colorama import Fore
from urllib.request import urlopen
from jarm.scanner.scanner import Scanner
from re import search, sub, MULTILINE, IGNORECASE
from traceback import format_exc as print_traceback
from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from argparse import ArgumentParser, SUPPRESS, HelpFormatter

configs = {
    "port_regex": ":([0-9]+)",
    "domains_regex": "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)[A-Za-z]{2,6}",
    "clear_input_to_jarm": r"(https?:\/\/)?([w]{3}\.)?(\w*.\w*)([\/\w]*)",
    "response_msg": "BAD REQUEST: Bad percent-encoding.",
    "argparser": {
        "desc_general": "Cobalt Strike Discover - Finding Cobalt Strike Fingerprint.",
        "url": "Single url to check",
        "file": "File path with urls to check",
        "help": "Show this help message and exit."
    },
    "logs": {
        "url_to_check": "{}[{}>{}] Analyzing target {}{}",
        "cs_possible": "\t{}[{}>{}] Possible Cobalt Strike detected using encoded byte",
        "no_indicator": "\t{}[{}>{}] No indicator was found in target {}<{}>{} using encoded byte",
        "get_jarm": "\t{}[{}>{}] Jarm: {}\n",
        "key_interrupt": "\n{}[{}!{}] Well, it looks like someone interrupted the execution...",
        "error": "{}[{}!{}] An error occurred: {}"
    },
    "logo": r'''{}
                   ______      __          ____     _____ __       _ __                  
                  / ____/___  / /_  ____ _/ / /_   / ___// /______(_) /_____             
                 / /   / __ \/ __ \/ __ `/ / __/   \__ \/ __/ ___/ / //_/ _ \            
                / /___/ /_/ / /_/ / /_/ / / /_    ___/ / /_/ /  / / ,< /  __/            
                \____/\____/_.___/\__,_/_/\__/___/____/\__/_/  /_/_/|_|\___/             
                                            / __ \(_)_____________ _   _____  _______  __
                                           / / / / / ___/ ___/ __ \ | / / _ \/ ___/ / / /
                                          / /_/ / (__  ) /__/ /_/ / |/ /  __/ /  / /_/ / 
                                         /_____/_/____/\___/\____/|___/\___/_/   \__, /  
                                                                                /____/   

                         {}[{}>{}] Finding Cobalt Strike Fingerprint
                         [{}>{}] by Johnatan Zacarias and Higor Melgaço                   
    '''
}


class CustomHelpFormatter(HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50, width=100)

    def format_action_invocation(self, action):
        """
        argparser beautifier to method print help
        :param action: argparser action
        :return: beautifier argparser string
        """
        if not action.option_strings or action.nargs == 0:
            return super().format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ', '.join(action.option_strings) + ' ' + args_string


def acquire_jarm(address: str) -> str:
    """
    receives a user input, validate itself and get jarm
    :param address: domain, url or ip
    :return: jarm signature
    """
    port, subst = None, "\\3"
    try:
        port = int(search(configs["port_regex"], address).group().replace(":", ""))
    except Exception:
        port = 443

    input_cleared = sub(configs["clear_input_to_jarm"], subst, address, 0, MULTILINE | IGNORECASE)
    domain = search(configs["domains_regex"], input_cleared)

    if domain is not None:
        try:
            result = Scanner.scan(domain.string, port)[0]
            if result is not None:
                return result
            else:
                return "Not found"
        except Exception:
            return "Not found"


if __name__ == "__main__":
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args = ArgumentParser(description=configs["argparser"]["desc_general"], add_help=False, formatter_class=arg_style)
    group_required = args.add_argument_group(title="required arguments")
    group_required.add_argument("-u", "--url", metavar="<url>", type=str, help=configs["argparser"]["url"])
    group_required.add_argument("-f", "--file", metavar="<file>", type=str, help=configs["argparser"]["file"])
    group_optional = args.add_argument_group(title="optional arguments")
    group_optional.add_argument("-h", "--help", help=configs["argparser"]["help"], action="help", default=SUPPRESS)

    try:
        ssl._create_default_https_context = ssl._create_unverified_context
        # request warning disable
        disable_warnings(InsecureRequestWarning)
        print(configs['logo'].format(Fore.LIGHTBLUE_EX,
                                     Fore.LIGHTWHITE_EX,
                                     Fore.LIGHTBLUE_EX,
                                     Fore.LIGHTWHITE_EX,
                                     Fore.LIGHTBLUE_EX,
                                     Fore.LIGHTWHITE_EX))
        request_error, urls = None, list()

        arguments = args.parse_args()
        if arguments.url:
            urls.append(str(arguments.url).strip())
        elif arguments.file:
            with open(arguments.file, "r+") as file_urls:
                urls = [url.strip() for url in file_urls.readlines()]
        else:
            args.print_help()
            exit(0)

        for url in urls:
            print(configs["logs"]["url_to_check"].format(Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTBLUE_EX,
                                                         Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTCYAN_EX,
                                                         url,
                                                         Fore.LIGHTWHITE_EX))
            try:
                response = urlopen(f"{url}/%0".strip().replace("//%", "/%"))
            except Exception as error:
                request_error = str(error.read().decode())

            if request_error == configs["response_msg"]:
                print(configs["logs"]["cs_possible"].format(Fore.LIGHTWHITE_EX,
                                                            Fore.LIGHTRED_EX,
                                                            Fore.LIGHTWHITE_EX))
                jarm = acquire_jarm(url)
                print(configs["logs"]["get_jarm"].format(Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTRED_EX,
                                                         Fore.LIGHTWHITE_EX,
                                                         jarm))
            else:
                print(configs["logs"]["no_indicator"].format(Fore.LIGHTWHITE_EX,
                                                             Fore.LIGHTBLUE_EX,
                                                             Fore.LIGHTWHITE_EX,
                                                             url))

    except KeyboardInterrupt:
        print(configs["logs"]["key_interrupt"].format(configs["logs"]["key_interrupt"].format(Fore.LIGHTWHITE_EX,
                                                                                              Fore.LIGHTRED_EX,
                                                                                              Fore.LIGHTWHITE_EX)))
    except Exception:
        print(configs["logs"]["error"].format(Fore.LIGHTWHITE_EX,
                                              Fore.LIGHTRED_EX,
                                              Fore.LIGHTWHITE_EX,
                                              print_traceback()))
