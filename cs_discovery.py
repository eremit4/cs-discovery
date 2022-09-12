#!/usr/bin/env python3
import ssl
from bs4 import BeautifulSoup
from colorama import Fore, init
from jarm.scanner.scanner import Scanner
from urllib.request import urlopen
from urllib3.exceptions import MaxRetryError
from traceback import format_exc as print_traceback
from re import search, sub, match, MULTILINE, IGNORECASE
from requests import get
from requests.exceptions import ConnectionError
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
        "url_to_check": "{}[{}>{}] Analyzing target {}<{}>{}",
        "target_alive": "\t{}[{}>{}] The target {}<{}>{} is alive",
        "target_not_alive": "\t{}[{}!{}] The target {}<{}>{} is not alive",
        "cs_possible": "\t{}[{}>{}] Possible Cobalt Strike detected using encoded byte",
        "no_indicator": "\t{}[{}>{}] No indicator was found in target {}<{}>{} using encoded byte",
        "get_jarm": "\t{}[{}>{}] Jarm: {}",
        "jarm_lookup": "\t{}[{}>{}] Searching for the Jarm above in Github and VirusTotal",
        "lookup_url": "\t\t{}[{}+{}] Url: {}",
        "lookup_not_found": "\t\t{}[{}-{}] Not found",
        "key_interrupt": "\n{}[{}!{}] Well, it looks like someone interrupted the execution...",
        "error": "{}[{}!{}] An error occurred: {}"
    },
    "logo": r"""{}
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
    """
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


def target_alive_checker(target: str) -> bool:
    """
    check if the target is alive
    :param target: target url
    :return: True if the target is alive and False if the target is down
    """
    try:
        resp = get(url=target)
        if resp.status_code >= 500:
            print(configs["logs"]["target_not_alive"].format(Fore.LIGHTWHITE_EX,
                                                             Fore.LIGHTRED_EX,
                                                             Fore.LIGHTWHITE_EX,
                                                             Fore.LIGHTRED_EX,
                                                             target,
                                                             Fore.LIGHTWHITE_EX))
            return False
        print(configs["logs"]["target_alive"].format(Fore.LIGHTWHITE_EX,
                                                     Fore.LIGHTRED_EX,
                                                     Fore.LIGHTWHITE_EX,
                                                     Fore.LIGHTRED_EX,
                                                     target,
                                                     Fore.LIGHTWHITE_EX))
        return True
    except ConnectionError or MaxRetryError:
        print(configs["logs"]["target_not_alive"].format(Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTRED_EX,
                                                         Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTRED_EX,
                                                         target,
                                                         Fore.LIGHTWHITE_EX))
        return False


def acquire_jarm(address: str) -> str:
    """
    receives a user input, validate itself and get jarm
    :param address: domain, url or ip
    :return: jarm signature
    """
    def get_jarm(address_: str, port_: int) -> str:
        """
        get the jarm itself
        :param address_: domain or ip extracted
        :param port_: port
        :return: jarm code string
        """
        try:
            result = Scanner.scan(address_, port_)[0]
            if result is not None:
                return result
            else:
                return "Not found"
        except Exception:
            return "Not found"

    port, subst = None, "\\3"
    try:
        port = int(search(configs["port_regex"], address).group().replace(":", ""))
    except Exception:
        port = 443

    input_cleared = sub(configs["clear_input_to_jarm"], subst, address, 0, MULTILINE | IGNORECASE)
    is_domain = search(configs["domains_regex"], input_cleared)
    is_ip = match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', input_cleared)
    if is_domain:
        return get_jarm(address_=is_domain.string, port_=port)
    elif is_ip:
        return get_jarm(address_=is_ip[0], port_=port)
    else:
        return "Not found"


def jarm_lookup(jarm_code: str) -> None:
    """
    Search the collected jarm on the internet to know if this jarm is known
    :param jarm_code: jarm collected after the encoded bte detection
    :return: None
    """
    print(configs["logs"]["jarm_lookup"].format(Fore.LIGHTWHITE_EX,
                                                Fore.LIGHTRED_EX,
                                                Fore.LIGHTWHITE_EX))
    response = get(url=f"https://www.google.com/search?q={jarm_code}")
    soup = BeautifulSoup(response.content, 'lxml')
    links, count = soup.find_all("a"), 0
    for link in links:
        if "github" in link.attrs['href'] or "virustotal" in link.attrs['href']:
            print(configs["logs"]["lookup_url"].format(Fore.LIGHTWHITE_EX,
                                                       Fore.LIGHTGREEN_EX,
                                                       Fore.LIGHTWHITE_EX,
                                                       link.attrs['href'].replace('/url?q=', '')))
            count += 1
    if count == 0:
        print(configs["logs"]["lookup_not_found"].format(Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTRED_EX,
                                                         Fore.LIGHTWHITE_EX,))


def main(args: ArgumentParser) -> None:
    """
    manages all script procedures
    :param args: argparser client
    :return: None
    """
    arguments = args.parse_args()
    request_error, urls = None, list()
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
                                                     Fore.LIGHTRED_EX,
                                                     Fore.LIGHTWHITE_EX,
                                                     Fore.LIGHTRED_EX,
                                                     url,
                                                     Fore.LIGHTWHITE_EX))
        if not target_alive_checker(target=url):
            continue
        try:
            urlopen(f"{url}/%0".strip().replace("//%", "/%"))
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
            if jarm == "Not found":
                continue
            jarm_lookup(jarm_code=jarm)
        else:
            print(configs["logs"]["no_indicator"].format(Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTRED_EX,
                                                         Fore.LIGHTWHITE_EX,
                                                         url))


if __name__ == "__main__":
    arg_style = lambda prog: CustomHelpFormatter(prog)
    args_ = ArgumentParser(description=configs["argparser"]["desc_general"], add_help=False, formatter_class=arg_style)
    group_required = args_.add_argument_group(title="required arguments")
    group_required.add_argument("-u", "--url", metavar="<url>", type=str, help=configs["argparser"]["url"])
    group_required.add_argument("-f", "--file", metavar="<file>", type=str, help=configs["argparser"]["file"])
    group_optional = args_.add_argument_group(title="optional arguments")
    group_optional.add_argument("-h", "--help", help=configs["argparser"]["help"], action="help", default=SUPPRESS)

    try:
        ssl._create_default_https_context = ssl._create_unverified_context
        # request warning disable
        disable_warnings(InsecureRequestWarning)
        # perform coloroma multiplatform
        init(strip=False)
        print(configs['logo'].format(Fore.LIGHTRED_EX,
                                     Fore.LIGHTWHITE_EX,
                                     Fore.LIGHTRED_EX,
                                     Fore.LIGHTWHITE_EX,
                                     Fore.LIGHTRED_EX,
                                     Fore.LIGHTWHITE_EX))
        main(args=args_)

    except KeyboardInterrupt:
        print(configs["logs"]["key_interrupt"].format(configs["logs"]["key_interrupt"].format(Fore.LIGHTWHITE_EX,
                                                                                              Fore.LIGHTRED_EX,
                                                                                              Fore.LIGHTWHITE_EX)))
    except Exception:
        print(configs["logs"]["error"].format(Fore.LIGHTWHITE_EX,
                                              Fore.LIGHTRED_EX,
                                              Fore.LIGHTWHITE_EX,
                                              print_traceback()))
        exit(1)
