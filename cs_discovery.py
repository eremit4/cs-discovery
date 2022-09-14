#!/usr/bin/env python3
import ssl
from warnings import filterwarnings
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
        "url_to_check": "\n{}[{}>{}] Analyzing target {}<{}>{}",
        "target_alive": "\t{}[{}>{}] The target {}<{}>{} is alive",
        "target_not_alive": "\t{}[{}!{}] The target {}<{}>{} is not alive",
        "cs_possible": "\t{}[{}>{}] Possible Cobalt Strike detected using encoded byte",
        "no_indicator": "\t{}[{}>{}] No indicator was found in target {}<{}>{} using encoded byte",
        "get_jarm": "\t{}[{}>{}] Jarm: {}{}{}",
        "target_mentions": "\t{}[{}>{}] Looking for target mentions on the internet",
        "lookup_url": "\t\t{}[{}+{}] Url: {}{}{}",
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
        resp = get(url=target, verify=False)
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
    except ConnectionError or MaxRetryError as error:
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
        get the Jarm itself
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

    if port == 80 or "http://" in address:
        return "Not found"

    input_cleared = sub(configs["clear_input_to_jarm"], subst, address, 0, MULTILINE | IGNORECASE)
    is_domain = search(configs["domains_regex"], input_cleared)
    is_ip = match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', input_cleared)

    if is_domain:
        return get_jarm(address_=is_domain.string, port_=port)
    elif is_ip:
        return get_jarm(address_=is_ip[0], port_=port)
    else:
        return "Not found"


def target_lookup_from_google(query: str) -> None:
    """
    Search the target on Google to look for mentions of it
    :param query: dork to find the target on VT or GitHub from Google Search
    :return: None
    """
    print(configs["logs"]["target_mentions"].format(Fore.LIGHTWHITE_EX,
                                                    Fore.LIGHTRED_EX,
                                                    Fore.LIGHTWHITE_EX))
    response = get(url=f"https://www.google.com/search?q={query}",
                   headers={"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                            "Connection": "keep-alive",
                            "Upgrade-Insecure-Requests": "1"})
    soup = BeautifulSoup(response.content, 'html.parser')
    count = 0
    links_1, links_2 = soup.findAll("a"), soup.findAll("div > a")
    for link in links_1:
        if not link.attrs.get("href"):
            continue
        if ("github" in link.attrs["href"] or "virustotal" in link.attrs["href"]) and not "translate.google" in link.attrs["href"]:
            print(configs["logs"]["lookup_url"].format(Fore.LIGHTWHITE_EX,
                                                       Fore.LIGHTBLUE_EX,
                                                       Fore.LIGHTWHITE_EX,
                                                       Fore.LIGHTBLUE_EX,
                                                       link.attrs["href"].replace("/url?q=", ""),
                                                       Fore.RESET))
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
            url = f"{url}/%0".strip().replace("//%", "/%")
            urlopen(url=url)
        except Exception as error:
            request_error = str(error)

        if ("Bad Request" or configs["response_msg"]) in request_error:
            print(configs["logs"]["cs_possible"].format(Fore.LIGHTWHITE_EX,
                                                        Fore.LIGHTRED_EX,
                                                        Fore.LIGHTWHITE_EX))
            jarm = acquire_jarm(url)
            print(configs["logs"]["get_jarm"].format(Fore.LIGHTWHITE_EX,
                                                     Fore.LIGHTRED_EX,
                                                     Fore.LIGHTWHITE_EX,
                                                     Fore.LIGHTRED_EX,
                                                     jarm,
                                                     Fore.RESET))
            target = url.replace("/%0", "")
            if jarm == "Not found":
                target_lookup_from_google(query=f"{target} cobalt strike")
            else:
                target_lookup_from_google(query=f"{jarm}")

        else:
            print(configs["logs"]["no_indicator"].format(Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTRED_EX,
                                                         Fore.LIGHTWHITE_EX,
                                                         Fore.LIGHTRED_EX,
                                                         url,
                                                         Fore.LIGHTWHITE_EX))


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
        filterwarnings("ignore")
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
