# Cobalt Strike Discovery
> Cobalt Strike is a commercial penetration testing tool, which gives security testers access to a large variety of attack capabilities.
> This tool aims to detect Cobalt Strike servers from traffic telemetry, replacing the much-used endpoint telemetry.<br>
> The construction of this project was inspired on the reports <b>[How I Meet Your Beacon - Cobalt Strike](https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/)</b> by <b>MDSec</b>, 
> and <b>[How Malleable C2 Profiles Make Cobalt Strike Difficult to Detect](https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2-profile/)</b> by <b>Palo Alto Unit 42</b>.

## 👨‍💻 Installing

Clone the repository:
```bash
git clone https://github.com/eremit4/cs-discovery.git
```
Optional - Create a virtualenv before install the dependencies
> Note: The use of virtual environments is optional, but recommended. In this way, we avoid possible conflicts in different versions of the project's dependencies.
> Learn how to install and use virtualenv according to your OS [here](https://virtualenv.pypa.io/en/latest/)

Install the dependencies:
```bash
pip install -r requirements.txt
```

## 🥷️ Using

Discovering the project capabilities:
```bash
python cs_discovery.py --help
```

Running against a single target to detect Team Servers using the encoded byte:
```bash
python cs_discovery.py --url <target>
```

Running against multiple targets to detect Team Servers using the encoded byte:
```bash
python cs_discovery.py --file <filepath>
```

Running against a single target to detect Team Servers using byte encoded and other optional method:
```bash
python cs_discovery.py --url <target> --<optional flag>
```

## 🔮️ Demo
[![asciicast](https://asciinema.org/a/541035.svg)](https://asciinema.org/a/541035)

## 📝 License
This project is under the [MIT License](LICENSE).
