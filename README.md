# Cobalt Strikes Discovery
> Cobalt Strike is a commercial penetration testing tool, which gives security testers access to a large variety of attack capabilities.
> This tool aims to detect Cobalt Strike servers by sending an encoded byte in the request to the server itself and, if the response is satisfactory, collects the server's JARM and looks for evidence of the target on the internet.
> The construction of this project was based on a report prepared by MDSec named "How I Meet Your Beacon - Cobalt Strike".
> The report can be seen [here](https://www.mdsec.co.uk/2022/07/part-2-how-i-met-your-beacon-cobalt-strike/) 

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

Running against a single target:
```bash
python cs_discovery.py --url <target>
```

Running against multiple targets
```bash
python cs_discovery.py --file <filepath>
```

## 🔮️ Demo
![](./readme_demo.gif)

## 📝 License
This project is under the [MIT License](LICENSE).
