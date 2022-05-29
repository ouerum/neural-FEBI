import scrapy
import json
import os

class Crawl_Gigahorse(scrapy.spiders.Spider):

    name = "etherscanSpider"

    output_dir = "/home/dapp/ssd-ext/etherscan/"

    address_dir = "/home/dapp/ssd/nas/contract_src_addrs/addresses"

    url = "https://api-cn.etherscan.com/api?module=contract&action=getsourcecode&apikey=M6VMBHP2TIIQKT9TH4471HWS92H5HW73HR&address="

    headers = {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"
    }

    def start_requests(self):
        with open(self.address_dir, 'r') as f:
            addresses = f.read().split('\n')
            for address in addresses:
                if address.startswith('0x') and not os.path.exists(self.output_dir+"/"+address+"/code.sol"):
                    page_url = self.url + address
                    yield scrapy.Request(page_url)

    def parse(self, reponse):
        result = json.loads(reponse.body)
        param = reponse.url.split("&")[-1]
        if param.startswith("address="):
            address = param[8:]
            if result["message"] == 'OK' and len(result["result"]) == 1:
                if len(result['result'][0]['SourceCode']) > 0:
                    if not os.path.exists(self.output_dir + "/" + address):
                        os.system("mkdir " + self.output_dir + "/" + address)
                    src = result["result"][0]["SourceCode"]
                    solc_version = result["result"][0]["CompilerVersion"]
                    name = result["result"][0]["ContractName"]
                    optimized = result["result"][0]["OptimizationUsed"]
                    runs = result["result"][0]["Runs"]
                    constructor = result["result"][0]["ConstructorArguments"]
                    abi = result["result"][0]["ABI"]
                    with open(self.output_dir+"/"+address+"/"+"info", "w+") as f:
                        f.write(name + '\n')
                        f.write(solc_version + '\n')
                        f.write(optimized + '\n')
                        f.write(runs)
                    with open(self.output_dir+"/"+address+"/contract_creation_code", "w+") as f:
                        f.write(constructor)
                    with open(self.output_dir+"/"+address+"/code.abi", "w+") as f:
                        f.write(abi)
                    with open(self.output_dir+"/"+address+"/code.sol", "w+") as f:
                        f.write(src)



