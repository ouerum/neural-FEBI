## Neural-FEBI: Accurate Function Identification in Ethereum Virtual Machine Bytecode

#### 1. The workflow of neural-FEBI

![workflow](https://github.com/ouerum/neural-FEBI/blob/main/figures/workflow.png)

#### 2. Dataset

URL: https://drive.google.com/drive/folders/1LsVEmKFALN9t2trWivPgEZI41lzeqEdu?usp=sharing

The dataset contains two parts :

* dataset/etherscan.zip: the solidity contracts crawled from Etherscan. It was collected by /neural-FEBI/scripts/contractCrawler
* dataset/ground-truth: the ground-truth of function boundaries for given instrumented solc and contracts. It was constructed by /neural-FEBI/scripts/buildGroundTruth

