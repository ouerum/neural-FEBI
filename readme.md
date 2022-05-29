Note: you need to clone this repo using the --recursive flag since this repo has submodules, e.g., git clone git@github.com:ouerum/neural-FEBI.git --recursive

# Neural-FEBI: Accurate Function Identification in Ethereum Virtual Machine Bytecode


## 1. The workflow of neural-FEBI

![workflow](https://github.com/ouerum/neural-FEBI/blob/master/figures/workflow.png)


## 2. Prerequisites
* Build Solidity compiler from the source(https://docs.soliditylang.org/)
* Python 3.8

## 3. Running neural-FEBI

### 3.1 ground truth extractor

1. Use the project `scripts/contractCrawler` to download the Solidity code from EtherScan.
2. Compile the instrumented Solidity Compiler (`instrumentedSolc/solc-0.4.25` and `instrumentedSolc/solc-0.5.17`). 
3. Use the `scripts/buildGroundTruth/compileContracts.py` to compile Solidity Contract into EVM bytecode and annotation about how to construct function boundaries.
4. Use the `scripts/buildGroundTruth/getGroundTruthBatch.py` to extract the ground truth from the above annotation.

### 3.2 function entries identification

1. make sure the setting in `FSI/utils/config.py` are set.
2. Use the `FSI/main.py` to train the model to identify function entries of EVM bytecode.
3. Once the training is over, use the `FSI/predict_operator.py` to predict the function entries for the stripped EVM bytecode.

### 3.3 function boundaires detection

1. make sure the setting in `FBD/fbdconfig.py` are set.
2. Use the `FBD/batch_analysis.py` to detect function boundaries.



## 3. Dataset

URL: https://drive.google.com/drive/folders/1LsVEmKFALN9t2trWivPgEZI41lzeqEdu?usp=sharing

The dataset contains two parts :

* dataset/etherscan.zip: the solidity contracts crawled from Etherscan. 
* dataset/ground-truth.zip: the ground-truth of function boundaries for given instrumented solc and contracts. 



