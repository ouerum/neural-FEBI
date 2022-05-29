## Neural-FEBI: Accurate Function Identification in Ethereum Virtual Machine Bytecode

#### 1. The workflow of neural-FEBI

![workflow](https://github.com/ouerum/neural-FEBI/blob/main/figures/workflow.png)



#### 2. neural-FEBI

##### 2.1 ground truth extractor

* Step1. Use `scripts/contractCrawler` to download the Solidity code from EtherScan.
* Step2. Compile the instrumented Solidity Compiler (`instrumentedSolc/solc-0.4.25` and `instrumentedSolc/solc-0.5.17`). 
* Step3. Use the `scripts/buildGroundTruth/compileContracts.py` to compile Solidity Contract into EVM bytecode and annotation about how to construct function boundaries.
* Step4. Use the `scripts/buildGroundTruth/getGroundTruthBatch.py` to extract the ground truth from annotation.

##### 2.2 function entries identification

* Step1. Configure the setting in `FSI/utils/config.py`.
* Step2. Use the `FSI/main.py` to train the model to identify function entries of EVM bytecode.
* Step3. Once the training is over, use the `FSI/predict_operator.py` to predict the function entries for the stripped EVM bytecode.

##### 2.3 function boundaires detection

* Step1. configure the setting in `FBD/fbdconfig.py`.
* Step2. Use the `FBD/batch_analysis.py` to detect function boundaries.



#### 3. Dataset

URL: https://drive.google.com/drive/folders/1LsVEmKFALN9t2trWivPgEZI41lzeqEdu?usp=sharing

The dataset contains two parts :

* dataset/etherscan.zip: the solidity contracts crawled from Etherscan. 
* dataset/ground-truth.zip: the ground-truth of function boundaries for given instrumented solc and contracts. 



