
dtypes[0]="0.4.25-unoptimized"
#dtypes[1]="0.4.25-optimized"
#dtypes[2]="0.5.17-optimized"
#dtypes[3]="0.5.17-unoptimized"

osolcs[0]="0.4.25"
#osolcs[1]="0.4.25"
#osolcs[2]="0.5.17"
#osolcs[3]="0.5.17"

asolcs[0]="0.4.25-59dbf8f1"
#asolcs[1]="0.4.25-59dbf8f1"
#asolcs[2]="0.5.17-d19bba13"
#asolcs[3]="0.5.17-d19bba13"

optimiteds[0]="n"
#optimiteds[1]="y"
#optimiteds[2]="y"
#optimiteds[3]="n"


for i in {0..0}
do
  echo "cleaning output dir"

  rm -rf /home/dapp/ssd/personal/neural-FIBD/data/ground-truth/${dtypes[${i}]}/*
  mkdir /home/dapp/ssd/personal/neural-FIBD/data/ground-truth/${dtypes[${i}]}/data

  echo "generate ground truth on "${dtypes[${i}]}
  python ./compileContracts.py --contract_dir /home/dapp/ssd-ext/etherscan/ \
          --temp_working_dir /home/dapp/ssd/personal/neural-FIBD/.temp/ \
          --additional_solc /home/dapp/ssd/personal/neural-FIBD/project/instrumented-solc/${asolcs[${i}]}/solidity/build/solc/solc \
          --original_solc /home/dapp/ssd/personal/projects/${osolcs[${i}]}/solidity/build/solc/solc \
          --unique_addresses_path /home/dapp/ssd/personal/neural-FIBD/data/solc-data/unique_addresses \
          --result_dir /home/dapp/ssd/personal/neural-FIBD/data/ground-truth/${dtypes[${i}]}\
          --optimized ${optimiteds[${i}]} \

  echo "completed for "${dtypes[${i}]}
done


exit 0