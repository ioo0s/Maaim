# Maaim 

base on [sleighcraft](https://github.com/StarCrossPortal/sleighcraft) implement for Multi-architecture assembly instruction matching

# Depends

```
pip install bincraft==0.1.0
```
## Usage
Obtain valid related instructions for all architectures by input opcode
```python
    branch_dict = match_inst("BRANCH", valid_inst=True)
    print(branch_dict)
    # output
    # {'x86': {'0xe9': {'offset': ' 1*offset + 3', 'arch': []}, '0xeb': {'offset': ' 1*offset + 2', 'arch': []}, '0xf4': {'offset': ' 0', 'arch': []}}}
```
`output.txt` are all `BRANCH` instructions that currently contain the architecture
