# Checking for false positives

After generating a YARA rule with a tool such as AutoYara, it is also necessary to check the rule for a high false-positive rate. 
One way to do this is by using a large dataset of random malware from a website such as virusshare.com and to see how often the given rule matches. 
If a Yara rule gets a lot of matches from a large dataset of random malware, it is likely to be a bad rule. 
To accomplish this, it was necessary to prepare a python script that could iterate through a given directory and check all executable files with a Yara rule. 
It is important to note that some of the samples from datasets on virusshare are archive files, and the script used to test the Yara rules accounts for that. 
In a python script with the Yara library imported, a given rule can compiled/referenced like so:
```
rules = yara.compile(filepath='xorddos.yara')
```
After setting up a script to test the Yara rule, it is recommended to download the archived datasets from virusshare into a isolated virtual environment before running any scripts or testing.
