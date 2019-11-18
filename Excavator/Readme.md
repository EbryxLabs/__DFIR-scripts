# Excavator

*A light-weight tool to parse Windows event-logs to XML and send them to ELK*

__Requirments:__

- xmltodict
- elasticsearch

__Tested OS:__

- Windows 10
- Ubuntu 18.04

__Tested Python Version:__

- Python 3.7.2

__What You Can Do With Excavator:__

- You can convert any or all evtx files in a path to XML __*-m xml*__
- You can send event-logs from any or all files in a given path to ELK __*-m send*__
- You can achieve both of the above tasks in a single run __*-m auto*__
- If you do not want to send the logs to ELK but only convert them to JSON instead, you can display the JSON output on your terminal __*-m json*__

__How Exacavtor Works:__

- Uses windows' own utility __wevtutil__ to parse the event-logs to XML
- Requires *xmltodict* for converting the logs form XML to JSON
- Requires *elasticsearch* to push the event-logs to your ELK
- Windows platform is a must for converting logs to xml we use windows' own utility for that

*NOTE: Excavator saves the XML files in the same directory after converting them from EVTX*

## Usage:

```
Excavator.py [-h] [-m <action>] [-p <path>] [-ip <ip>] [-port <port>]
             [-f <file>] [-i <index>] [-user <user>] [-pwd <pass>]
             [-s <size>] [-scheme <size>]

optional arguments:
    -h, --help      show this help message and exit
    -m <action>     xml, send, dont_send, auto
    -p <path>       path to Evtx files
    -ip <ip>        elasticsearch IP
    -port <port>    elasticsearch port
    -f <file>       evtx file to process. Only use for single file
    -i <index>      name of ELK index
    -user <user>    username of ELK for authorization
    -pwd <pass>     password of ELK for authorization
    -s <size>       size of queue
    -scheme <size>  http or https
```

## Examples:

- Convert all evtx files in a directory to XML
```
python Excavator.py -m xml -p <path_of_directory>
```
- Convert a single file in a directory to XML
```
python Excavator.py -m xml -p <path_to_directory> -f <filename.evtx>
```
- Display all event-logs from all XML files in a directory as JSON
```
python Excavator.py -m json -p <path_to_directory>
```
- Send 1000 logs at a time into ELK from a single XML file generated from its corresponding evtx file
```
python Excavator.py -m send -p <path_to_directory> -f <filename.evtx> -ip <elasticsearch_IP> -port <elasticsearch_port> -user <elasticsearch_user> -pwd <elasticsearch_password> -s 1000
```
- Send 100 logs at a time into ELK from a single EVTX file
```
python Excavator.py -m auto -p <path_to_directory> -f <filename.evtx> -ip <elasticsearch_IP> -port <elasticsearch_port> -user <elasticsearch_user> -pwd <elasticsearch_password>
```
