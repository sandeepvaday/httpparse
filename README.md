# httpparse
Utilily function for parsing HTTP using Python Scapy

### Steps to use:

1. Implement the user_fn() as per your use case.
2. Run the script as:
```
	python httpparse.py -f ../data/example.pcap
```

Replace the pcap file with your own.

The purpose of releasing this code is to share the tweak required for correct
parsing of HTTP sessions, specifically for packets which contain _padding_.


License
-------
Copyright &copy; 2018 Sandeep Yadav
