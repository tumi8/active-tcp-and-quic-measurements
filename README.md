# Paper

Simon Bauer, Patrick Sattler, Johannes Zirngibl, Christoph Schwarzenberg, and Georg Carle. 2023. Evaluating the Benefits: Quantifying the Effects of TCP Options, QUIC, and CDNs on Throughput. In Applied Networking Research Workshop (ANRW ’23), July 24, 2023, San Francisco, CA, USA. 

# Pipeline 

## Crawling 

### Requirments

* scrapy
* psutil 
* forcediphttpsadapter

### Run crawl
```
python3 startCrawl.py --file ./target_domains.csv --depth 15 
```
## Downloading 

### Requirments

* requests
* forcediphttpsadapter
* psutil
* aioquic
* asgiref 
* dnslib
* "flask<2.2"
* httpbin
* starlette
* "werkzeug<2.1" 
* wsproto

### Run downloads
```
python3 startDownloads.py -c ./example_conf.json
```

## PCAP Analysis

### Requirments

* scipy
* numpy
* pandas
* json

### Run analysis
```
python3 kpi_extraction.py -p ./dl_result_dir -o ./output_files
```