Tool for downloading APKs from Androzoo. AndroZoo is a collection of Android APKs (Benign and Malware) from multiple sources. 
The APKs have been scanned using various antivirus products.
Androzoo location - https://androzoo.uni.lu/
Reference Publication - K. Allix, T. F. Bissyandé, J. Klein and Y. L. Traon, "AndroZoo: Collecting Millions of Android Apps for 
the Research Community," 2016 IEEE/ACM 13th Working Conference on Mining Software Repositories (MSR), 2016, pp. 468-471.
http://doi.acm.org/10.1145/2901739.2903508


Put your Androzoo API key in .apiconf

Usage: python azoo.py [options]

Options:

update: Download latest list of apks and update local lists
    e.g. python azoo.py update

download <benign> <malware>:
  - Bulk download random APKs. Number of benign apks (i) and malware apks (j) to download 
        
        python azoo.py download i j
        
  - 'A' to Download all apks in a list (Make sure you have enough space...)
  
      - Download all APKs
            
            python azoo.py download A A
            
      - Download all malware APKs
      
            python azoo.py download 0 A
            
