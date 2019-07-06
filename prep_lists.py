import os
# import csv

DATADIR = os.path.join('DATA')
LISTDIR = os.path.join('LISTS')
TOTAL_COUNT = 5845412


def main():
    with open(LISTDIR + '/latest.csv', 'r') as f:
        i = 1.0
        for line in f.readlines()[1:]:
            if line.strip('\n').split(',')[7] == '0':
                with open(LISTDIR + '/benign_list_sha256', 'a') as benf:
                    benf.write(line.strip('\n').split(',')[0] + '\n')
            else:
                with open(LISTDIR + '/malware_list_sha256', 'a') as malf:
                    malf.write(line.strip('\n').split(',')[0] + '\n')
            print('\r[{} / {}] {}% Done'.format(i, TOTAL_COUNT, (i / TOTAL_COUNT)*100))  
            i += 1

    with open(LISTDIR + '/benign_list_sha256', 'r') as f:
        print('{} Benign Samples'.format(len(f.readlines())))
    
    with open(LISTDIR + '/malware_list_sha256', 'r') as f:
        print('{} Malware Samples'.format(len(f.readlines())))

if __name__ == '__main__':
    main()
