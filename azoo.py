import os
import requests
import gzip
import sys
import shutil
from random import sample
import time
from threading import Thread
from queue import Queue
from math import ceil

DATADIR = os.path.join('DATA')
BENIGNDIR = DATADIR + '/BENIGN'
MALWAREDIR = DATADIR + '/MALWARE'
LISTDIR = os.path.join('LISTS')
INPUTPATH_B = LISTDIR + '/benign_list_sha256'
INPUTPATH_M = LISTDIR + '/malware_list_sha256'

REPORT_COUNT = 0

if os.path.isfile('.apiconf'):
    with open('.apiconf', 'r') as f:
        API_KEY = f.readline().strip('\n')
else:
    print('.apiconf missing. API key needed.')
    exit(1)

if os.path.isfile(LISTDIR + '/latest.csv'):
    with open(LISTDIR + '/latest.csv', 'r') as f:
        TOTAL_COUNT = len(f.readlines()[1:])

def download_file(url, dirname):
    local_filename = url.split('/')[-1]
    with open(dirname + '/' + local_filename, 'wb') as f:
        start = time.clock()
        r = requests.get(url, stream=True)
        total_length = r.headers.get('content-length')
        dl = 0
        if total_length is None:
            f.write(r.content)
        else:
            for chunk in r.iter_content(1024):
                dl += len(chunk)
                f.write(chunk)
                done = int(50 * dl / total_length)
                print('\r{} [{} {}] {:2.2f} Mb/s'.format(local_filename, '=' * done,
                      ' ' * (50 - done), (dl/1048576)//(time.clock() - start)), end='')
    return 0


def get_apk(url, outfile, dirname, num, total):
    local_filename = outfile + '.apk'
    with open(dirname + '/' + local_filename, 'wb') as f:
        # start = time.clock()
        r = requests.get(url, stream=True)
        total_length = int(r.headers.get('content-length'))
        dl = 0
        if total_length is None:
            f.write(r.content)
        else:
            for chunk in r.iter_content(1024):
                dl += len(chunk)
                f.write(chunk)
                # done = int(50 * dl / total_length)
                # print('\r[{}/{}][{} {}] {:2.2f} Mb/s'.format(str(num), str(total), '=' * done, ' ' * (50 - done), (dl/1048576)//(time.clock() - start)))
        print('\r[{}/{}] {:2.2f} %'.format(str(num),
              str(total), (num/total)*100), end='')
    return 0


def update_lists():
    try:
        print('Downloading latest')
        if os.path.isfile(LISTDIR + '/latest.csv.gz'):
            os.remove(LISTDIR + '/latest.csv.gz')
        download_file(
            'https://androzoo.uni.lu/static/lists/latest.csv.gz', LISTDIR)
    except requests.exceptions.RequestException as err:
        print('Error when getting latest list: {}'.format(err))
        return 1

    print('Extracting csv...')
    if os.path.isfile(LISTDIR + '/latest.csv.gz'):
        latest_csv = gzip.open(LISTDIR + '/latest.csv.gz', 'rb')
        with open(LISTDIR + '/latest.csv', 'wb') as outf:
            outf.write(latest_csv.read())
    else:
        print('File latest.csv.gz does not exist.')
        return 1

    global TOTAL_COUNT

    if os.path.isfile(LISTDIR + '/latest.csv'):
        with open(LISTDIR + '/latest.csv', 'r') as f:
            TOTAL_COUNT = len(f.readlines()[1:])

    print('Updating lists...')
    benign_list = []
    malware_list = []
    if os.path.isfile(LISTDIR + '/benign_list_sha256'):
        with open(LISTDIR + '/benign_list_sha256', 'r') as f:
            for line in f.readlines():
                benign_list.append(line.strip('\n'))
    if os.path.isfile(LISTDIR + '/malware_list_sha256'):
        with open(LISTDIR + '/malware_list_sha256', 'r') as f:
            for line in f.readlines():
                malware_list.append(line.strip('\n'))

    if os.path.isfile(LISTDIR + '/latest.csv'):
        with open(LISTDIR + '/latest.csv', 'r') as f:
            i = 1.0
            for line in f.readlines()[1:]:
                if line.strip('\n').split(',')[7] == '0':
                    if line.strip('\n').split(',')[0] not in benign_list:
                        with open(LISTDIR + '/benign_list_sha256', 'a') as benf:
                            benf.write(line.strip('\n').split(',')[0] + '\n')
                    else:
                        continue
                else:
                    if line.strip('\n').split(',')[0] not in malware_list:
                        with open(LISTDIR + '/malware_list_sha256', 'a') as malf:
                            malf.write(line.strip('\n').split(',')[0] + '\n')
                print('\r[{} / {}] {:0.2f}%'.format(i,
                      TOTAL_COUNT, (i / TOTAL_COUNT)*100), end='')
                i += 1

        print('Done!')

        with open(LISTDIR + '/benign_list_sha256', 'r') as f:
            print('{} Benign Samples'.format(len(f.readlines())))

        with open(LISTDIR + '/malware_list_sha256', 'r') as f:
            print('{} Malware Samples'.format(len(f.readlines())))

        os.remove(LISTDIR + '/latest.csv')
        return 0
    else:
        print('latest.csv not found!')
        return 1


def con_url(sha256):
    return 'https://androzoo.uni.lu/api/download?apikey={}&sha256={}'.format(API_KEY, sha256)


def get_dl(path, num):
    if path == BENIGNDIR:
        if num != 'A':
            if int(num) > 0:
                benign_list_total = []
                with open(LISTDIR + '/benign_list_sha256', 'r') as benf:
                    for line in benf:
                        benign_list_total.append(line.strip('\n'))
                curr_list = [
                    f[:-4] for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
                return sample([f for f in benign_list_total if f not in curr_list], int(num))
        elif num == 'A':
            benign_list_total = []
            with open(LISTDIR + '/benign_list_sha256', 'r') as benf:
                for line in benf:
                    benign_list_total.append(line.strip('\n'))
            curr_list = [
                f[:-4] for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
            return [f for f in benign_list_total if f not in curr_list]
    else:
        if num != 'A':
            if int(num) > 0:
                malware_list_total = []
                with open(LISTDIR + '/malware_list_sha256', 'r') as benf:
                    for line in benf:
                        malware_list_total.append(line.strip('\n'))
                curr_list = [
                    f[:-4] for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
                return sample([f for f in malware_list_total if f not in curr_list], int(num))
        elif num == 'A':
            malware_list_total = []
            with open(LISTDIR + '/malware_list_sha256', 'r') as benf:
                for line in benf:
                    malware_list_total.append(line.strip('\n'))
            curr_list = [
                f[:-4] for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
            return [f for f in malware_list_total if f not in curr_list]


class DownloadWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            url, sha, dirname, count, total = self.queue.get()
            get_apk(url, sha, dirname, count, total)
            self.queue.task_done()


def download(num_benign, num_malware):
    benign_download_list = get_dl(BENIGNDIR, num_benign)
    malware_download_list = get_dl(MALWAREDIR, num_malware)

    print('Benign Downloads...')

    work_queue = Queue()

    for x in range(4):
        worker = DownloadWorker(work_queue)
        worker.daemon = True
        worker.start()

    if benign_download_list:
        for i, sha in enumerate(benign_download_list):
            work_queue.put((con_url(sha), sha, BENIGNDIR,
                           i + 1, len(benign_download_list)))

    work_queue.join()

    print('Malware Downloads...')
    if malware_download_list:
        for i, sha in enumerate(malware_download_list):
            work_queue.put((con_url(sha), sha, MALWAREDIR,
                           i + 1, len(malware_download_list)))
    print('')
    work_queue.join()

    return 0


def usage_err():
    message = """
Usage: python azapi.py <options>

Options:

update: Download latest list of apks and update local lists
    e.g. python azapi.py update

download <benign> <malware>:
Bulk download random APKs. Number of benign apks and malware apks to download 
        python azapi.py download 1 1
    'A' to Download all apks in the lists (Make sure you have enough space...)
        python azapi.py download A A
            Download all benign and malware apks
        python azapi.py download 0 A
            Download all malware apks
        """
    print(message)
    exit(1)


def main():
    if len(sys.argv) < 2:
        usage_err()
    elif sys.argv[1] == 'update':
        update = update_lists()
        if update:
            print('Update Failed!')
            exit(1)
        else:
            print('Update successful!')
            exit(0)
    elif sys.argv[1] == 'download':
        if len(sys.argv) < 4:
            usage_err()
        else:
            num_benign = sys.argv[2]
            num_malware = sys.argv[3]
            download(num_benign, num_malware)
            print('Download Complete!')
            exit(0)
    else:
        usage_err()

    exit(0)


if __name__ == '__main__':
    main()
