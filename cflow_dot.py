import os
import subprocess
import time
import logging
import sys
import smtplib
import ssl
from asyncio.subprocess import DEVNULL

base_folder = '/storage2/yueke/'
sample_folder = os.path.join(base_folder, 'projects')
severities = ['low', 'crit', 'med', 'high']

def get_c_files(repo_folder: str) -> list:
    c_files_with_whitespace = subprocess.check_output(f'find {repo_folder} -type f -name "*.c"', 
        shell=True, stderr=DEVNULL)
    return [f.strip().decode('utf-8') for f in c_files_with_whitespace.splitlines()]

def forward_cflow(analysis_folder: str, c_file_string: str):
    cflow_output = os.path.join(analysis_folder, 'cflow-caller.dot')

    cflow_cmd = f'cflow -f dot -d 8 -o {cflow_output} {c_file_string}'
    subprocess.run(cflow_cmd.split(), stderr=DEVNULL, timeout=10800)

def reverse_cflow(analysis_folder: str, c_file_string: str):
    cflow_output = os.path.join(analysis_folder, 'cflow-callee.dot')

    cflow_cmd = f'cflow -r -f dot -d 8 -o {cflow_output} {c_file_string}'
    subprocess.run(cflow_cmd.split(), stderr=DEVNULL, timeout=10800)

def run_cflow(repo_folder: str, analysis_folder: str):
    c_files = get_c_files(repo_folder)
    c_file_string = ' '.join(c_files)

    try:
        forward_cflow(analysis_folder, c_file_string)
        reverse_cflow(analysis_folder, c_file_string)
    except:
        with open(os.path.join(analysis_folder, 'cflow-fail'), 'w'): pass


def send_email(subject: str, body: str) -> None:

    message = f"""\
Subject: {subject}

{body}"""

    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)

port = 465
smtp_server = 'smtp.gmail.com'
sender_email = 'nicole.developer.acct@gmail.com'
receiver_email = 'nicole.e.cuthbert+cumberland@vanderbilt.edu'
password = 'anqhowsgeeotlwqd'
context = ssl.create_default_context()


# configure logging
timestr = time.strftime("%Y%m%d-%H%M%S")
log_file = os.path.join('/home/yueke/logs/', f'cflow2_{timestr}.log')
targets = logging.StreamHandler(sys.stdout), logging.FileHandler(log_file)
logging.basicConfig(format='%(message)s', level=logging.INFO, handlers=targets)


for sev_folder in [os.path.join(sample_folder, sev) for sev in severities]:
    for project_folder in [f.path for f in os.scandir(sev_folder) if f.is_dir()]:
        repo_folder = os.path.join(project_folder, 'repo')
        analysis_folder = os.path.join(project_folder, 'analysis')

        if not os.path.exists(repo_folder):
            logging.info(f'- skipping {os.path.basename(project_folder)}')
            continue

        if os.path.exists(os.path.join(analysis_folder, 'cflow-caller.dot')) and os.path.exists(os.path.join(analysis_folder, 'cflow-callee.dot')):
            logging.info(f'- already did {os.path.basename(project_folder)}')
            continue

        # if os.path.exists(os.path.join(analysis_folder, 'cflow-fail')):
        #     logging.info(f'- previously timed out {os.path.basename(project_folder)}')
        #     continue

        if os.path.basename(project_folder).endswith('linux'):
            logging.info(f'- skipping {os.path.basename(project_folder)}')
            continue

        tmstmp = time.strftime("%m-%d %H:%M:%S")
        logging.info(f'-- starting {os.path.basename(project_folder)} at {tmstmp}')

        run_cflow(repo_folder, analysis_folder)

        tmstmp = time.strftime("%m-%d %H:%M:%S")
        logging.info(f'-- done with {os.path.basename(project_folder)} at {tmstmp}')

    logging.info(f'done with {os.path.basename(sev_folder)}')
    send_email('cflow update', f'done with {os.path.basename(sev_folder)}')    

logging.info('done with everything!')
send_email('cflow update', f'DONE with everything') 
