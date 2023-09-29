import os
import re
import time
import logging
import sys
import networkx as nx
import pandas as pd
import numpy as np
from tqdm import *
pd.options.mode.chained_assignment = None

base_folder = '/storage2/yueke/'
sample_folder = os.path.join(base_folder, 'projects')

severity = sys.argv[1]
if severity == 'all':
    severities = ['low', 'crit', 'med', 'high']
else:
    severities = [severity]

# configure logging
timestr = time.strftime("%Y%m%d-%H%M%S")
log_file = os.path.join('/home/yueke/logs/', f'logdist_{timestr}.log')
targets = logging.StreamHandler(sys.stdout), logging.FileHandler(log_file)
logging.basicConfig(format='%(message)s', level=logging.INFO, handlers=targets)

for sev_folder in [os.path.join(sample_folder, sev) for sev in severities]:
    for project_folder in tqdm([f.path for f in os.scandir(sev_folder) if f.is_dir()]):

        analysis_folder = os.path.join(project_folder, 'analysis')
        repo_folder = os.path.join(project_folder, 'repo')
        if not os.path.exists(os.path.join(analysis_folder, 'tool_data_ci.csv')):
            continue
        try:
            caller_df = pd.read_csv(os.path.join(analysis_folder, 'caller_graph.csv'), index_col=0)
            caller = nx.from_pandas_adjacency(caller_df)
#            for node in caller.nodes():
#                print(node)
            callee_df = pd.read_csv(os.path.join(analysis_folder, 'callee_graph.csv'), index_col=0)
            callee = nx.from_pandas_adjacency(callee_df)

            # now that we have the graphs, need to get location of patch
            patches = pd.read_csv(os.path.join(analysis_folder, 'diff.csv'), index_col=0)

            # also get the tool data
            tool_data = pd.read_csv(os.path.join(analysis_folder,'tool_data_ci.csv'), index_col=0)
            tool_data = tool_data.assign(location=tool_data.agg('{0[file]}-:{0[func_name]}'.format, axis=1))
            funcnamelist=tool_data['func_name'].to_list()
            # calculate distances
            logical_distances = [np.NaN] * len(tool_data)
            print(len(logical_distances))
            for _, row in patches.iterrows():
                # idea is to get distance from patched function to every other function
                # then fill in the distances in the table
                
                # want to go from tool flag -> ?? -> patched func
                # therefore patched func is target
#                print(row['function'])
                target = f"{row['filename']}-:{row['function']}"[1:] 
#                target = f"{row['function']}"               
                # calculate the length from target to each other function
                try:
                    caller_paths = nx.shortest_path(caller,target=target)
#                    print(caller_paths)
                    caller_lens = {k.replace('rc/','') if k.startswith('rc/') else k: len(v) for k, v in caller_paths.items()}
#                    print(caller_lens)
                    caller_dists = tool_data['location'].map(caller_lens)
                    logical_distances=logical_distances[:]
                    caller_dists = caller_dists[:]
#                    print(tool_data['location'])
#                    print("caller")
#                    print(caller_dists)
#                    print(len(caller_dists))
#                    logical_distances = np.fmin(caller_dists, logical_distances)
                    logical_distances = [min(x, y) for x, y in zip(caller_dists, logical_distances)]
                except(nx.exception.NodeNotFound):
                    try:
                        target = f"{row['function']}"
                        caller_paths = nx.shortest_path(caller,target=target)
#                    print(caller_paths)
                        caller_lens = {k.replace('rc/','') if k.startswith('rc/') else k: len(v) for k, v in caller_paths.items()}
#                    print(caller_lens)
                        caller_dists = tool_data['location'].map(caller_lens)
                        logical_distances=logical_distances[:]
                        caller_dists = caller_dists[:]
                        logical_distances = np.fmin(caller_dists, logical_distances)
#                        logical_distances = [min(x, y) for x, y in zip(caller_dists, logical_distances)]
                    except(nx.exception.NodeNotFound):
                        print(f'{target} caller not found') 
                target = f"{row['filename']}-:{row['function']}"[1:]                   
                try:
                    callee_paths = nx.shortest_path(callee, target=target)
                    callee_lens = {k.replace('rc/','') if k.startswith('rc/') else k: len(v) for k, v in callee_paths.items()}
                    callee_dists = tool_data['location'].map(callee_lens)
                    callee_dists = callee_dists[:]
#                    print(callee_dists)
                    logical_distances = [min(x, y) for x, y in zip(callee_dists, logical_distances)]
#                    logical_distances = pd.Series(np.where(np.abs(callee_dists) < logical_distances, callee_dists, logical_distances))
                except(nx.exception.NodeNotFound):
                    try:
                        target = f"{row['function']}"
                        callee_paths = nx.shortest_path(callee,target=target)
#                    print(caller_paths)
                        callee_lens = {k.replace('rc/','') if k.startswith('rc/') else k: len(v) for k, v in callee_paths.items()}
#                    print(caller_lens)
                        callee_dists = tool_data['location'].map(callee_lens)
                        logical_distances=logical_distances[:]
                        callee_dists = callee_dists[:]
                        logical_distances = [min(x, y) for x, y in zip(callee_dists, logical_distances)]
#                        logical_distances = np.fmin(caller_dists, logical_distances)
#                        logical_distances = [min(x, y) for x, y in zip(callee_dists, logical_distances)]
                    except(nx.exception.NodeNotFound):
                        print(f'{target} caller not found')   

            # save the distances
            tool_data['logical_dist'] = logical_distances
            print(analysis_folder)
            tool_data.to_csv(os.path.join(analysis_folder, 'log-distances_ci.csv'))

        except(RuntimeError,FileNotFoundError,KeyError,nx.exception.NetworkXError) as e:
            logging.info(f'failed on {os.path.basename(project_folder)} {e}')

    logging.info(f'DONE with {os.path.basename(sev_folder)}')

logging.info(f'done with everything')
