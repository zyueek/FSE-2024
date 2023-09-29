"""
Calculates both logical and spatial distances between what the tools found and
what was actually patched.

TODO: update after adjusting get_diff_info.py. also fix file distance. 
"""

import os
import sys
import pandas as pd
import networkx as nx
from ast import literal_eval
from tqdm import *

pd.options.mode.chained_assignment = None

base_folder = '/storage2'
sample_folder = os.path.join(base_folder, 'projects')

severity = sys.argv[1]
if severity == 'all':
    severities = ['low', 'crit', 'med', 'high']
else:
    severities = [severity]

def calc_logical_dist(df: pd.DataFrame, analysis_folder: str):
    called_df = pd.read_csv(os.path.join(analysis_folder, 'caller_graph.csv'), index_col=0)
    called = nx.from_pandas_adjacency(called_df)
    callee_df = pd.read_csv(os.path.join(analysis_folder, 'callee_graph.csv'), index_col=0)
    callee = nx.from_pandas_adjacency(callee_df)

    logical_dists = []
    with open(os.path.join(analysis_folder, 'patched_funcs.txt')) as f:
        patched_funcs = f.readlines()

    for _, row in df.iterrows():
        vul_func = str(row['func_name']).strip()
        distances = []

        for patched_func in patched_funcs:
            patched_func = patched_func.strip()

            if patched_func in called and vul_func in called:
                if nx.has_path(called, patched_func, vul_func):
                    distances.append(len(nx.shortest_path(called, patched_func, vul_func)))
            else:
                distances.append(99)

            if patched_func in callee and vul_func in callee:
                if nx.has_path(callee, patched_func, vul_func):
                    distances.append(-1 * len(nx.shortest_path(callee, patched_func, vul_func)))
            else:
                distances.append(99)

        if distances:
            logical_dists.append(min(distances, key=abs))
        else:
            logical_dists.append(99)
    
    df['logical_dists'] = logical_dists
    close_df = df.loc[df['logical_dists'] != 99]

def calc_line_dist(df: pd.DataFrame, analysis_folder: str):

    diff = pd.read_csv(os.path.join(analysis_folder, 'diff.csv'))
    diff['filename'] = [s.replace('src/','') if s.startswith('src/') else s for s in diff['filename']]
    line_dist = []
    for _, row in df.iterrows():
        vul_file = str(row['file']).strip()
        try:
            vul_line = int(str(row['line_num']).strip())
        except:
            line_dist.append(0.1)
            continue

        if vul_file in diff['filename'].tolist():
            min_dist = []
            right_file = diff.loc[diff['filename'] == vul_file]
            for _, frow in right_file.iterrows():
                start = frow['start_line']
                end = frow['end_line']

                if vul_line in range(start, end+1):
                    min_dist.append(0)
                else:
                    dist_start = abs(vul_line - start)
                    dist_end = abs(vul_line - end)
                    min_dist.append(min([dist_start, dist_end]))

            line_dist.append(min(min_dist))

        else:
            line_dist.append(0.1)

    df['line_dists'] = line_dist
 #   print(line_dist)
    close_df = df.loc[df['line_dists'] > 0.1]


def calc_file_dist(df: pd.DataFrame, analysis_folder: str):
    repo_folder = os.path.join(os.path.dirname(analysis_folder), 'repo')

    diff = pd.read_csv(os.path.join(analysis_folder, 'diff.csv'))

    file_dist = []
    for _, row in df.iterrows():
        flag_dists = []
        vul_file = str(row['file']).strip()

        if vul_file in diff['filename'].tolist():
            flag_dists.append(0)
        else:

            def _compare_paths(path_1: str, path_2: str) -> int:
                if path_1 == path_2:
                    return 0

                path_1_list = path_1.split(os.sep)
                path_2_list = path_2.split(os.sep)

                for i in range(min([len(path_1_list), len(path_2_list)])):
                    if path_1_list[i] != path_2_list[i]:
                        return max([len(path_1_list), len(path_2_list)]) - i
            
            for _, frow in diff.iterrows():
                abs_path_1 = os.path.join(repo_folder, vul_file)
                abs_path_2 = os.path.join(repo_folder, frow['filename'])
                dist = _compare_paths(abs_path_1, abs_path_2)

                flag_dists.append(dist)
        
        file_dist.append(min(flag_dists))

    df['file_dists'] = file_dist
    close_df = df.loc[df['file_dists'] > 0.1]


def analyze_project(analysis_folder: str):
    df = pd.read_csv(os.path.join(analysis_folder, 'tool_data_ci.csv'))
    df = df[['tool', 'file', 'line_num', 'func_name']]
    df.dropna()

#    calc_logical_dist(df, analysis_folder)
    calc_line_dist(df, analysis_folder)
    calc_file_dist(df, analysis_folder)
    df.to_csv(os.path.join(analysis_folder, 'distances_ci.csv'))

for sev_folder in [os.path.join(sample_folder, sev) for sev in severities]:
    for project_folder in tqdm([f.path for f in os.scandir(sev_folder) if f.is_dir()]):
        repo_folder = os.path.join(project_folder, 'repo')

        analysis_folder = os.path.join(project_folder, 'analysis')

        if not os.path.exists(os.path.join(analysis_folder, 'tool_data_ci.csv')):
            continue
        if not os.path.exists(os.path.join(analysis_folder, 'diff.csv')):
            continue
        if not os.path.exists(os.path.join(analysis_folder, 'caller_graph.csv')):
            continue
        print(f'starting {os.path.basename(project_folder)}')
        analyze_project(analysis_folder)
        try:
            analyze_project(analysis_folder)
        except(FileNotFoundError):
            continue
        print(f'done with {os.path.basename(project_folder)}')

print('done with everything')
