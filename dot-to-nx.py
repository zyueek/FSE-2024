import os
import re
import time
import logging
import sys
import networkx as nx

base_folder = '/storage2/
sample_folder = os.path.join(base_folder, 'projects')

severity = sys.argv[1]
if severity == 'all':
    severities = ['low', 'crit', 'med', 'high']
else:
    severities = [severity]

# configure logging
timestr = time.strftime("%Y%m%d-%H%M%S")
targets = logging.StreamHandler(sys.stdout), logging.FileHandler(log_file)
logging.basicConfig(format='%(message)s', level=logging.INFO, handlers=targets)

for sev_folder in [os.path.join(sample_folder, sev) for sev in severities]:
    for project_folder in [f.path for f in os.scandir(sev_folder) if f.is_dir()]:

        analysis_folder = os.path.join(project_folder, 'analysis')
        repo_folder = os.path.join(project_folder, 'repo')

        caller_dot = os.path.join(analysis_folder, 'cflow-caller.dot')
        callee_dot = os.path.join(analysis_folder, 'cflow-callee.dot')

        if not os.path.exists(caller_dot) or not os.path.exists(callee_dot):
            continue
        
        try:
            # import the dot files to networkx graphs
            Caller = nx.drawing.nx_agraph.read_dot(caller_dot)
            Callee = nx.drawing.nx_agraph.read_dot(callee_dot)

            # rename nodes
            for G in [Caller, Callee]:
                repo_path_len = len(repo_folder)

                new_names = {}
                for node_id in G.nodes:
                    try:
                        label_lines = G._node[node_id]['label'].split('\n')
                        if len(label_lines) > 1:
                            file_loc = label_lines[1][repo_path_len + 1:]
                            trimmed_header = label_lines[0].rsplit('(')[0].split()[-1]

                            if trimmed_header.find('*') > -1:
                                func_name = re.sub('*', '', trimmed_header)
                            else:
                                func_name = trimmed_header
                            
                            file_loc = file_loc.rsplit(':')[0]

                            # ex: src/openvpn/openvpn.c-:openvpn_main
                            name = f'{file_loc}-:{func_name}'
                        else:
                            name = node_id
                    except:
                        name = node_id

                    new_names[node_id] = name

                nx.relabel_nodes(G, new_names, copy=False)

            # save graphs
            callee_matrix = nx.to_pandas_adjacency(Callee)
            callee_matrix.to_csv(os.path.join(analysis_folder, 'callee_graph.csv'))

            caller_matrix = nx.to_pandas_adjacency(Caller)
            caller_matrix.to_csv(os.path.join(analysis_folder, 'caller_graph.csv'))

            logging.info(f'DONE with {os.path.basename(project_folder)}')

        except:
            logging.info(f'failed on {os.path.basename(project_folder)}')

    logging.info(f'DONE with {os.path.basename(sev_folder)}')

logging.info(f'done with everything')
