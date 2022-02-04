import matplotlib.pyplot as plt

import networkx as nx
import matplotlib.pyplot

def bug_fix_permutate(testedges, graph, indivudal_edge_thickness):
    #print testedges
    for i in range(0,len(graph)):
        if testedges[i]!=graph[i]:
            try:
                indbadges=testedges.index(graph[i])
            except Exception as ex:
                indbadges=testedges.index((graph[i][1],graph[i][0]))

            testedges[i],testedges[indbadges]=testedges[indbadges],testedges[i]
            indivudal_edge_thickness[i],indivudal_edge_thickness[indbadges]=indivudal_edge_thickness[indbadges],indivudal_edge_thickness[i]

    #print indivudal_edge_thickness
    return indivudal_edge_thickness


def draw_graph(graph,individual_edge_thickness, labels=None, graph_layout='shell',
               node_size=1600, node_color='blue', node_alpha=0.3,
               node_text_size=12,
               edge_color='blue', edge_alpha=0.3, edge_tickness=1,
               edge_text_pos=0.3,
               text_font='sans-serif'):

    G=nx.Graph()
    G.add_edges_from(graph)

    #Fixing autistic bug
    testedges=G.edges()
    individual_edge_thickness=bug_fix_permutate(testedges,graph,individual_edge_thickness)

    if graph_layout == 'spring':
        graph_pos=nx.spring_layout(G)
    elif graph_layout == 'spectral':
        graph_pos=nx.spectral_layout(G)
    elif graph_layout == 'random':
        graph_pos=nx.random_layout(G)
    else:
        graph_pos=nx.shell_layout(G)

    nx.draw_networkx_nodes(G,graph_pos,node_size=node_size,
                           alpha=node_alpha, node_color=node_color)
    nx.draw_networkx_edges(G,graph_pos,width=individual_edge_thickness,
                           alpha=edge_alpha,edge_color=edge_color)
    nx.draw_networkx_labels(G, graph_pos,font_size=node_text_size,
                            font_family=text_font)

    if labels is None:
        labels = ["" for element in range(len(graph))]

    edge_labels = dict(zip(graph, labels))
    nx.draw_networkx_edge_labels(G, graph_pos, edge_labels=edge_labels,
                                 label_pos=edge_text_pos)

    plt.show()