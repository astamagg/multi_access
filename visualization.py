import statistics
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import scipy.stats as stats
import re
import math

def read_file(filename):
    f = open(filename,'r')
    return f.read().splitlines()

def read_means_std(filename, indicators=[]):
    lines = read_file(filename)
    results = []

    for i, line in enumerate(lines):
        values = line.split(', ')
        first_entry = values[0].split('(')
        last_entry = values[2].split(')')

        results.append((indicators[i], (float(values[1])*10), (float(last_entry[0])*10)))
    
    return results

def read_average(filename):
    lines = read_file(filename)
    json_results = []
    binary_results = []

    for i, line in enumerate(lines):
        values = re.split(', |: ', line)
        json_results.append(int(values[1])/1000)
        binary_results.append(int(values[3])/1000)
    return json_results,binary_results

def compute_mean_stdev(resulting_times):
    mean_stdev = []
    for i, result in enumerate(resulting_times):
        count, curr_times_str = result
        curr_times = [float(i)*10/1000 for i in curr_times_str]
        curr_mean = statistics.mean(curr_times)
        curr_std = statistics.stdev(curr_times)
        mean_stdev.append((count, curr_mean, curr_std))

    return mean_stdev

def read_all_files(variable_values, source_file, txt=False, splitter=False):
    result_pairs = []

    if not variable_values:
        result_times = read_file(source_file)
        if splitter:
            key_strings = result_times[::11]
            keys = [int(key) for key in key_strings]
            index = 1
            for key in keys:
                times = result_times[index:index+10]
                result_pairs.append((key, times))
                index = index + 11
        else:
            result_pairs.append((0, result_times))

    for count in variable_values:
        if txt:
            filename = "{}_{}.txt".format(source_file, count)
        else:
            filename = "{}_{}".format(source_file, count)

        result_times = read_file(filename)
        if splitter:
            key_strings = result_times[::11]
            keys = [int(key) for key in key_strings]
            index = 1
            for key in keys:
                times = result_times[index:index+10]
                result_pairs.append((count, key, times))
                index = index + 11
        else:
            result_pairs.append((count, result_times))
    return result_pairs

def write_to_file(results_filename, means_stdev):
    f = open(results_filename, 'w+')
    for value in means_stdev:
        f.write(str(value) + '\n')
    f.close()

def make_graph(means_stdevs, xlabel, ylabel, visual_filename, labels=None, results_filename=None,  title = None, comparison=False):
    fig = plt.figure()
    colors = ['darkblue', "darkred", "orange", "green", "purple", "brown", "black"]
    markers = ['o', 'd', 'p', 's'] 

    if comparison:
        index = 0
        for mean_stdev in means_stdevs:
            means = []
            stdevs = []
            counts = []
            if results_filename is not None:
                write_to_file(results_filename, mean_stdev)

            for i, result in enumerate(mean_stdev):
                count, mean, stdev = result
                counts.append(count)
                means.append(mean)
                stdevs.append(stdev)
                
            plt.errorbar(counts, means, stdevs, color=colors[index], marker=markers[index], label=labels[index])
            index += 1

    else:
        means = []
        stdevs = []
        counts = []
        for mean_stdev in means_stdevs:
            if results_filename is not None:
                write_to_file(results_filename, mean_stdev)

            count, mean, stdev = mean_stdev
            counts.append(count)
            means.append(mean)
            stdevs.append(stdev)
        plt.errorbar(counts, means, stdevs, color='darkblue', marker='o')

    if title:
        plt.title(title, fontsize=17)
    
    plt.xlim(xmin=0)
    #plt.ylim(ymin=0)
    plt.xlabel(xlabel, fontsize=14)
    plt.ylabel(ylabel, fontsize=14)
    plt.grid()
    plt.legend()
    plt.savefig(visual_filename, dpi=1200)

def make_reconstruction_graph(levels, xlabel, ylabel, visual_filename,results_filename=None):
    fig = plt.figure()
    colors = ['darkblue', "darkred", "orange", "green", "purple", "brown", "black"]
    labels = levels.keys()
    index = 0
    for level in labels:
        mean_stdev = levels[level]
        if results_filename is not None:
                write_to_file(results_filename, levels)
        means = []
        stdevs = []
        counts = []
        for i, result in enumerate(mean_stdev):
            count, mean, stdev = result
            counts.append(count)
            means.append(mean)
            stdevs.append(stdev)

        plt.errorbar(counts, means, stdevs, color=colors[index], marker='o', label=level)
        index += 1

    plt.xlim(xmin=0)
    plt.ylim(ymin=0)
    plt.xlabel(xlabel, fontsize=15)
    plt.ylabel(ylabel, fontsize=15)
    plt.grid()
    #plt.legend()
    plt.savefig(visual_filename)

def calculate_anova(levels, counts):
    keys = list(levels.keys())
    df = pd.DataFrame(columns=keys)

    for i, key in enumerate(keys):
        means = []
        curr_level = levels[key]
        for i in range(len(counts)):
            means.append(curr_level[i][1])
        
        curr_series = pd.Series(means, index=counts)
        df = df.append(curr_series, ignore_index=True)
        df[key] = means

    fvalue, pvalue = stats.f_oneway(df[1], df[2], df[3], df[4],df[5], df[6], df[7])
    print(fvalue, pvalue)

def calc_gap(means_std, ms=True):
    count, mean, std = means_std
    if ms:
        upper_gap = (mean + std)*1000
        lower_gap = (mean - std)*1000
    else:
        upper_gap = mean + std
        lower_gap = mean - std

    final_lower_gap = lower_gap//10
    if final_lower_gap == 0:
        final_lower_gap = 1

    return final_lower_gap, math.ceil((upper_gap)/10)

def create_tree(heights, visual_file):
    leaf = [28, 24] 
    children = [16, 48]
    self_weight = 48
    string_weight = 55
    memory = []
    sizes = []
    for height in heights:
        sizes.append(pow(2,height)-1)

    for i in range(len(heights)):
        total = 0
        curr_height = heights[i]
        curr_size = sizes[i]
        number_of_leafs = (curr_size + 1) // 2
        not_leafs = curr_size - number_of_leafs
        count = 1

        for i in range(curr_size):
            total += self_weight + string_weight 
            if count >= not_leafs+1:
                total += leaf[0] + (children[0]*2)
            else:
                total += leaf[1] + (children[1]*2)
            count += 1
        
        memory.append(total//1024)

    plt.plot(memory, sizes, marker='o', color='darkblue')
    plt.xlabel("Memory [KB]", fontsize=14)
    plt.ylabel("Size of tree", fontsize=14)
    plt.grid()
    plt.xlim(xmin=0)
    plt.ylim(ymin=0)
    plt.savefig(visual_file)


