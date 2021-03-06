#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import yara
import re
import sys
import subprocess
import argparse
import hashlib
import csv
import numpy as np
import pandas as pd



packers_path = "/home/luca/Scrivania/tesi/new_scripts/exe_analysis/packers/rules_fixed.csv"

with open(packers_path, mode='r') as infile:
    reader = csv.reader(infile)
    packers_dict = {rows[1]:rows[-1] for rows in reader}

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def compute_stats(rules_path, all_malware_path, family_path, goodware_path, labels_path, output_subdir):

    fp_output = open(output_subdir+"/fp.txt", "w")
    rules_new_matches = open(output_subdir+"/new_matches.txt", "w")
    family_name = family_path.split("/")[-1]
    if family_name == "":
        family_name = family_path.split("/")[-2]

    compiled_rules = yara.compile(rules_path)

    fp_count = 0
    n_tested_goodwares = 0
    for file in os.listdir(goodware_path):
        try:
            res = compiled_rules.match(os.path.join(goodware_path,file))
            n_tested_goodwares += 1
        except Exception as e:
            continue
        if(len(res) > 0):
            fp_output.write("\t-"+file+"\n")
            for rulename in list(res):
                fp_output.write("\t\t-"+str(rulename)+":\n")
            fp_count +=1
    fp_output.write("Total false positives: "+ str(fp_count))
    fp_output.close()
    fp_ratio = fp_count/ n_tested_goodwares

    with open(labels_path) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    labels_dict = {x.split("\t")[0] : x.split("\t")[1] for x in content}


    global_match_set = set()
    global_match_md5 = set()

    positives = 0
    family_count = 0
    n_tests = 0
    for file in os.listdir(all_malware_path):
        if re.match(".*\.json", file):
            continue
        try:
            res = compiled_rules.match(os.path.join(all_malware_path,file))
            n_tests += 1
        except Exception as e:
            continue
        if(len(res) > 0):
            global_match_set.add(file)
            file_md5 = md5(os.path.join(all_malware_path,file))
            global_match_md5.add(file_md5)
            positives +=1
            if re.match("\[\('"+family_name+"'.*",labels_dict[file_md5]):
                family_count+=1
    rules_new_matches.write("New positives:"+ str(positives-family_count)+"\n")
    rules_new_matches.write("Total positives: "+ str(len(global_match_set))+"\n")
    for match in global_match_set:
        file_md5 = md5(os.path.join(all_malware_path,match))
        rules_new_matches.write("\t->"+match+" - "+labels_dict[file_md5]+" - "+packers_dict[match]+"\n")

    count = 0
    for res in global_match_md5:
        if re.match(".*"+family_name+".*",labels_dict[res]):
            count +=1
    already_found = family_count
    family_total = len(os.listdir(family_path))
    family_ratio = family_count / family_total
    recall_denominator = len(list(filter(lambda x: re.match(".*"+family_name+".*",x),labels_dict.values())))
    try:
        recall = (count- already_found)/(recall_denominator- already_found)
    except Exception as e:
        recall = np.nan
    rules_new_matches.write("Recall: "+ str(recall)+"\n")
    precision_denominator = len(global_match_md5)
    try:
        precision = (count-already_found)/(precision_denominator-already_found)
    except Exception as e:
        precision = np.nan
    rules_new_matches.write("Precision: "+ str(precision)+"\n")
    rules_new_matches.close()
    rules_stats= pd.DataFrame([[rules_path, fp_count, fp_ratio, n_tested_goodwares, positives, family_ratio, recall, precision]],
                    columns =["Rules", "False positives", "False positives ratio", "Total goodwares tested successfully", "Malware positives", "Malware family ratio", "Overall recall", "Overall precision"])
    return rules_stats

def main():
    """ That's main! """
    parser = argparse.ArgumentParser(description='YaYaGen')
    parser.add_argument('-o', '--outputdir', type=str, required = True,
                        help='Output dir where to save rules.')
    parser.add_argument('-dir', '--directory', type=str, required = True,
                        help='A Directory with PE files')
    parser.add_argument('-gw', '--goodwares', type = str, required = True, help = "Folder of goodwares that rules have not to match.")

    parser.add_argument('-s', '--statsdir', required = True, help = 'Directory of the stats output')
    parser.add_argument('-m', '--malwaresdir', required = True, help = 'Directory path of all the malwares the family has been taken from.')
    parser.add_argument('-l', '--av_labels', default = '../avclass-master/4bf4bc2c3309458670687f7f35a034e87726c0b2b4ce5949aa05b2a6844cd112.verbose',
                        help = 'File path of the verbose av class labels output (to compute statistics on the files)')
    args = parser.parse_args()



    rules_prefix = args.outputdir
    os.mkdir(rules_prefix)
    goodwares_path = args.goodwares
    all_malware_path = args.malwaresdir
    stats_prefix = args.statsdir
    labels_path = args.av_labels
    os.mkdir(stats_prefix)
    csv_path = open("yarGen.csv", 'a')

    df_stats = pd.DataFrame(columns =["Rules", "False positives", "False positives ratio", "Malware positives", "Malware family ratio", "Overall recall", "Overall precision"])


    for root, subdirs, filenames in os.walk(args.directory):
        if len(subdirs) > 0:
            for subdir in subdirs:
                family_path = os.path.join(args.directory, subdir)
                if len(os.listdir(family_path))<3:
                    continue
                family_name = family_path.split("/")[-1]
                family_rules_path = os.path.join(rules_prefix, subdir)
                os.mkdir(family_rules_path)
                family_output_subdir = os.path.join(stats_prefix, subdir)
                os.mkdir(family_output_subdir)
                for z in [False, True]:
                    if z:
                        z_arg = "-z 0"
                        z_path = "z0_"
                    else:
                        z_arg = ""
                        z_path = ""
                    for opcodes in [False, True]:
                        if opcodes:
                            opcodes_arg = "--opcodes"
                            opcodes_path = "opcodes_"
                        else:
                            opcodes_arg = ""
                            opcodes_path = ""
                        for excludegood in [False, True]:
                            if excludegood:
                                excludegood_arg = "--excludegood"
                                excludegood_path = "excludegood_"
                            else:
                                excludegood_arg = ""
                                excludegood_path = ""
                            for goodware in [False, True]:
                                if goodware:
                                    goodware_arg = "-g "+goodware_path
                                    goodware_path = "goodware"
                                else:
                                    goodware_arg = ""
                                    goodware_path = ""
                                rules_path = os.path.join(family_rules_path, "rules_"+ z_path+opcodes_path+excludegood_path+goodware_path+".yar")
                                output_subdir = os.path.join(family_output_subdir,"stats_"+z_path+opcodes_path+excludegood_path+goodware_path)
                                print(output_subdir)
                                os.mkdir(output_subdir)

                                os.system("python ~/yarGen/yarGen.py -m "+family_path+" "+z_arg+" "+opcodes_arg+" "+excludegood_arg+" -o "+rules_path)
                                rules_stats = compute_stats(rules_path, all_malware_path, family_path, goodwares_path, labels_path, output_subdir )
                                rules_stats.to_csv(csv_path, header = False)

if __name__ == '__main__':
    main()
