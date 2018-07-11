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

df_stats = pd.DataFrame(columns =["Rules", "False positives", "False positives ratio", "Malware positives", "Malware family ratio", "Overall recall", "Overall precision"])

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

    rules_dict = dict()
    rules_list = os.listdir(rules_path)
    for i,rule in enumerate(rules_list):
        rules_dict[i] = yara.compile(os.path.join(rules_path,rule))

    fp_count = 0
    for i, rule in rules_dict.items():
        prologue = False
        for file in os.listdir(goodware_path):
            res = rule.match(os.path.join(goodware_path,file))
            if(len(res) > 0):
                if not prologue:
                    fp_output.write(rules_list[i]+":\n")
                    prologue = True
                fp_output.write("\t-"+file+"\n")
                fp_count +=1
    fp_output.write("Total false positives: "+ str(fp_count))
    fp_output.close()

    fp_ratio = fp_count / len(os.listdir(goodware_path))

    with open(labels_path) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    labels_dict = {x.split("\t")[0] : x.split("\t")[1] for x in content}


    global_match_set = set()
    global_match_md5 = set()
    original_family_matches = set()
    already_found = 0

    for i, rule in rules_dict.items():
        positives = 0
        teslacrypt_count = 0
        rules_new_matches.write(os.listdir(rules_path)[i]+" :\n")
        for file in os.listdir(all_malware_path):
            res = rule.match(os.path.join(all_malware_path,file))
            if(len(res) > 0):
                global_match_set.add(file)
                file_md5 = md5(os.path.join(all_malware_path,file))
                global_match_md5.add(file_md5)
                rules_new_matches.write("\t\t>"+file+"-"+labels_dict[file_md5]+"-"+packers_dict[file]+"\n")
                positives +=1
                if re.match("\[\('"+family_name+"'.*",labels_dict[file_md5]):
                    teslacrypt_count+=1
                    original_family_matches.add(file)
        rules_new_matches.write("\t- New positives:"+ str(positives-teslacrypt_count)+"\n")
    rules_new_matches.write("Total positives: "+ str(len(global_match_set))+"\n")
    for match in global_match_set:
        file_md5 = md5(os.path.join(all_malware_path,match))
        rules_new_matches.write("\t->"+match+" - "+labels_dict[file_md5]+" - "+packers_dict[match]+"\n")


    already_found = len(original_family_matches)
    count = 0
    for res in global_match_md5:
        if re.match(".*"+family_name+".*",labels_dict[res]):
            count +=1
    family_ratio = already_found / len(os.listdir(family_path))
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

    rules_stats = pd.DataFrame([[rules_path, fp_count, fp_ratio, len(global_match_set), family_ratio, recall, precision]],
                    columns =["Rules", "False positives", "False positives ratio", "Malware positives", "Malware family ratio", "Overall recall", "Overall precision"])
    return rules_stats

def main():
    """ That's main! """
    parser = argparse.ArgumentParser(description='YaYaGen')
    parser.add_argument('-o', '--outputdir', type=str, required = True,
                        help='Output dir where to save rules.')
    parser.add_argument('-dir', '--directory', type=str, required = True,
                        help='A Directory with PE files')
    parser.add_argument('-yr', '--yara-rules', type=str, dest = 'rules_path', required = True,
                        help='Use a directory or file path where to take yara rules to include in the automatic generation.')
    parser.add_argument('-gw', '--goodwares', type = str, required = True, help = "Folder of goodwares that rules have not to match.")

    parser.add_argument('-s', '--statsdir', required = True, help = 'Directory of the stats output')
    parser.add_argument('-m', '--malwaresdir', required = True, help = 'Directory path of all the malwares the family has been taken from.')
    parser.add_argument('-l', '--av_labels', default = './avclass-master/4bf4bc2c3309458670687f7f35a034e87726c0b2b4ce5949aa05b2a6844cd112.verbose',
                        help = 'File path of the verbose av class labels output (to compute statistics on the files)')
    args = parser.parse_args()


    yyg_base = "./YaYaGenPE/"
    csv_path = open("/home/luca/Scrivania/testing/YaYaGenPE.csv", 'a')
    rules_prefix = args.outputdir
    os.mkdir(rules_prefix)
    goodware_path = args.goodwares
    all_malware_path = args.malwaresdir
    stats_prefix = args.statsdir
    labels_path = args.av_labels
    os.mkdir(stats_prefix)

    for root, subdirs, filenames in os.walk(args.directory):
        if len(subdirs) > 0:
            for subdir in subdirs:
                family_path = os.path.join(args.directory, subdir)
                if len(os.listdir(family_path))<3:
                    continue
                family_rules_path = os.path.join(rules_prefix, subdir)
                os.mkdir(family_rules_path)
                family_output_subdir = os.path.join(stats_prefix, subdir)
                os.mkdir(family_output_subdir)
                for algorithm in ['greedy','clot','udt','udt:clot']:
                    if (algorithm == 'clot' or algorithm == 'greedy') and len(os.listdir(family_path))>40:
                        continue
                    rules_path = os.path.join(family_rules_path, algorithm)
                    output_subdir = os.path.join(family_output_subdir,algorithm)
                    os.mkdir(output_subdir)

                    os.system("./yyg.py -c _config/configuration.json -dir "+family_path+" -a "+algorithm+" -ndb -o "+ rules_path)
                    rules_stats = compute_stats(rules_path, all_malware_path, family_path, goodware_path, labels_path, output_subdir )
                    df_stats.append(rules_stats)

                    rules_path = os.path.join(family_rules_path, algorithm+"_w_rules")
                    output_subdir = os.path.join(family_output_subdir, algorithm+"_w_rules")
                    os.mkdir(output_subdir)

                    os.system("./yyg.py -c _config/configuration.json -dir "+family_path+" -a "+algorithm+" -ndb -o "+ rules_path+" -yr "+args.rules_path)
                    rules_stats = compute_stats(rules_path, all_malware_path, family_path, goodware_path, labels_path, output_subdir )
                    df_stats.append(rules_stats)
                    if re.match("udt.*",algorithm):
                        rules_path = os.path.join(family_rules_path, algorithm+"_goodware")
                        output_subdir = os.path.join(family_output_subdir,algorithm+"_goodware")
                        os.mkdir(output_subdir)

                        os.system("./yyg.py -c _config/configuration.json -dir "+family_path+" -a "+algorithm+" -ndb -o "+ rules_path +" -gw "+goodware_path)
                        rules_stats = compute_stats(rules_path, all_malware_path, family_path, goodware_path, labels_path, output_subdir )
                        df_stats.append(rules_stats)

                        rules_path = os.path.join(family_rules_path, algorithm+"_w_rules_and_goodware")
                        output_subdir = os.path.join(family_output_subdir, algorithm+"_w_rules_and_goodware")
                        os.mkdir(output_subdir)

                        os.system("./yyg.py -c _config/configuration.json -dir "+family_path+" -a "+algorithm+" -ndb -o "+ rules_path+" -yr "+args.rules_path+" -gw "+goodware_path)
                        rules_stats = compute_stats(rules_path, all_malware_path, family_path, goodware_path, labels_path, output_subdir )
                        rules_stats.to_csv(csv_path, header = False)



if __name__ == '__main__':
    main()
