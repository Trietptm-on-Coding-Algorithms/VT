#!/usr/bin/env python
# -*- coding: utf-8 -*-

##############################################################################
## Authors: Andrea Marcelli                                                 ##
## 23/05/2018 - @ Politecnico di Torino and Malaga                          ##
## Test YaYaGenPE                                                           ##
##############################################################################

import os
import ast
import subprocess
import argparse
import time
import glob

import pandas as pd
import operator
import shutil

import logging
import coloredlogs
from sklearn.model_selection import KFold

log = None

CREATE_RULE_COMMAND = "./yyg.py -a greedy -c _config/configuration.json -dir %s -o %s"
TEST_RULE_COMMAND = "./check_yara.py -nc 2 -i empty_file -r %s -o %s %s"
TRAIN_FOLDER = "./TRAIN/"
TEST_FOLDER = "./TEST/"


def clean_output_folders(outputrules, outputpandas):
    """ Clean the output folder data """
    if os.path.isdir(TRAIN_FOLDER):
        shutil.rmtree(TRAIN_FOLDER)
    os.mkdir(TRAIN_FOLDER)

    if os.path.isdir(TEST_FOLDER):
        shutil.rmtree(TEST_FOLDER)
    os.mkdir(TEST_FOLDER)

    if os.path.isdir(outputrules):
        shutil.rmtree(outputrules)

    if os.path.isdir(outputpandas):
        shutil.rmtree(outputpandas)


def select_samples(df, familyname, rulename):
    """ Select which sample you want to use """
    sha256s = set(df['Exe name'].values)

    if familyname:
        # Select the samples that match familyname
        df = df[df['Family'] == familyname]
        sha256s &= set(df['Exe name'].values)

    if rulename:
        # Select the samples that match this rulename
        filter_set = set()
        for c, rulesets in enumerate(df.yara_matching_rules.values):
            if rulename in rulesets:
                filter_set.add(df_tesla.iloc[c]['Exe name'])
        sha256s &= filter_set

    log.info("Final sha list len: %d", len(sha256s))
    return list(sha256s)


def split_dataset(sha256s, nsplits=10, shuffle=True):
    """ Split the dataset in training and testset """
    kf = KFold(n_splits=nsplits, shuffle=shuffle)
    log.debug("Num of splits: %d", kf.get_n_splits(sha256s))
    splits = list(kf.split(sha256s))

    # Be aware that train and test are inverted in respect to the ML terminology. Here few samples are enough to create a rule
    train_indexes = splits[0][1]
    test_indexes = splits[0][0]
    log.debug("Len train index set: %d", len(train_indexes))
    log.debug("Let test index set: %d", len(test_indexes))

    train = [sha256s[i] for i in train_indexes]
    test = [sha256s[i] for i in test_indexes]
    log.info("Len train set: %d", len(train))
    log.info("Let test set: %d", len(test))
    return train, test


def print_rule_info(df):
    """ Display how many matches each ruleset produces """
    # Create a dict to count the rule match frequency
    ruleset = dict()
    for v in df.yara_matching_rules.values:
        v = ast.literal_eval(v)
        for r in v:
            if r in ruleset:
                ruleset[r] += 1
            else:
                ruleset[r] = 1

    # Sort the results
    ruleset_sorted = sorted(ruleset.items(), key=operator.itemgetter(1))
    for k in ruleset_sorted:
        log.info("%d %s", k[1], k[0])


def test_ruleset(samplesdir, train, test, outputrules, outputpandas):
    """ Create test and samples folder. Run YaYaGenPE and checkYARA """
    global TRAIN_FOLDER
    global TEST_FOLDER

    for sha in train:
        os.symlink(os.path.join(samplesdir, sha),
                   os.path.join(TRAIN_FOLDER, sha))

    for sha in test:
        os.symlink(os.path.join(samplesdir, sha),
                   os.path.join(TEST_FOLDER, sha))

    global CREATE_RULE_COMMAND
    global TEST_RULE_COMMAND

    CREATE_RULE_COMMAND = CREATE_RULE_COMMAND % (TRAIN_FOLDER, outputrules)
    process = subprocess.Popen(
        CREATE_RULE_COMMAND.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    outputruleset = " ".join(glob.glob(os.path.join(outputrules, "*.yar")))
    TEST_RULE_COMMAND = TEST_RULE_COMMAND % (TEST_FOLDER, outputpandas, outputruleset)
    process = subprocess.Popen(TEST_RULE_COMMAND.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()


def process_results(outputpandas):
    """ Parse detection results """
    df_result = pd.read_csv(os.path.join(
        outputpandas, "sha256_pandas.csv"), index_col=0)
    det_counter = 0
    for x in df_result.values:
        if sum(x) > 0:
            det_counter += 1
    log.warning("Total samples: %d", len(df_result.values))
    log.warning("Total matches: %d", det_counter)


def main():
    """ That's main! """
    parser = argparse.ArgumentParser(description='YaYaGenPE')
    parser.add_argument('-d', '--debug', dest='debug',
                        action='store_true', help='Log level debug')
    parser.add_argument('-i', '--inputcsv', required=True,
                        help='CSV file with sample info')
    parser.add_argument('-s', '--samples', required=True,
                        help='Folder with samples')
    parser.add_argument('-k', '--kfold', required=True,
                        help='Number of kfold partitions')
    parser.add_argument('-or', '--outputrules', required=True,
                        help='Output dir where to save rules')
    parser.add_argument('-op', '--outputpandas', required=True,
                        help='Output dir where to save the pandas results')
    parser.add_argument('-f', '--familyname', required=False,
                        help='Filter samples by family name')
    parser.add_argument('-r', '--rulename', required=False,
                        help='Filter samples by matching ruleset')
    args = parser.parse_args()

    global log
    log = logging.getLogger()
    loglevel = 'INFO'
    if args.debug:
        loglevel = 'DEBUG'
    coloredlogs.install(fmt='%(asctime)s %(levelname)s:: %(message)s',
                        datefmt='%H:%M:%S', level=loglevel, log=log)

    log.warning("Let's start!")
    clean_output_folders(args.outputrules, args.outputpandas)
    df = pd.read_csv(args.inputcsv, index_col=0)
    sha256s = select_samples(df, args.familyname, args.rulename)
    train, test = split_dataset(sha256s, nsplits=int(args.kfold))
    test_ruleset(args.samples, train, test, args.outputrules, args.outputpandas)
    process_results(args.outputpandas)


if __name__ == '__main__':
    print("Test YaYaGenPE")
    main()
