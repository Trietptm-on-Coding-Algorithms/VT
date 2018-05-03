#!/usr/bin/env python
# -*- coding: utf-8 -*-

##############################################################################
## Authors: Antonio Sanchez and Andrea Marcelli                             ##
## 28/06/2017 - @ Politecnico di Torino and Malaga                          ##
## cy.py : Yet another Yara checker                                         ##
##############################################################################

import multiprocessing
import argparse
import traceback
import sys
import os

import pandas as pd
import json
import time

import logging
logger = logging.getLogger()
import coloredlogs

from logging.handlers import RotatingFileHandler
handler = RotatingFileHandler(
    "cy_multiprocess_pandas_debug.log", maxBytes=2000)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


if sys.version_info >= (3, 0):
    sys.stdout.write(":( Requires Python 2.x, not Python 3.x\n")
    sys.exit(1)

try:
    import yara
except ImportError:
    print("... works only with custom Yara module! (N/A to the public)")
    sys.exit()


def compile_ruleset(ruleset):
    logger.debug("Loading ruleset...")
    rules_dict = {rule: open(rule, "rt").read() for rule in ruleset}

    logger.debug("First ruleset compilation...")
    error_keys = set()

    for rule in rules_dict:
        try:
            yara.compile(source=rules_dict[rule])
        except Exception as e:
            logger.critical("Exception raised")
            logger.critical("Skipping rule %s\n", rule)
            error_keys.add(rule)

    tot_len = len(rules_dict)
    new_len = tot_len - len(error_keys)
    logger.debug("Compiled %d rules / %d", new_len, tot_len)

    logger.debug("Removing error keys")
    for key in error_keys:
        del rules_dict[key]
    logger.debug("New rules_dict lenght: %d", len(rules_dict))

    logger.debug("Final ruleset compilation...")
    rules = yara.compile(sources=rules_dict)
    logger.debug("Ruleset compilation completed")
    return rules


def check_report(report, compiled_rules):
    with open(report) as fd:
        report_json = json.load(fd)

    androguard = report_json.get('androguard', '{}')
    cuckoo = report_json.get('cuckoo', '{}')
    droidbox = report_json.get('droidbox', '{}')

    if androguard:
        androguard = json.dumps(androguard)
        androguard = androguard.replace('\u0000', '')
    else:
        androguard = '{}'

    if droidbox:
        droidbox = json.dumps(droidbox)
        droidbox = droidbox.replace('\u0000', '')
    else:
        droidbox = '{}'

    if cuckoo:
        cuckoo = json.dumps(cuckoo)
        cuckoo = cuckoo.replace('\u0000', '')
    else:
        cuckoo = '{}'

    rule_matches = compiled_rules.match("empty_file",
                                        modules_data={
                                            'cuckoo': bytes(cuckoo),
                                            'androguard': bytes(androguard),
                                            'droidbox': bytes(droidbox)
                                        })
    return [_.namespace for _ in rule_matches]


class Consumer(multiprocessing.Process):

    def __init__(self, task_queue, result_queue, yara_ruleset, ruleset):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.shalist_matches = 0
        self.yara_ruleset = yara_ruleset
        self.ruleset = ruleset
        self.stat = {r: {"FP": list(), "FN": list(), "TP": list(), "TN": 0}
                     for r in self.yara_ruleset}
        self.skipped = 0

    def run(self):
        proc_name = self.name
        while True:
            next_task = self.task_queue.get()
            if next_task is None:
                # Poison pill means shutdown
                self.task_queue.task_done()
                result_dict = dict()
                result_dict["shalist_matches"] = self.shalist_matches
                result_dict["stat"] = self.stat
                result_dict["skipped"] = self.skipped
                self.result_queue.put(result_dict)
                logger.debug('%s: exiting...', proc_name)
                break
            self.skipped, self.stat = next_task(self.shalist_matches, self.stat,
                                                self.skipped, self.yara_ruleset,
                                                self.ruleset)
            logger.debug('%s: finished -- %s (%d skipped)',
                         proc_name, next_task, self.skipped)
            self.task_queue.task_done()
        return


class Task(object):

    def __init__(self, file_report, sha256_report, shalist):
        self.file_report = file_report
        self.sha256 = sha256_report
        self.shalist = shalist

    def __call__(self, shalist_matches, stat, skipped, yara_ruleset, ruleset):
        try:
            # Check the yara rule on the report
            # logger.debug("Checking: %s", self.sha256)
            rule_matches = check_report(self.file_report, ruleset)
            # logger.debug(rule_matches)

            if self.sha256 in self.shalist:
                # The report should match
                for yara_rule in yara_ruleset:
                    if yara_rule in rule_matches:
                        shalist_matches += 1
                        stat[yara_rule]["TP"].append(self.sha256)
                    else:
                        stat[yara_rule]["FN"].append(self.sha256)
            else:
                # The report should not match
                for yara_rule in yara_ruleset:
                    if yara_rule in rule_matches:
                        stat[yara_rule]["FP"].append(self.sha256)
                    else:
                        stat[yara_rule]["TN"] += 1
        except Exception:
            logger.critical("Error. Skipping: %s", self.sha256)
            traceback.print_exc()
            skipped += 1
        return skipped, stat

    def __str__(self):
        return 'sha256:%s' % (self.sha256)


def loading_stuff(shalist_file, filterlist_file, yara_ruleset):
    logger.debug("Loading YARA ruleset...")
    ruleset = compile_ruleset(yara_ruleset)

    logger.debug("Loading sha256 list...")
    with open(shalist_file) as fd:
        shalist = [_.strip().split('.')[0] for _ in fd.readlines()]
    logger.debug("len shalist: %d", len(shalist))
    logger.debug(shalist)

    filterlist = None
    if filterlist_file:
        logger.debug("Loading sha256 filterlist...")
        with open(filterlist_file) as fd:
            filterlist = [_.strip().split('.')[0] for _ in fd.readlines()]
        logger.debug("len filterlist: %d", len(filterlist))
    return ruleset, shalist, filterlist


def print_stat(stat, outputdir):
    if not os.path.isdir(outputdir):
        os.mkdir(outputdir)
        logger.debug("Created dir %s", outputdir)
    for rule in stat:
        try:
            logger.debug(rule)
            rule_name, _ = os.path.splitext(os.path.split(rule)[1])
            logger.debug(rule_name)
            rule_outputdir = os.path.join(outputdir, rule_name)
            if not os.path.isdir(rule_outputdir):
                os.mkdir(rule_outputdir)
                logger.debug("Created dir %s", rule_outputdir)
            for key in stat[rule].keys():
                if isinstance(stat[rule][key], list):
                    if key == 'FP' and len(stat[rule][key]) > 0:
                        logger.debug("%s %d ", key, len(stat[rule][key]))
                    else:
                        logger.debug("%s %d ", key, len(stat[rule][key]))
                else:
                    logger.debug("%s %d ", key, stat[rule][key])

            fp_path = os.path.join(rule_outputdir, 'FP.txt')
            fn_path = os.path.join(rule_outputdir, 'FN.txt')
            with open(fp_path, 'w') as fp, open(fn_path, 'w') as fn:
                fp.writelines('\n'.join(stat[rule]['FP']))
                fn.writelines('\n'.join(stat[rule]['FN']))
            logger.debug("False positives saved to %s" % fp_path)
            logger.debug("False negatives saved to %s" % fn_path)
        except Exception:
            logger.critical("Something went wrong while processing: %s", rule)


def create_pandas_df(stat, outputdir):
    df = pd.DataFrame(columns=['TP', 'TN', 'FP', 'FN'])
    df.index.name = 'rule'
    for rule in stat:
        rule_name, _ = os.path.splitext(os.path.split(rule)[1])
        df.loc[rule_name] = [len(stat[rule]['TP']), stat[rule]['TN'], len(
            stat[rule]['FP']), len(stat[rule]['FN'])]
    df.to_csv(os.path.join(outputdir, "rule_pandas.csv"))


def from_stat_list_to_stat(out_dict, l_skipped):
    g_skipped = l_skipped
    g_shalist_matches = 0
    g_stat = None
    for dic in out_dict:
        g_skipped += dic['skipped']
        g_shalist_matches += dic['shalist_matches']
        if not g_stat:
            g_stat = dic['stat']
        else:
            for rule_key in dic['stat']:
                if rule_key in g_stat:
                    for key in dic['stat'][rule_key]:
                        if key == 'TN':
                            g_stat[rule_key][key] += dic['stat'][rule_key][key]
                        else:
                            g_stat[rule_key][key] += dic['stat'][rule_key][key]
                else:
                    g_stat[rule_key] = dic['stat'][rule_key]
    return g_stat, g_skipped, g_shalist_matches


def multiprocess_checking(num_consumers, yara_ruleset, ruleset, reports_dir, filterlist, shalist, outputdir):
    """ Check reports using multiprocesses """
    tasks = multiprocessing.JoinableQueue()
    results = multiprocessing.Queue()
    logger.debug('Starting %d consumers', num_consumers)
    consumers = [Consumer(tasks, results, yara_ruleset, ruleset)
                 for i in range(num_consumers)]
    for w in consumers:
        w.start()

    logger.debug("Started checking...")
    l_skipped = 0
    for counter, report in enumerate(os.listdir(reports_dir)):
        sha256_report = report.split('.')[0]
        # Check if is in filterlist
        if filterlist and (sha256_report in filterlist):
            l_skipped += 1
        else:
            report_path = os.path.join(reports_dir, report)
            tasks.put(Task(report_path, sha256_report, shalist))

    for i in range(num_consumers):
        tasks.put(None)
    logger.debug("Waiting for consumers to join")
    tasks.join()
    logger.debug("Collecting results from consumers")
    out_dict = [results.get() for i in range(num_consumers)]

    logger.debug(out_dict)
    g_stat, g_skipped, g_shalist_matches = from_stat_list_to_stat(
        out_dict, l_skipped)
    logger.debug(g_stat)

    print_stat(g_stat, outputdir)
    create_pandas_df(g_stat, outputdir)
    logger.debug("Reports checked: %d" % counter)
    logger.debug("Reports skipped: %d" % g_skipped)
    logger.debug("Shalist size: %d" % len(shalist))
    logger.debug("Shalist matches: %d" % g_shalist_matches)
    return counter


def main():
    """
    usage: cy_multiprocess_pandas.py [-h] [-d] -nc NUMBER_OF_CORES -i INPUTLIST
                                [-f FILTERLIST] -r REPORTS -o OUTPUTDIR
                                RULES [RULES ...]
    """
    parser = argparse.ArgumentParser(description='Yet another Yara checker')
    parser.add_argument('-d', '--debug', dest='debug',
                        action='store_true', help='Log level debug')
    parser.add_argument('-nc', '--number_of_cores',
                        required=True, help='Number of cores to use')
    parser.add_argument('-i', '--inputlist', required=True,
                        help='File with list of sha256 that match the rule')
    parser.add_argument('-f', '--filterlist',
                        help='File with list of sha256 to not check')
    parser.add_argument('-r', '--reports', required=True,
                        help='Reports folder')
    parser.add_argument('-o', '--outputdir', required=True,
                        help='Outputdir', default="./")
    parser.add_argument('rules', metavar='RULES', type=str,
                        nargs='+', help='YARA rules')
    args = parser.parse_args()

    global logger
    loglevel = 'INFO'
    if args.debug:
        loglevel = 'DEBUG'
    coloredlogs.install(fmt='%(asctime)s %(levelname)s:: %(message)s',
                        datefmt='%H:%M:%S', level=loglevel, logger=logger)
    logger.debug("Let's start!")

    if not os.path.isfile("empty_file"):
        logger.critical("empty_file is required")
        sys.exit()

    args = parser.parse_args()
    start = time.time()

    yara_ruleset = args.rules
    num_consumers = int(args.number_of_cores)
    reports_dir = args.reports

    ruleset, shalist, filterlist = loading_stuff(
        args.inputlist, args.filterlist, args.rules)
    counter = multiprocess_checking(
        num_consumers, yara_ruleset, ruleset, reports_dir,
        filterlist, shalist, args.outputdir)

    end = time.time()
    logger.debug('Checking %d reports took %.2f seconds', counter, end - start)
    logger.debug("That's all folks")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("An except has occurred while executing cy.py.")
        traceback.print_exc()
