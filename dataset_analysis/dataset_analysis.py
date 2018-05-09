import multiprocessing
import argparse
import sys
import os
import re
import pandas as pd
import json
import subprocess
import pefile

try:
	import yara
except ImportError:
	print("This module requires yara to work.")
	sys.exit()



err=open(os.devnull,"w")



def compile_ruleset(ruleset_path, filterlist_path):
	if(os.path.isdir(ruleset_path)==False):
		print("Invalid directory given:", ruleset_path)
		sys.exit()

	if(filterlist_path!="" and os.path.isfile(filterlist_path)==False):
		print("Invalid filtering file given:", filterlist_path)
		sys.exit()

	rules_dictionary={}

	filter_list=[]

	if(filterlist_path!=""):
		filterlist_file = open(filterlist_path, "r")
		filter_list_nl = filterlist_file.readlines()
		for entry in filter_list_nl:
			filter_list.append(entry.rstrip("\n"))

	print(filter_list)

	""" Creating the dictionary to import all rules at once. """
	for dir, subdirs, rule_files in os.walk(ruleset_path):
		for rule_file in rule_files:
			try:
				rule_file_w_path=os.path.join(dir, rule_file)
				#print(rule_file_w_path)
				to_filter=False
				for entry in filter_list:
					if(re.match("(?i).*"+entry+".*",rule_file_w_path) is not None):
						print("File:", rule_file_w_path, "ignored as requested")
						to_filter=True
						break
					if(to_filter==True):
						break
				if(to_filter==True):
					continue
				yara.compile(filepaths={rule_file_w_path : rule_file_w_path})
				rules_namespace=rule_file_w_path
				rules_dictionary[rules_namespace]=rule_file_w_path
			except Exception as e:
				#continue
				print("Syntax error opening file: "+rule_file_w_path+" -skipping:",e)


	print(rules_dictionary)
	compiled_rules=yara.compile(filepaths=rules_dictionary)
	return compiled_rules

class Consumer(multiprocessing.Process):

	def __init__(self, task_queue, result_queue, yara_ruleset):
		multiprocessing.Process.__init__(self)
		self.task_queue = task_queue
		self.result_queue = result_queue
		self.yara_ruleset = yara_ruleset

	def run(self):
		df = pd.DataFrame(columns=['Exe name', 'Family','first_seen', 'last_seen', 'total', 'positives', 'ssdeep', 'imphash', 'yara_detected', 'yara_matching_rules' ])
		#df = df.set_index('Exe name')
		while True:
			next_task = self.task_queue.get()
			if next_task is None:
				self.task_queue.task_done()
				self.result_queue.put(df)
				break
			dict=next_task(self.yara_ruleset)
			df=df.append(dict, ignore_index=True)
			self.task_queue.task_done()
		#print("Process ended successfully.")
		return

class Task(object):
	def __init__(self, dir_path, json_name):
		self.dir_path = dir_path
		self.json_name = json_name

	def __call__(self, yara_ruleset):
		report_path=os.path.join(self.dir_path,self.json_name)
		json_file=open(report_path)
		data=json.load(json_file)
		cmd=[AVCLASS_path, "-vt" , report_path]
		mw_family=subprocess.check_output(cmd,stderr=err)
		family_name=mw_family.split(b"\t")[1].decode('ascii')[:-1]
		#print(data['Family'])



		""" Getting the executable related to the report ( NOTE: it is assumed NOT to be necessarily a .exe, but, if it is certain
			it could be better to create the name entirely)"""
		file_name_no_extension=self.json_name[:len(self.json_name)-5]
		exe_name=file_name_no_extension
		exe_path=os.path.join(self.dir_path,exe_name)


		matches = yara_ruleset.match(exe_path)
		dict = {}
		dict['Exe name'] = exe_name
		dict['Family'] = family_name
		dict['first_seen'] = data['first_seen']
		dict['last_seen'] = data['last_seen']
		dict['total'] = data['total']
		dict['positives'] = data['positives']
		dict['ssdeep'] = data['ssdeep']
		dict['imphash'] = pefile.PE(exe_path).get_imphash()
		dict['yara_detected'] = (len(matches)>0)
		dict['yara_matching_rules'] = [_.namespace+":"+_.rule for _ in matches]

		return dict

if __name__ == "__main__":

	"""
	usage: dataset_analysis.py -i INPUT_DIRECTORY -nc NUMBER_OF_CORES
								[-f FILTERLIST] -y RULES_DIRECTORY -o OUTPUT_FILE_NAME
								-c AVCLASS_DIRECTORY
	"""
	parser = argparse.ArgumentParser(description='DataSet Analysis Tool')
	parser.add_argument('-n', '--number_of_cores',
						required=True, help='Number of cores to use',default='1')
	parser.add_argument('-i', '--inputdir', required=True,
						help='Directory to read input VT reports from (json format only)')
	parser.add_argument('-f', '--filterlist',
						help='File with list of .yar not to check',required=False, default="")
	parser.add_argument('-c', '--avclass_main', default="/home/luca/Scrivania/tesi/avclass-master",
						help='AVCLASS main directory')
	parser.add_argument('-o', '--output', required=True,
						help='Output file name', default="./output.csv")
	parser.add_argument('-y', '--yars', required=True,
						 help='YARA rules')
	args = parser.parse_args()
	samples_path=args.inputdir
	rules_path=args.yars
	proc_num=int(args.number_of_cores)
	filterlist=args.filterlist
	global AVCLASS_path


	if(os.path.isdir(args.avclass_main)==False):
		print("The AVCLASS path is NOT a directory.")
		sys.exit()

	AVCLASS_path = os.path.join(args.avclass_main,"avclass_labeler.py")


	if(os.path.isdir(samples_path)==False):
		print("The samples directory is NOT a directory.")
		sys.exit()

	jobs=multiprocessing.JoinableQueue()
	results = multiprocessing.Queue()

	yara_ruleset=compile_ruleset(rules_path, filterlist)

	consumers = [Consumer(jobs, results, yara_ruleset) for i in range(proc_num)]

	for c in consumers:
		c.start()

	json_file_list=list(filter(lambda x: re.match(".*\.json",x),os.listdir(samples_path)))

	for entry in json_file_list:
		jobs.put(Task(samples_path, entry))
	for c in range(proc_num):
		jobs.put(None)

	jobs.join()
	#print("Main awake.")

	df_list = [results.get() for i in range(proc_num)]
	pd_dataset= pd.concat(df_list)

	yara_matches_count = len(pd_dataset[pd_dataset['yara_detected']==True])
	print("Yara rules detected "+str(yara_matches_count)+" samples")


	if(os.path.isdir(args.output)==True):
		output_file=os.path.join(args.output,"output.csv")
	else:
		output_file=args.output
	pd_dataset.to_csv(output_file)
